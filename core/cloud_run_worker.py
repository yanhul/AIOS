"""Cloud Run composition root for the Firestore-authoritative worker.

Only signed Firestore authority records can select a provider capability. The
configured adapter factory is trusted deployment code; the worker calls its
read-only reconcile method only and never calls execute.
"""
from __future__ import annotations

import importlib
import json
import os
import time
import uuid
from collections.abc import Mapping
from typing import Any

from .cloud_tasks_outbox import reconcile_dispatch_outbox_batch
from .cloud_tasks_worker import create_app
from .firestore_authority import FirestoreAuthorityStore
from .firestore_authority_resolver import FirestoreAuthorityResolver
from .firestore_execution import resume_firestore_effect
from .firestore_worker import create_firestore_effect_store


class CloudRunWorkerConfigurationError(RuntimeError):
    """Required trusted worker configuration is missing or invalid."""


def _required(env: Mapping[str, str], key: str) -> str:
    value = env.get(key, "")
    if not isinstance(value, str) or not value.strip():
        raise CloudRunWorkerConfigurationError(f"{key} is required")
    return value.strip()


def _positive_int(env: Mapping[str, str], key: str) -> int:
    raw = _required(env, key)
    try:
        value = int(raw)
    except ValueError as exc:
        raise CloudRunWorkerConfigurationError(f"{key} must be a positive integer") from exc
    if value < 1:
        raise CloudRunWorkerConfigurationError(f"{key} must be a positive integer")
    return value


def _load_adapter_factory(spec: str):
    if spec.count(":") != 1:
        raise CloudRunWorkerConfigurationError(
            "AIOS_RECONCILIATION_ADAPTER_FACTORY must use trusted module:callable syntax"
        )
    module_name, attribute = spec.split(":", 1)
    if not module_name.startswith("aios_worker_adapters.") or not attribute.isidentifier():
        raise CloudRunWorkerConfigurationError(
            "reconciliation adapter factory must be in the aios_worker_adapters package"
        )
    try:
        factory = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise CloudRunWorkerConfigurationError("configured reconciliation adapter factory is unavailable") from exc
    if not callable(factory):
        raise CloudRunWorkerConfigurationError("configured reconciliation adapter factory is not callable")
    return factory


def _verify_caller(environ: Mapping[str, Any], *, audience: str, expected_email: str) -> bool:
    authorization = environ.get("HTTP_AUTHORIZATION", "")
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return False
    token = authorization[7:].strip()
    if not token:
        return False
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token
        claims = id_token.verify_oauth2_token(token, Request(), audience=audience)
    except Exception:
        return False
    return (
        isinstance(claims, dict)
        and claims.get("email") == expected_email
        and claims.get("email_verified") is True
    )


def create_production_app(*, environ: Mapping[str, str] | None = None):
    """Compose production adapters; all external configuration is explicit."""
    env = os.environ if environ is None else environ
    store = create_firestore_effect_store(environ=dict(env))
    project_id = _required(env, "AIOS_FIRESTORE_PROJECT_ID")
    trust_anchor_raw = _required(env, "AIOS_AUTHORITY_TRUST_ANCHOR")
    try:
        trust_anchor = json.loads(trust_anchor_raw)
    except ValueError as exc:
        raise CloudRunWorkerConfigurationError("AIOS_AUTHORITY_TRUST_ANCHOR must be valid JSON") from exc
    attestation_secret = _required(env, "AIOS_AUTHORITY_ATTESTATION_SECRET")
    authority_store = FirestoreAuthorityStore(store.client, project_id=project_id)
    resolver = FirestoreAuthorityResolver(
        authority_store, trust_anchor=trust_anchor,
        attestation_secret=attestation_secret,
    )
    adapter_factory = _load_adapter_factory(_required(env, "AIOS_RECONCILIATION_ADAPTER_FACTORY"))

    def reconcile_same_attempt(*, effect: dict[str, Any], attempt: dict[str, Any]) -> None:
        if effect.get("attempt_id") != attempt.get("attempt_id"):
            raise PermissionError("effect/attempt identity mismatch; DENY")
        authority_digests = effect.get("authority_digests")
        required_keys = {
            "contract_digest", "permit_digest", "attestation_digest",
            "policy_digest", "capability_digests",
        }
        if not isinstance(authority_digests, Mapping) or set(authority_digests) != required_keys:
            raise PermissionError("durable effect has no complete signed authority references; DENY")
        bundle = resolver.resolve(**authority_digests)
        provider = effect.get("provider")
        matches = [
            capability for key, capability in bundle["capabilities"].items()
            if key.split("@", 1)[0] == provider
        ]
        if len(matches) != 1:
            raise PermissionError("provider must bind to exactly one signed capability version; DENY")
        adapter = adapter_factory(provider=provider, capability=dict(matches[0]))
        if getattr(adapter, "name", None) != provider or not callable(getattr(adapter, "reconcile", None)):
            raise CloudRunWorkerConfigurationError(
                "adapter must expose the exact provider name and a read-only reconcile method"
            )
        resume_firestore_effect(
            None, store, effect["effect_id"], effect["attempt_id"], effect["actor"], adapter,
            authority_resolver=resolver, authority_digests=dict(authority_digests),
        )

    from google.cloud import tasks_v2
    tasks_client = tasks_v2.CloudTasksClient()
    cloud_tasks_project = _required(env, "AIOS_CLOUD_TASKS_PROJECT")
    cloud_tasks_location = _required(env, "AIOS_CLOUD_TASKS_LOCATION")
    cloud_tasks_queue = _required(env, "AIOS_CLOUD_TASKS_QUEUE")
    target_url = _required(env, "AIOS_CLOUD_TASKS_TARGET_URL")
    if not target_url.startswith("https://") or not target_url.endswith("/dispatch"):
        raise CloudRunWorkerConfigurationError("AIOS_CLOUD_TASKS_TARGET_URL must be the HTTPS /dispatch URL")
    task_service_account = _required(env, "AIOS_CLOUD_TASKS_INVOKER_EMAIL")
    scheduler_service_account = _required(env, "AIOS_SCHEDULER_INVOKER_EMAIL")
    service_url = _required(env, "AIOS_CLOUD_RUN_SERVICE_URL")
    if not service_url.startswith("https://"):
        raise CloudRunWorkerConfigurationError("AIOS_CLOUD_RUN_SERVICE_URL must use HTTPS")
    lease_seconds = _positive_int(env, "AIOS_OUTBOX_LEASE_SECONDS")
    task_ttl_seconds = _positive_int(env, "AIOS_OUTBOX_TASK_TTL_SECONDS")
    batch_limit = _positive_int(env, "AIOS_OUTBOX_BATCH_LIMIT")

    def reconcile_outbox() -> dict[str, Any]:
        return reconcile_dispatch_outbox_batch(
            store=store, client=tasks_client,
            project=cloud_tasks_project, location=cloud_tasks_location,
            queue=cloud_tasks_queue, target_url=target_url,
            oidc_service_account=task_service_account, oidc_audience=service_url,
            lease_owner=f"{env.get('K_SERVICE', 'aios-worker')}:{env.get('K_REVISION', 'local')}:{uuid.uuid4().hex}",
            now=time.time(), lease_seconds=lease_seconds,
            limit=batch_limit, task_ttl_seconds=task_ttl_seconds,
        )

    def authorize_request(environ: Mapping[str, Any], path: str) -> bool:
        expected = task_service_account if path == "/dispatch" else scheduler_service_account
        return _verify_caller(environ, audience=service_url, expected_email=expected)

    return create_app(
        store_factory=lambda: store,
        reconcile_same_attempt=reconcile_same_attempt,
        outbox_reconciler=reconcile_outbox,
        authorize_request=authorize_request,
    )


__all__ = ["CloudRunWorkerConfigurationError", "create_production_app"]
