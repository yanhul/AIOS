"""ADC-backed Firestore effect-store construction.

This module intentionally constructs only the durable effect store. It does
not create an executable worker because contract/permit/attestation/policy/
capability authority is still filesystem-backed in core.authority.
"""
from __future__ import annotations

import os
from typing import Any

from .firestore_effect_store import FirestoreEffectStore


class WorkerBootstrapBlocked(RuntimeError):
    """Production worker startup is unsafe until all durable authorities exist."""


def create_firestore_effect_store(*, environ: dict[str, str] | None = None) -> FirestoreEffectStore:
    """Create FirestoreEffectStore using ADC; never accept key-file credentials.

    Cloud Run supplies ADC through its attached service identity. The explicit
    project check prevents ambient credentials from silently selecting another
    project. Emulator use requires a separate explicit opt-in.
    """
    env = os.environ if environ is None else environ
    if env.get("AIOS_REQUIRE_FIRESTORE_EFFECT_STORE", "").lower() != "true":
        raise WorkerBootstrapBlocked("Firestore-only production guard must be explicitly enabled")
    project_id = env.get("AIOS_FIRESTORE_PROJECT_ID", "").strip()
    if not project_id:
        raise WorkerBootstrapBlocked("AIOS_FIRESTORE_PROJECT_ID is required")
    if env.get("FIRESTORE_EMULATOR_HOST") and env.get("AIOS_ALLOW_FIRESTORE_EMULATOR", "").lower() != "true":
        raise WorkerBootstrapBlocked("Firestore Emulator is forbidden unless explicitly enabled for tests")

    try:
        import google.auth
        from google.cloud import firestore
    except ImportError as exc:
        raise WorkerBootstrapBlocked("google-auth and google-cloud-firestore are required") from exc

    try:
        credentials, adc_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/datastore"]
        )
    except Exception as exc:
        raise WorkerBootstrapBlocked("Application Default Credentials unavailable") from exc
    if adc_project and adc_project != project_id:
        raise WorkerBootstrapBlocked("ADC project does not match AIOS_FIRESTORE_PROJECT_ID")

    try:
        client = firestore.Client(project=project_id, credentials=credentials)
        if getattr(client, "project", None) != project_id:
            raise WorkerBootstrapBlocked("Firestore client project identity mismatch")
        return FirestoreEffectStore(client, project_id=project_id)
    except WorkerBootstrapBlocked:
        raise
    except Exception as exc:
        raise WorkerBootstrapBlocked("Firestore client construction failed closed") from exc


def create_production_worker(*, environ: dict[str, str] | None = None, **_kwargs: Any) -> Any:
    """Fail closed until durable authority backend is implemented and injected."""
    env = os.environ if environ is None else environ
    if env.get("AIOS_AUTHORITY_BACKEND") != "firestore":
        raise WorkerBootstrapBlocked(
            "filesystem authority is not permitted for a stateless production worker"
        )
    # Deliberately do not return a partially wired worker. Merely naming the
    # backend 'firestore' is not evidence that signed authority records exist.
    raise WorkerBootstrapBlocked(
        "Firestore authority backend is not implemented: contract, permit, "
        "attestation, policy and capability reads must be durable and verified"
    )


__all__ = [
    "WorkerBootstrapBlocked",
    "create_firestore_effect_store",
    "create_production_worker",
]
