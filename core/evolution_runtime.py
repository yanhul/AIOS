"""Firestore-only M10/M11 service facade for governed AIOS runtime callers.

Unlike the developer-local experience_memory/capability_versions modules,
this facade has no filesystem fallback. Production callers must construct it
with ADC, the pinned public trust anchor and the Firestore authority store.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from .firestore_authority import FirestoreAuthorityStore
from .firestore_evolution_store import FirestoreEvolutionStore


class EvolutionRuntimeBlocked(RuntimeError):
    """Firestore evolution runtime is unavailable or not explicitly enabled."""


class FirestoreEvolutionService:
    def __init__(self, store: FirestoreEvolutionStore, *, actor: str) -> None:
        if not isinstance(actor, str) or not actor.strip():
            raise EvolutionRuntimeBlocked("explicit runtime actor identity required")
        self.store, self.actor = store, actor.strip()

    def record_experience(self, **values: Any) -> dict[str, Any]:
        values["record_type"] = "EXPERIENCE"
        return self.store.record_experience(values, actor=self.actor)

    def propose_candidate(self, **values: Any) -> dict[str, Any]:
        values["record_type"] = "CAPABILITY_CANDIDATE"
        return self.store.propose_candidate(values, actor=self.actor)

    def evaluate_candidate(self, **values: Any) -> dict[str, Any]:
        return self.store.evaluate_candidate(values, actor=self.actor)

    def record_ci_evidence(self, record: Mapping[str, Any]) -> dict[str, Any]:
        return self.store.record_ci_evidence(record, actor=self.actor)

    def promote_candidate(self, **values: Any) -> dict[str, Any]:
        return self.store.promote_candidate(**values)

    def bootstrap_active_capability(self, **values: Any) -> dict[str, Any]:
        return self.store.bootstrap_active_capability(**values)

    def get_active_capability(self, capability_id: str) -> dict[str, Any]:
        return self.store.get_active_capability(capability_id)


def create_firestore_evolution_service(
    *, environ: Mapping[str, str] | None = None, actor: str,
    evidence_verifier=None,
) -> FirestoreEvolutionService:
    """Build a Firestore-only service from ADC; never silently fall back locally."""
    env = os.environ if environ is None else environ
    if env.get("AIOS_EVOLUTION_BACKEND") != "firestore":
        raise EvolutionRuntimeBlocked("AIOS_EVOLUTION_BACKEND=firestore is required; no local fallback")
    project_id = env.get("AIOS_FIRESTORE_PROJECT_ID", "").strip()
    if not project_id:
        raise EvolutionRuntimeBlocked("AIOS_FIRESTORE_PROJECT_ID is required")
    workflow_pin = env.get("AIOS_FIRESTORE_WORKFLOW_SHA256", "").strip().lower()
    if not workflow_pin:
        raise EvolutionRuntimeBlocked("AIOS_FIRESTORE_WORKFLOW_SHA256 is required")
    try:
        import google.auth
        from google.cloud import firestore
        credentials, adc_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/datastore"]
        )
        if adc_project and adc_project != project_id:
            raise EvolutionRuntimeBlocked("ADC project differs from AIOS_FIRESTORE_PROJECT_ID")
        client = firestore.Client(project=project_id, credentials=credentials)
        if getattr(client, "project", None) != project_id:
            raise EvolutionRuntimeBlocked("Firestore client project mismatch")
        trust_anchor = FirestoreAuthorityStore.trust_anchor_from_env(dict(env))
        authority_store = FirestoreAuthorityStore(client, project_id=project_id)
        store = FirestoreEvolutionStore(
            client, project_id=project_id, authority_store=authority_store,
            trust_anchor=trust_anchor, evidence_verifier=evidence_verifier,
            expected_workflow_sha256=workflow_pin,
        )
        return FirestoreEvolutionService(store, actor=actor)
    except EvolutionRuntimeBlocked:
        raise
    except Exception as exc:
        raise EvolutionRuntimeBlocked("Firestore evolution service bootstrap failed closed") from exc


__all__ = ["EvolutionRuntimeBlocked", "FirestoreEvolutionService", "create_firestore_evolution_service"]
