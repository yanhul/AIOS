"""Firestore-backed DurableRuntime adapter.

This adapter persists an AIOS dispatch intent before the provider boundary is
entered. It is a ledger adapter, not an authority issuer and not a provider
executor. AIOS remains responsible for contract/permit/retry authorization
and signed provider-receipt verification.

The Firestore client must target the explicitly provisioned database. No
credentials are accepted by this module; use Application Default Credentials
from the Cloud Run workload identity.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Callable, Mapping

from .durable_runtime import RuntimeSubmission


class LedgerConflict(RuntimeError):
    """A deterministic ledger identity already exists with different content."""


class LedgerUnavailable(RuntimeError):
    """The durable ledger could not confirm a committed transaction."""


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _canonical_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(raw.encode("utf-8")).hexdigest()


def _snapshot_data(snapshot: Any) -> dict[str, Any] | None:
    if not getattr(snapshot, "exists", False):
        return None
    data = snapshot.to_dict()
    if not isinstance(data, dict):
        raise LedgerConflict("ledger document is not a mapping")
    return data


class FirestoreDurableRuntime:
    """Persist immutable effect/attempt identity and dispatch intent.

    `transaction_runner` accepts (client, callback) and must execute callback
    inside a Firestore transaction with the SDK's retry/commit semantics. The
    production constructor uses google-cloud-firestore's transactional
    decorator; tests may inject a deterministic in-memory runner.
    """

    name = "google-cloud-firestore"

    def __init__(
        self,
        client: Any,
        *,
        project_id: str,
        transaction_runner: Callable[[Any, Callable[[Any], Any]], Any] | None = None,
    ) -> None:
        self.client = client
        self.project_id = _required_text(project_id, "project_id")
        actual_project = getattr(client, "project", None)
        if actual_project != self.project_id:
            raise ValueError("Firestore client project does not match configured project_id")
        if transaction_runner is None:
            try:
                from google.cloud.firestore_v1.transaction import transactional
            except ImportError as exc:
                raise RuntimeError(
                    "google-cloud-firestore is required to construct the production adapter"
                ) from exc

            def run(client_obj: Any, callback: Callable[[Any], Any]) -> Any:
                transaction = client_obj.transaction(max_attempts=5)

                @transactional
                def invoke(tx: Any) -> Any:
                    return callback(tx)

                return invoke(transaction)

            transaction_runner = run
        self._transaction_runner = transaction_runner

    @staticmethod
    def _identity(effect: Mapping[str, Any], attempt_id: str, attempt: int) -> tuple[dict[str, Any], dict[str, Any]]:
        effect_id = _required_text(effect.get("effect_id"), "effect.effect_id")
        provider = _required_text(effect.get("provider"), "effect.provider")
        _required_text(attempt_id, "attempt_id")
        if effect.get("state") != "DISPATCHED":
            raise ValueError("Firestore submission requires an AIOS-authorized DISPATCHED effect")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValueError("attempt number must be a positive integer")
        expected_attempt_id = f"{effect_id}:attempt:{attempt}"
        if attempt_id != expected_attempt_id:
            raise ValueError("attempt_id does not match deterministic AIOS effect attempt")
        effect_identity = {
            "effect_id": effect_id,
            "contract_id": _required_text(effect.get("contract_id"), "effect.contract_id"),
            "permit_id": _required_text(effect.get("permit_id"), "effect.permit_id"),
            "actor": _required_text(effect.get("actor"), "effect.actor"),
            "effect_type": _required_text(effect.get("effect_type"), "effect.effect_type"),
            "provider": provider,
            "policy_digest": _required_text(effect.get("policy_digest"), "effect.policy_digest"),
        }
        lineage = effect.get("execution_lineage")
        if lineage is not None:
            if not isinstance(lineage, dict) or not lineage:
                raise ValueError("execution_lineage must be a non-empty mapping when supplied")
            effect_identity["lineage_digest"] = _required_text(
                lineage.get("binding_digest"), "execution_lineage.binding_digest"
            )
        attempt_identity = {
            "attempt_id": attempt_id,
            "attempt_number": attempt,
            "provider": provider,
            "effect_id": effect_id,
            "effect_identity_digest": _canonical_digest(effect_identity),
            "lineage_digest": effect_identity.get("lineage_digest"),
            "idempotency_key": "aios-" + sha256(f"{effect_id}\0{attempt_id}".encode()).hexdigest(),
            "state": "DISPATCHED",
        }
        return effect_identity, attempt_identity

    def _refs(self, effect_id: str, attempt_id: str) -> tuple[Any, Any, Any]:
        effect_ref = self.client.collection("effects").document(effect_id)
        attempt_doc_id = sha256(attempt_id.encode("utf-8")).hexdigest()
        attempt_ref = effect_ref.collection("attempts").document(attempt_doc_id)
        event_id = sha256(f"dispatch\0{effect_id}\0{attempt_id}".encode()).hexdigest()
        event_ref = effect_ref.collection("events").document(event_id)
        return effect_ref, attempt_ref, event_ref

    def _persist(self, effect: Mapping[str, Any], attempt_id: str, attempt: int) -> RuntimeSubmission:
        effect_identity, attempt_identity = self._identity(effect, attempt_id, attempt)
        effect_id = effect_identity["effect_id"]
        effect_ref, attempt_ref, event_ref = self._refs(effect_id, attempt_id)
        effect_record = {
            **effect_identity,
            "state": "DISPATCHED",
            "current_attempt_id": attempt_id,
            "attempt_number": attempt,
            "revision": attempt,
        }
        event_record = {
            "event_type": "DISPATCH_INTENT_COMMITTED",
            "effect_id": effect_id,
            "attempt_id": attempt_id,
            "attempt_number": attempt,
            "provider": effect_identity["provider"],
            "effect_identity_digest": _canonical_digest(effect_identity),
            "attempt_identity_digest": _canonical_digest(attempt_identity),
        }

        def transaction_body(transaction: Any) -> None:
            effect_snapshot = effect_ref.get(transaction=transaction)
            attempt_snapshot = attempt_ref.get(transaction=transaction)
            event_snapshot = event_ref.get(transaction=transaction)
            old_effect = _snapshot_data(effect_snapshot)
            old_attempt = _snapshot_data(attempt_snapshot)
            old_event = _snapshot_data(event_snapshot)

            if old_effect is not None:
                for key, value in effect_identity.items():
                    if old_effect.get(key) != value:
                        raise LedgerConflict(f"effect identity conflict for {key}")
                if old_effect.get("current_attempt_id") not in (None, attempt_id):
                    raise LedgerConflict("effect already has a different current attempt")
                if old_effect.get("state") in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
                    raise LedgerConflict("terminal effect cannot be dispatched again")
            if old_attempt is not None and old_attempt != attempt_identity:
                raise LedgerConflict("attempt identity/idempotency key conflict")
            if old_event is not None and old_event != event_record:
                raise LedgerConflict("deterministic dispatch event conflict")

            # All reads occur before writes. Firestore retries the transaction on
            # contention; deterministic IDs make a repeated call idempotent.
            transaction.set(effect_ref, effect_record)
            if old_attempt is None:
                transaction.create(attempt_ref, attempt_identity)
            if old_event is None:
                transaction.create(event_ref, event_record)

        try:
            self._transaction_runner(self.client, transaction_body)
        except LedgerConflict:
            raise
        except Exception as exc:
            raise LedgerUnavailable(
                "Firestore dispatch intent commit was not confirmed; provider execution must not start"
            ) from exc
        return RuntimeSubmission(effect_id=effect_id, attempt_id=attempt_id, provider=effect_identity["provider"])

    def submit(self, *, effect: Mapping[str, Any], attempt_id: str) -> RuntimeSubmission:
        return self._persist(effect, attempt_id, 1)

    def retry(self, *, effect: Mapping[str, Any], attempt_id: str, attempt: int) -> RuntimeSubmission:
        # The current AIOS DurableRuntime protocol does not provide the previous
        # attempt's durable UNKNOWN transition or a Firestore-verifiable,
        # signed NOT_APPLIED proof. Recording a new attempt here would therefore
        # bypass the ledger's retry gate. Keep retries disabled until that
        # evidence is part of the adapter contract.
        raise LedgerConflict(
            "Firestore retry is blocked: durable UNKNOWN + authenticated NOT_APPLIED "
            "reconciliation must be integrated before a new attempt can be recorded"
        )

    def resume(self, *, effect: Mapping[str, Any], attempt_id: str) -> RuntimeSubmission:
        effect_id = _required_text(effect.get("effect_id"), "effect.effect_id")
        provider = _required_text(effect.get("provider"), "effect.provider")
        _required_text(attempt_id, "attempt_id")
        effect_ref, attempt_ref, _event_ref = self._refs(effect_id, attempt_id)

        def transaction_body(transaction: Any) -> RuntimeSubmission:
            effect_data = _snapshot_data(effect_ref.get(transaction=transaction))
            attempt_data = _snapshot_data(attempt_ref.get(transaction=transaction))
            if effect_data is None or attempt_data is None:
                raise LedgerConflict("cannot resume: durable effect/attempt record is missing")
            if (effect_data.get("effect_id") != effect_id
                    or effect_data.get("current_attempt_id") != attempt_id
                    or attempt_data.get("attempt_id") != attempt_id
                    or attempt_data.get("provider") != provider):
                raise LedgerConflict("cannot resume: durable effect/attempt binding mismatch")
            if effect_data.get("state") not in ("DISPATCHED", "UNKNOWN"):
                raise LedgerConflict("cannot resume a non-dispatched or terminal effect")
            return RuntimeSubmission(effect_id=effect_id, attempt_id=attempt_id, provider=provider)

        try:
            return self._transaction_runner(self.client, transaction_body)
        except LedgerConflict:
            raise
        except Exception as exc:
            raise LedgerUnavailable("Firestore resume readback was not confirmed") from exc


__all__ = ["FirestoreDurableRuntime", "LedgerConflict", "LedgerUnavailable"]
