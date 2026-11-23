"""Authoritative Firestore effect store.

This store owns durable effect state, attempt state, receipts and append-only
transition events. It deliberately does not authorize contracts, issue permits,
verify provider signatures, or call providers. Those checks remain in
core.effect_authority and core.runtime and must run before these write methods.

All state changes are compare-and-set transactions. A provider call is only
permitted after dispatch() returns with a confirmed committed intent. Recovery
must call get_effect()/get_attempt() and provider reconciliation for the SAME
attempt; it must never call execute() again for an ambiguous DISPATCHED attempt.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from typing import Any, Callable, Mapping


class EffectStoreConflict(RuntimeError):
    """A state transition lost its CAS or conflicts with immutable identity."""


class EffectStoreUnavailable(RuntimeError):
    """Firestore did not confirm a durable read/write."""


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return sha256(raw.encode("utf-8")).hexdigest()


def _data(snapshot: Any) -> dict[str, Any] | None:
    if not getattr(snapshot, "exists", False):
        return None
    value = snapshot.to_dict()
    if not isinstance(value, dict):
        raise EffectStoreConflict("Firestore record is not a mapping")
    return value


class FirestoreEffectStore:
    """Transactional effect/attempt/receipt store.

    transaction_runner(client, callback) must commit callback atomically using
    Firestore transaction semantics. The default runner uses the official SDK.
    """

    name = "firestore-effect-store"

    def __init__(self, client: Any, *, project_id: str,
                 transaction_runner: Callable[[Any, Callable[[Any], Any]], Any] | None = None):
        self.client = client
        self.project_id = _text(project_id, "project_id")
        if getattr(client, "project", None) != project_id:
            raise ValueError("Firestore client project does not match configured project_id")
        if transaction_runner is None:
            try:
                from google.cloud.firestore_v1.transaction import transactional
            except ImportError as exc:
                raise RuntimeError("google-cloud-firestore is required") from exc

            def run(client_obj: Any, callback: Callable[[Any], Any]) -> Any:
                tx = client_obj.transaction(max_attempts=5)

                @transactional
                def invoke(transaction: Any) -> Any:
                    return callback(transaction)

                return invoke(tx)

            transaction_runner = run
        self._run = transaction_runner

    def _effect_ref(self, effect_id: str) -> Any:
        return self.client.collection("effects").document(_text(effect_id, "effect_id"))

    def _attempt_ref(self, effect_id: str, attempt_id: str) -> Any:
        return self._effect_ref(effect_id).collection("attempts").document(
            sha256(_text(attempt_id, "attempt_id").encode()).hexdigest()
        )

    def _event_ref(self, effect_id: str, event_id: str) -> Any:
        return self._effect_ref(effect_id).collection("events").document(event_id)

    def _outbox_ref(self, task_id: str) -> Any:
        return self.client.collection("dispatch_outbox").document(_text(task_id, "task_id"))

    def _confirmed(self, label: str, callback: Callable[[Any], Any]) -> Any:
        try:
            return self._run(self.client, callback)
        except (EffectStoreConflict, ValueError):
            raise
        except Exception as exc:
            raise EffectStoreUnavailable(f"{label} was not confirmed; do not call provider or retry") from exc

    def create_effect(self, effect: Mapping[str, Any]) -> dict[str, Any]:
        required = ("effect_id", "contract_id", "permit_id", "actor", "effect_type", "policy_digest")
        record = {key: _text(effect.get(key), f"effect.{key}") for key in required}
        if effect.get("logical_operation_id") is not None:
            record["logical_operation_id"] = _text(effect.get("logical_operation_id"), "effect.logical_operation_id")
        authority_digests = effect.get("authority_digests")
        if authority_digests is not None:
            required_authority_keys = {
                "contract_digest", "permit_digest", "attestation_digest",
                "policy_digest", "capability_digests",
            }
            if (not isinstance(authority_digests, Mapping)
                    or set(authority_digests) != required_authority_keys
                    or not isinstance(authority_digests.get("capability_digests"), Mapping)):
                raise ValueError("effect.authority_digests must contain the complete signed authority bundle")
            for key in required_authority_keys - {"capability_digests"}:
                record_value = authority_digests.get(key)
                if (not isinstance(record_value, str) or len(record_value) != 64
                        or any(ch not in "0123456789abcdef" for ch in record_value)):
                    raise ValueError(f"effect.authority_digests.{key} must be a SHA-256 hex digest")
            capabilities = dict(authority_digests["capability_digests"])
            if not capabilities or any(
                not isinstance(k, str) or not k.strip()
                or not isinstance(v, str) or len(v) != 64
                or any(ch not in "0123456789abcdef" for ch in v)
                for k, v in capabilities.items()
            ):
                raise ValueError("effect.authority_digests.capability_digests is invalid")
            record["authority_digests"] = {
                **{key: authority_digests[key] for key in required_authority_keys - {"capability_digests"}},
                "capability_digests": capabilities,
            }
        max_attempts = effect.get("max_attempts")
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
            raise ValueError("effect.max_attempts must be a positive integer")
        record["max_attempts"] = max_attempts
        if effect.get("state") != "PLANNED":
            raise ValueError("new durable effect must be PLANNED")
        record.update({"state": "PLANNED", "attempt": 0, "revision": 0})
        ref = self._effect_ref(record["effect_id"])
        event_id = _digest({"event": "CREATED", "effect_id": record["effect_id"]})
        event_ref = self._event_ref(record["effect_id"], event_id)
        event = {"event_type": "EFFECT_CREATED", "effect_id": record["effect_id"],
                 "record_digest": _digest(record), "revision": 0}

        def body(tx: Any) -> dict[str, Any]:
            old = _data(ref.get(transaction=tx))
            old_event = _data(event_ref.get(transaction=tx))
            if old is not None:
                if old != record:
                    raise EffectStoreConflict("effect ID already exists with different immutable content")
                if old_event != event:
                    raise EffectStoreConflict("effect creation event missing or conflicting")
                return old
            if old_event is not None:
                raise EffectStoreConflict("orphan effect creation event")
            tx.create(ref, record)
            tx.create(event_ref, event)
            return record
        return self._confirmed("effect creation transaction", body)

    def get_effect(self, effect_id: str) -> dict[str, Any] | None:
        try:
            return _data(self._effect_ref(effect_id).get())
        except Exception as exc:
            raise EffectStoreUnavailable("effect readback was not confirmed") from exc

    def get_attempt(self, effect_id: str, attempt_id: str) -> dict[str, Any] | None:
        try:
            return _data(self._attempt_ref(effect_id, attempt_id).get())
        except Exception as exc:
            raise EffectStoreUnavailable("attempt readback was not confirmed") from exc

    def dispatch(self, *, effect_id: str, attempt_id: str, provider: str,
                 expected_revision: int, lineage: Mapping[str, Any] | None = None) -> dict[str, Any]:
        provider = _text(provider, "provider")
        attempt_id = _text(attempt_id, "attempt_id")
        if (os.environ.get("AIOS_REQUIRE_EXECUTION_LINEAGE", "").lower() == "true"
                and (not isinstance(lineage, Mapping) or not lineage)):
            raise EffectStoreConflict("production dispatch requires immutable execution lineage")
        ref = self._effect_ref(effect_id)
        attempt_ref = self._attempt_ref(effect_id, attempt_id)
        event_id = _digest({"event": "DISPATCHED", "effect_id": effect_id, "attempt_id": attempt_id})
        event_ref = self._event_ref(effect_id, event_id)
        idempotency_key = "aios-" + sha256(f"{effect_id}\0{attempt_id}".encode()).hexdigest()

        def body(tx: Any) -> dict[str, Any]:
            current = _data(ref.get(transaction=tx))
            existing_attempt = _data(attempt_ref.get(transaction=tx))
            existing_event = _data(event_ref.get(transaction=tx))
            if current is None:
                raise EffectStoreConflict("cannot dispatch missing durable effect")
            if current.get("revision") != expected_revision or current.get("state") != "PLANNED":
                raise EffectStoreConflict("dispatch CAS failed; effect is not the expected PLANNED revision")
            attempt_number = current.get("attempt", 0) + 1
            expected_id = f"{effect_id}:attempt:{attempt_number}"
            if attempt_id != expected_id:
                raise EffectStoreConflict("attempt ID does not match durable effect attempt number")
            attempt = {"effect_id": effect_id, "attempt_id": attempt_id,
                       "attempt_number": attempt_number, "provider": provider,
                       "idempotency_key": idempotency_key, "state": "DISPATCHED",
                       "lineage_digest": _digest(lineage) if lineage else None}
            if existing_attempt is not None or existing_event is not None:
                raise EffectStoreConflict("dispatch attempt/event already exists; use resume, never redispatch")
            updated = dict(current, state="DISPATCHED", attempt=attempt_number,
                           attempt_id=attempt_id, provider=provider,
                           revision=expected_revision + 1,
                           execution_lineage=dict(lineage) if lineage else None)
            event = {"event_type": "DISPATCH_INTENT_COMMITTED", "effect_id": effect_id,
                     "attempt_id": attempt_id, "attempt_number": attempt_number,
                     "provider": provider, "idempotency_key": idempotency_key,
                     "from_revision": expected_revision, "to_revision": expected_revision + 1}
            # The durable outbox record is committed atomically with the
            # effect/attempt dispatch intent. A process crash after this commit
            # cannot lose the obligation to enqueue the deterministic task.
            from .cloud_tasks_contract import deterministic_task_name, dispatch_event_digest
            task_id = deterministic_task_name(effect_id, attempt_id)
            outbox_ref = self._outbox_ref(task_id)
            # tx.create carries the non-existence precondition atomically; do
            # not add an extra transactional read/lock for this deterministic ID.
            outbox = {
                "schema": "aios.dispatch-outbox.v1",
                "task_id": task_id,
                "effect_id": effect_id,
                "attempt_id": attempt_id,
                "expected_revision": expected_revision + 1,
                "dispatch_event_digest": dispatch_event_digest(effect_id, attempt_id),
                "state": "PENDING",
                "lease_generation": 0,
            }
            tx.set(ref, updated)
            tx.create(attempt_ref, attempt)
            tx.create(event_ref, event)
            tx.create(outbox_ref, outbox)
            return updated
        return self._confirmed("dispatch intent transaction", body)

    def mark_unknown(self, *, effect_id: str, attempt_id: str, reason: str,
                     expected_revision: int) -> dict[str, Any]:
        reason = _text(reason, "reason")
        ref = self._effect_ref(effect_id)
        attempt_ref = self._attempt_ref(effect_id, attempt_id)
        event_id = _digest({"event": "UNKNOWN", "effect_id": effect_id, "attempt_id": attempt_id,
                            "revision": expected_revision + 1})

        def body(tx: Any) -> dict[str, Any]:
            current = _data(ref.get(transaction=tx))
            attempt = _data(attempt_ref.get(transaction=tx))
            if current is None or attempt is None:
                raise EffectStoreConflict("UNKNOWN transition requires durable effect and attempt")
            if current.get("revision") != expected_revision or current.get("state") != "DISPATCHED":
                raise EffectStoreConflict("UNKNOWN transition CAS failed")
            if current.get("attempt_id") != attempt_id or attempt.get("attempt_id") != attempt_id:
                raise EffectStoreConflict("UNKNOWN transition attempt binding mismatch")
            updated = dict(current, state="UNKNOWN", unknown_reason=reason,
                           revision=expected_revision + 1)
            attempt_updated = dict(attempt, state="UNKNOWN", unknown_reason=reason)
            tx.set(ref, updated)
            tx.set(attempt_ref, attempt_updated)
            tx.create(self._event_ref(effect_id, event_id), {
                "event_type": "ATTEMPT_UNKNOWN", "effect_id": effect_id,
                "attempt_id": attempt_id, "reason_digest": sha256(reason.encode()).hexdigest(),
                "from_revision": expected_revision, "to_revision": expected_revision + 1})
            return updated
        return self._confirmed("UNKNOWN transition transaction", body)

    def record_verified_receipt(self, *, effect_id: str, attempt_id: str,
                                receipt: Mapping[str, Any], verified_authentication: Mapping[str, Any],
                                expected_revision: int) -> dict[str, Any]:
        """Persist only after AIOS has cryptographically verified the receipt.

        This method cannot verify signatures itself. The caller must pass the
        exact authentication object returned by the existing AIOS verifier.
        """
        if not isinstance(receipt, Mapping) or not isinstance(verified_authentication, Mapping):
            raise ValueError("receipt and verified authentication must be mappings")
        required = ("receipt_id", "provider", "provider_operation_id", "outcome",
                    "observation", "observation_digest")
        receipt_record = {key: receipt.get(key) for key in required}
        if receipt.get("evidence") is not None:
            receipt_record["evidence"] = receipt.get("evidence")
        if any(value is None for value in receipt_record.values()):
            raise ValueError("verified receipt schema is incomplete")
        if receipt_record["outcome"] not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            raise ValueError("receipt outcome must be a terminal observed outcome")
        if not isinstance(receipt_record["observation"], dict) or not receipt_record["observation"]:
            raise ValueError("receipt observation must be a non-empty mapping")
        receipt_id = _text(receipt_record["receipt_id"], "receipt.receipt_id")
        ref = self._effect_ref(effect_id)
        attempt_ref = self._attempt_ref(effect_id, attempt_id)
        receipt_ref = self.client.collection("provider_receipts").document(receipt_id)
        event_id = _digest({"event": "RECEIPT", "effect_id": effect_id, "attempt_id": attempt_id,
                            "receipt_id": receipt_id})

        def body(tx: Any) -> dict[str, Any]:
            current = _data(ref.get(transaction=tx))
            attempt = _data(attempt_ref.get(transaction=tx))
            existing_receipt = _data(receipt_ref.get(transaction=tx))
            if current is None or attempt is None:
                raise EffectStoreConflict("receipt requires durable effect and attempt")
            if current.get("revision") != expected_revision:
                # Crash after commit but before acknowledgement: accept exact readback only.
                if current.get("state") == receipt_record["outcome"] and existing_receipt is not None:
                    expected_receipt = {"record_type": "AIOS_TERMINAL_PROVIDER_RECEIPT",
                                        **receipt_record, "effect_id": effect_id, "attempt_id": attempt_id,
                                        "contract_id": current["contract_id"], "permit_id": current["permit_id"],
                                        "authentication": dict(verified_authentication),
                                        "lineage_digest": (current.get("execution_lineage") or {}).get("lineage_digest")}
                    if existing_receipt == expected_receipt:
                        return current
                raise EffectStoreConflict("receipt terminal CAS failed")
            if current.get("state") not in ("DISPATCHED", "UNKNOWN"):
                raise EffectStoreConflict("receipt terminal CAS failed")
            if current.get("attempt_id") != attempt_id or attempt.get("attempt_id") != attempt_id:
                raise EffectStoreConflict("receipt attempt binding mismatch")
            if attempt.get("state") not in ("DISPATCHED", "UNKNOWN"):
                raise EffectStoreConflict("receipt attempt is already terminal")
            if current.get("provider") != receipt_record["provider"] or attempt.get("provider") != receipt_record["provider"]:
                raise EffectStoreConflict("receipt provider binding mismatch")
            terminal = dict(current, state=receipt_record["outcome"],
                            provider_operation_id=receipt_record["provider_operation_id"],
                            provider_observation=receipt_record["observation"],
                            provider_evidence=receipt_record.get("evidence"),
                            provider_receipt_id=receipt_id,
                            provider_authentication=dict(verified_authentication),
                            observation_digest=receipt_record["observation_digest"],
                            revision=expected_revision + 1)
            attempt_terminal = dict(attempt, state=receipt_record["outcome"],
                                    provider_receipt_id=receipt_id)
            immutable_receipt = {"record_type": "AIOS_TERMINAL_PROVIDER_RECEIPT",
                                 **receipt_record, "effect_id": effect_id, "attempt_id": attempt_id,
                                 "contract_id": current["contract_id"], "permit_id": current["permit_id"],
                                 "authentication": dict(verified_authentication),
                                 "lineage_digest": (current.get("execution_lineage") or {}).get("lineage_digest")}
            if existing_receipt is not None and existing_receipt != immutable_receipt:
                raise EffectStoreConflict("receipt ID replayed with different content")
            if existing_receipt is None:
                tx.create(receipt_ref, immutable_receipt)
            tx.set(ref, terminal)
            tx.set(attempt_ref, attempt_terminal)
            tx.create(self._event_ref(effect_id, event_id), {
                "event_type": "VERIFIED_PROVIDER_RECEIPT", "effect_id": effect_id,
                "attempt_id": attempt_id, "receipt_id": receipt_id,
                "outcome": receipt_record["outcome"], "from_revision": expected_revision,
                "to_revision": expected_revision + 1})
            return terminal
        return self._confirmed("verified receipt transaction", body)

    def consume_retry_authorization(self, *, authorization: Mapping[str, Any],
                                    issuer_keyring: Any, not_applied_verifier: Callable[..., bool],
                                    now: float | None = None) -> dict[str, Any]:
        """Consume a signed retry grant and allocate the next dispatch atomically.

        The nonce consumption, exact UNKNOWN-state CAS, immutable next attempt,
        dispatch event and Cloud Tasks outbox obligation commit in one Firestore
        transaction. No provider call occurs in this method.
        """
        import time
        from .retry_issuer import RetryAuthorizationRejected, effect_state_digest
        from .cloud_tasks_contract import deterministic_task_name, dispatch_event_digest

        if not isinstance(authorization, Mapping):
            raise ValueError("authorization must be a mapping")
        effect_id = _text(authorization.get("effect_id"), "authorization.effect_id")
        attempt_id = _text(authorization.get("attempt_id"), "authorization.attempt_id")
        effect = self.get_effect(effect_id)
        attempt = self.get_attempt(effect_id, attempt_id)
        if effect is None or attempt is None:
            raise EffectStoreConflict("retry requires existing effect and attempt")
        claims = issuer_keyring.verify(
            authorization, now=time.time() if now is None else now,
            effect=effect, attempt=attempt, not_applied_verifier=not_applied_verifier,
        )
        nonce_key = sha256((claims["issuer_id"] + "\\0" + claims["nonce"]).encode()).hexdigest()
        nonce_ref = self.client.collection("retry_authorization_consumptions").document(nonce_key)
        effect_ref = self._effect_ref(effect_id)
        attempt_ref = self._attempt_ref(effect_id, attempt_id)
        retry_event_id = _digest({"event": "RETRY_AUTHORIZATION_CONSUMED",
                                  "effect_id": effect_id, "attempt_id": attempt_id,
                                  "issuer_id": claims["issuer_id"], "nonce": claims["nonce"]})
        retry_event_ref = self._event_ref(effect_id, retry_event_id)

        def body(tx: Any) -> dict[str, Any]:
            current = _data(effect_ref.get(transaction=tx))
            current_attempt = _data(attempt_ref.get(transaction=tx))
            consumed = _data(nonce_ref.get(transaction=tx))
            if consumed is not None:
                raise EffectStoreConflict("retry authorization nonce already consumed")
            if current is None or current_attempt is None:
                raise EffectStoreConflict("retry effect/attempt disappeared")
            if current.get("state") != "UNKNOWN" or current_attempt.get("state") != "UNKNOWN":
                raise EffectStoreConflict("retry requires current UNKNOWN effect and attempt")
            if (current.get("attempt_id") != attempt_id
                    or current_attempt.get("attempt_id") != attempt_id
                    or current.get("revision") != claims["state_revision"]
                    or effect_state_digest(current) != claims["state_digest"]):
                raise EffectStoreConflict("retry authorization became stale before transaction commit")
            if current.get("attempt") != claims["attempt_number"]:
                raise EffectStoreConflict("retry attempt number binding mismatch")
            next_number = current.get("attempt", 0) + 1
            if next_number > current.get("max_attempts", 0):
                raise EffectStoreConflict("retry exceeds effect max_attempts")

            next_attempt_id = f"{effect_id}:attempt:{next_number}"
            next_attempt_ref = self._attempt_ref(effect_id, next_attempt_id)
            dispatch_event_id = _digest({"event": "DISPATCHED", "effect_id": effect_id,
                                         "attempt_id": next_attempt_id})
            dispatch_event_ref = self._event_ref(effect_id, dispatch_event_id)
            task_id = deterministic_task_name(effect_id, next_attempt_id)
            outbox_ref = self._outbox_ref(task_id)
            # Read every transaction document before any write (Firestore rule).
            next_attempt_old = _data(next_attempt_ref.get(transaction=tx))
            dispatch_event_old = _data(dispatch_event_ref.get(transaction=tx))
            outbox_old = _data(outbox_ref.get(transaction=tx))
            if next_attempt_old is not None or dispatch_event_old is not None or outbox_old is not None:
                raise EffectStoreConflict("next retry attempt/event/outbox already exists; refusing replay")

            consumed_record = {
                "record_type": "AIOS_RETRY_AUTHORIZATION_CONSUMPTION",
                "issuer_id": claims["issuer_id"], "key_id": claims["key_id"],
                "nonce": claims["nonce"], "effect_id": effect_id,
                "attempt_id": attempt_id, "next_attempt_id": next_attempt_id,
                "state_digest": claims["state_digest"],
                "not_applied_proof_digest": claims["not_applied_proof_digest"],
                "authorization_digest": _digest(dict(authorization)),
            }
            idempotency_key = "aios-" + sha256(
                f"{effect_id}\\0{next_attempt_id}".encode()
            ).hexdigest()
            next_attempt = {
                "effect_id": effect_id, "attempt_id": next_attempt_id,
                "attempt_number": next_number, "provider": current["provider"],
                "idempotency_key": idempotency_key, "state": "DISPATCHED",
                "lineage_digest": _digest(current["execution_lineage"])
                    if current.get("execution_lineage") else None,
                "retry_authorization_digest": consumed_record["authorization_digest"],
            }
            next_revision = current["revision"] + 1
            updated = dict(
                current, state="DISPATCHED", attempt=next_number,
                attempt_id=next_attempt_id, revision=next_revision,
                retry_authorization_digest=consumed_record["authorization_digest"],
                retry_authorization_issuer=claims["issuer_id"],
            )
            updated.pop("unknown_reason", None)
            dispatch_event = {
                "event_type": "DISPATCH_INTENT_COMMITTED", "effect_id": effect_id,
                "attempt_id": next_attempt_id, "attempt_number": next_number,
                "provider": current["provider"], "idempotency_key": idempotency_key,
                "from_revision": next_revision - 1, "to_revision": next_revision,
                "retry_authorization_digest": consumed_record["authorization_digest"],
            }
            outbox = {
                "schema": "aios.dispatch-outbox.v1", "task_id": task_id,
                "effect_id": effect_id, "attempt_id": next_attempt_id,
                "expected_revision": next_revision,
                "dispatch_event_digest": dispatch_event_digest(effect_id, next_attempt_id),
                "state": "PENDING", "lease_generation": 0,
            }

            tx.create(nonce_ref, consumed_record)
            tx.set(effect_ref, updated)
            tx.create(retry_event_ref, {
                "event_type": "RETRY_AUTHORIZATION_CONSUMED",
                "effect_id": effect_id, "attempt_id": attempt_id,
                "next_attempt_id": next_attempt_id, "issuer_id": claims["issuer_id"],
                "authorization_digest": consumed_record["authorization_digest"],
                "not_applied_proof_digest": claims["not_applied_proof_digest"],
                "from_revision": current["revision"], "to_revision": next_revision,
            })
            tx.create(next_attempt_ref, next_attempt)
            tx.create(dispatch_event_ref, dispatch_event)
            tx.create(outbox_ref, outbox)
            return updated

        try:
            return self._confirmed("retry authorization + next dispatch transaction", body)
        except RetryAuthorizationRejected as exc:
            raise EffectStoreConflict("retry authorization rejected; DENY") from exc

    def bind_provider_operation_id(self, *, effect_id: str, attempt_id: str,
                                   provider: str, provider_operation_id: str) -> dict[str, Any]:
        """Durably bind a provider-created operation to this exact attempt.

        This is a post-create persistence boundary, not provider idempotency:
        if the process dies after provider acceptance but before this transaction,
        the operation remains unaddressable and must stay UNKNOWN.
        """
        provider = _text(provider, "provider")
        provider_operation_id = _text(provider_operation_id, "provider_operation_id")
        effect_ref = self._effect_ref(effect_id)
        attempt_ref = self._attempt_ref(effect_id, attempt_id)
        event_id = _digest({"event": "PROVIDER_OPERATION_BOUND", "effect_id": effect_id,
                            "attempt_id": attempt_id, "provider": provider,
                            "provider_operation_id": provider_operation_id})
        event_ref = self._event_ref(effect_id, event_id)
        event = {"event_type": "PROVIDER_OPERATION_BOUND", "effect_id": effect_id,
                 "attempt_id": attempt_id, "provider": provider,
                 "provider_operation_id": provider_operation_id,
                 "operation_id_digest": sha256(provider_operation_id.encode()).hexdigest()}

        def body(tx: Any) -> dict[str, Any]:
            effect = _data(effect_ref.get(transaction=tx))
            attempt = _data(attempt_ref.get(transaction=tx))
            existing_event = _data(event_ref.get(transaction=tx))
            if effect is None or attempt is None:
                raise EffectStoreConflict("provider operation binding requires durable effect and attempt")
            if (effect.get("attempt_id") != attempt_id or attempt.get("attempt_id") != attempt_id
                    or effect.get("provider") != provider or attempt.get("provider") != provider
                    or effect.get("state") not in ("DISPATCHED", "UNKNOWN")
                    or attempt.get("state") not in ("DISPATCHED", "UNKNOWN")):
                raise EffectStoreConflict("provider operation binding effect/attempt/provider mismatch")
            old_id = attempt.get("provider_operation_id")
            if old_id is not None:
                if old_id != provider_operation_id or attempt.get("provider_operation_provider") != provider:
                    raise EffectStoreConflict("provider operation ID is immutable and already bound")
                if existing_event != event:
                    raise EffectStoreConflict("provider operation binding event missing or conflicting")
                return attempt
            if existing_event is not None:
                raise EffectStoreConflict("orphan provider operation binding event")
            updated = dict(attempt, provider_operation_id=provider_operation_id,
                           provider_operation_provider=provider)
            tx.set(attempt_ref, updated)
            tx.create(event_ref, event)
            return updated
        return self._confirmed("provider operation binding transaction", body)

    def resume_same_attempt(self, *, effect_id: str, attempt_id: str) -> dict[str, Any]:
        """Read exact ambiguous attempt; caller must reconcile provider, never execute it."""
        effect = self.get_effect(effect_id)
        attempt = self.get_attempt(effect_id, attempt_id)
        if effect is None or attempt is None:
            raise EffectStoreConflict("resume requires durable effect and attempt")
        if (effect.get("state") not in ("DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE")
                or effect.get("attempt_id") != attempt_id
                or attempt.get("attempt_id") != attempt_id
                or effect.get("provider") != attempt.get("provider")):
            raise EffectStoreConflict("resume exact-attempt binding/state mismatch")
        return {"effect": effect, "attempt": attempt}

    def get_dispatch_outbox(self, *, effect_id: str, attempt_id: str) -> dict[str, Any] | None:
        from .cloud_tasks_contract import deterministic_task_name
        task_id = deterministic_task_name(effect_id, attempt_id)
        try:
            return _data(self._outbox_ref(task_id).get())
        except Exception as exc:
            raise EffectStoreUnavailable("dispatch outbox readback was not confirmed") from exc

    def list_dispatch_outbox_candidates(self, *, now: float, limit: int) -> list[dict[str, Any]]:
        """List pending and expired-lease obligations for a periodic reconciler."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be an integer from 1 to 500")
        try:
            collection = self.client.collection("dispatch_outbox")
            pending = list(collection.where("state", "==", "PENDING").limit(limit).stream())
            remaining = max(0, limit - len(pending))
            expired = []
            if remaining:
                # Query only the lease_until single-field index, then filter
                # state locally to avoid requiring a composite index at rollout.
                expired = list(
                    collection.where("lease_until", "<=", now).limit(remaining).stream()
                )
                expired = [
                    snapshot for snapshot in expired
                    if (_data(snapshot) or {}).get("state") == "LEASED"
                ]
            return [record for snapshot in pending + expired
                    if (record := _data(snapshot)) is not None]
        except Exception as exc:
            raise EffectStoreUnavailable("dispatch outbox scan was not confirmed") from exc

    def claim_dispatch_outbox(self, *, effect_id: str, attempt_id: str,
                              lease_owner: str, now: float, lease_seconds: int) -> dict[str, Any]:
        """Lease one durable enqueue obligation; never changes effect/attempt state."""
        from .cloud_tasks_contract import deterministic_task_name
        lease_owner = _text(lease_owner, "lease_owner")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds < 1:
            raise ValueError("lease_seconds must be a positive integer")
        task_id = deterministic_task_name(effect_id, attempt_id)
        ref = self._outbox_ref(task_id)

        def body(tx: Any) -> dict[str, Any]:
            record = _data(ref.get(transaction=tx))
            if record is None:
                raise EffectStoreConflict("dispatch outbox record is missing")
            if record.get("effect_id") != effect_id or record.get("attempt_id") != attempt_id:
                raise EffectStoreConflict("dispatch outbox identity mismatch")
            if record.get("state") == "PUBLISHED":
                return record
            if (record.get("state") == "LEASED" and record.get("lease_until", 0) > now
                    and record.get("lease_owner") != lease_owner):
                raise EffectStoreConflict("dispatch outbox is leased by another publisher")
            updated = dict(record, state="LEASED", lease_owner=lease_owner,
                           lease_until=now + lease_seconds,
                           lease_generation=record.get("lease_generation", 0) + 1)
            tx.set(ref, updated)
            return updated
        return self._confirmed("dispatch outbox lease transaction", body)

    def mark_dispatch_outbox_published(self, *, effect_id: str, attempt_id: str,
                                       lease_owner: str, published_at: float) -> dict[str, Any]:
        from .cloud_tasks_contract import deterministic_task_name
        task_id = deterministic_task_name(effect_id, attempt_id)
        ref = self._outbox_ref(task_id)

        def body(tx: Any) -> dict[str, Any]:
            record = _data(ref.get(transaction=tx))
            if record is None:
                raise EffectStoreConflict("dispatch outbox record is missing")
            if record.get("state") == "PUBLISHED":
                return record
            if record.get("state") != "LEASED" or record.get("lease_owner") != lease_owner:
                raise EffectStoreConflict("dispatch outbox lease ownership mismatch")
            updated = dict(record, state="PUBLISHED", published_at=published_at)
            updated.pop("lease_owner", None)
            updated.pop("lease_until", None)
            tx.set(ref, updated)
            return updated
        return self._confirmed("dispatch outbox publish acknowledgement transaction", body)

    def release_dispatch_outbox(self, *, effect_id: str, attempt_id: str,
                                lease_owner: str, error: str) -> dict[str, Any]:
        from .cloud_tasks_contract import deterministic_task_name
        task_id = deterministic_task_name(effect_id, attempt_id)
        ref = self._outbox_ref(task_id)

        def body(tx: Any) -> dict[str, Any]:
            record = _data(ref.get(transaction=tx))
            if record is None:
                raise EffectStoreConflict("dispatch outbox record is missing")
            if record.get("state") != "LEASED" or record.get("lease_owner") != lease_owner:
                raise EffectStoreConflict("dispatch outbox lease ownership mismatch")
            updated = dict(record, state="PENDING",
                           last_error_digest=sha256(_text(error, "error").encode()).hexdigest())
            updated.pop("lease_owner", None)
            updated.pop("lease_until", None)
            tx.set(ref, updated)
            return updated
        return self._confirmed("dispatch outbox release transaction", body)
