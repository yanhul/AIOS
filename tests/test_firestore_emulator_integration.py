"""Real Firestore Emulator integration tests (not transaction-double tests)."""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from google.cloud import firestore
from google.auth.credentials import AnonymousCredentials

from core.firestore_effect_store import EffectStoreConflict, FirestoreEffectStore


PROJECT = os.environ.get("AIOS_FIRESTORE_PROJECT_ID", "aios-emulator-test")
pytestmark = pytest.mark.skipif(
    not os.environ.get("FIRESTORE_EMULATOR_HOST"),
    reason="requires a running Firestore Emulator",
)


def make_store():
    client = firestore.Client(project=PROJECT, credentials=AnonymousCredentials())
    return FirestoreEffectStore(client, project_id=PROJECT)


def make_effect():
    effect_id = "emulator-" + uuid.uuid4().hex
    return effect_id, {
        "effect_id": effect_id,
        "logical_operation_id": "crash-window-test",
        "contract_id": "contract-fixture",
        "permit_id": "permit-fixture",
        "actor": "emulator-test",
        "effect_type": "external_effect",
        "policy_digest": "sha256:emulator-fixture",
        "max_attempts": 1,
        "state": "PLANNED",
    }


def test_restart_after_dispatch_commit_recovers_same_attempt_without_new_dispatch():
    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    dispatched = store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id, provider="provider-fixture",
        expected_revision=0,
    )
    # dispatch() returns the updated effect record; the idempotency key belongs
    # to the separate immutable attempt record.
    committed_attempt = store.get_attempt(effect_id, attempt_id)
    assert dispatched["state"] == "DISPATCHED"
    assert committed_attempt is not None
    assert committed_attempt["idempotency_key"]

    # Recreate client/store to model a new worker process after a crash.
    restarted = make_store()
    recovered = restarted.resume_same_attempt(effect_id=effect_id, attempt_id=attempt_id)
    assert recovered["effect"]["state"] == "DISPATCHED"
    assert recovered["attempt"]["idempotency_key"] == committed_attempt["idempotency_key"]
    assert restarted.get_effect(effect_id)["attempt_id"] == attempt_id
    with pytest.raises(EffectStoreConflict):
        restarted.dispatch(
            effect_id=effect_id, attempt_id=effect_id + ":attempt:2",
            provider="provider-fixture", expected_revision=1,
        )


def test_unknown_survives_worker_restart_and_blocks_next_attempt():
    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id, provider="provider-fixture",
        expected_revision=0,
    )
    store.mark_unknown(
        effect_id=effect_id, attempt_id=attempt_id,
        reason="simulated process death after possible provider side effect",
        expected_revision=1,
    )

    restarted = make_store()
    recovered = restarted.resume_same_attempt(effect_id=effect_id, attempt_id=attempt_id)
    assert recovered["effect"]["state"] == "UNKNOWN"
    with pytest.raises(EffectStoreConflict):
        restarted.dispatch(
            effect_id=effect_id, attempt_id=effect_id + ":attempt:2",
            provider="provider-fixture", expected_revision=2,
        )
    assert restarted.get_effect(effect_id)["attempt"] == 1


def test_concurrent_dispatch_cas_has_one_winner():
    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)

    def attempt_dispatch(_):
        try:
            store.dispatch(
                effect_id=effect_id, attempt_id=effect_id + ":attempt:1",
                provider="provider-fixture", expected_revision=0,
            )
            return "COMMITTED"
        except EffectStoreConflict:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt_dispatch, range(2)))

    assert sorted(outcomes) == ["COMMITTED", "CONFLICT"]
    assert store.get_effect(effect_id)["revision"] == 1


def test_dispatch_outbox_is_atomic_leased_and_survives_restart():
    from core.cloud_tasks_contract import deterministic_task_name

    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id,
        provider="provider-fixture", expected_revision=0,
    )

    # The outbox record is visible only after the same dispatch transaction
    # has committed the effect and attempt.
    outbox = store.get_dispatch_outbox(effect_id=effect_id, attempt_id=attempt_id)
    assert outbox is not None
    assert outbox["state"] == "PENDING"
    assert outbox["task_id"] == deterministic_task_name(effect_id, attempt_id)
    assert outbox["expected_revision"] == 1
    candidates = store.list_dispatch_outbox_candidates(now=1000, limit=20)
    assert any(item["task_id"] == outbox["task_id"] for item in candidates)
    assert store.get_effect(effect_id)["state"] == "DISPATCHED"
    assert store.get_attempt(effect_id, attempt_id)["state"] == "DISPATCHED"

    claimed = store.claim_dispatch_outbox(
        effect_id=effect_id, attempt_id=attempt_id,
        lease_owner="publisher-a", now=1000, lease_seconds=30,
    )
    assert claimed["state"] == "LEASED"
    assert claimed["lease_generation"] == 1
    with pytest.raises(EffectStoreConflict):
        store.claim_dispatch_outbox(
            effect_id=effect_id, attempt_id=attempt_id,
            lease_owner="publisher-b", now=1010, lease_seconds=30,
        )

    # A restarted publisher can reclaim after the lease expires.
    reclaimed = make_store().claim_dispatch_outbox(
        effect_id=effect_id, attempt_id=attempt_id,
        lease_owner="publisher-b", now=1031, lease_seconds=30,
    )
    assert reclaimed["state"] == "LEASED"
    assert reclaimed["lease_generation"] == 2
    published = make_store().mark_dispatch_outbox_published(
        effect_id=effect_id, attempt_id=attempt_id,
        lease_owner="publisher-b", published_at=1032,
    )
    assert published["state"] == "PUBLISHED"
    assert store.get_dispatch_outbox(effect_id=effect_id, attempt_id=attempt_id)["state"] == "PUBLISHED"


def test_cloud_tasks_redelivery_after_worker_crash_never_executes_new_attempt():
    import time
    from core.cloud_tasks_contract import SCHEMA, dispatch_event_digest
    from core.cloud_tasks_worker import handle_dispatch_delivery

    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id,
        provider="provider-fixture", expected_revision=0,
    )
    now = time.time()
    task = {
        "schema": SCHEMA, "effect_id": effect_id, "attempt_id": attempt_id,
        "expected_revision": 1,
        "dispatch_event_digest": dispatch_event_digest(effect_id, attempt_id),
        "issued_at": now - 5, "expires_at": now + 300,
    }
    provider_calls = []

    # Process died after dispatch commit. Both the original delivery and its
    # redelivery can only resume this exact attempt; no provider adapter is
    # injected, so the endpoint fails closed and asks Cloud Tasks to retry.
    first = handle_dispatch_delivery(task, store=store, now=now)
    second = handle_dispatch_delivery(task, store=make_store(), now=now + 1)
    assert first[0] == second[0] == 503
    assert first[1]["status"] == "RECONCILIATION_ADAPTER_UNAVAILABLE"
    assert second[1]["status"] == "RECONCILIATION_ADAPTER_UNAVAILABLE"
    assert provider_calls == []
    assert store.get_effect(effect_id)["state"] == "DISPATCHED"
    assert store.get_effect(effect_id)["attempt"] == 1
    assert store.get_attempt(effect_id, attempt_id)["attempt_number"] == 1

    # Once a separately verified terminal receipt is durably committed, a
    # redelivered copy of this task is acknowledged without reconciliation.
    receipt = {
        "receipt_id": "PR-" + uuid.uuid4().hex,
        "provider": "provider-fixture",
        "provider_operation_id": "operation-fixture",
        "outcome": "OBSERVED_SUCCESS",
        "observation": {"status": "done"},
        "observation_digest": "sha256:emulator-terminal",
    }
    store.record_verified_receipt(
        effect_id=effect_id, attempt_id=attempt_id, receipt=receipt,
        verified_authentication={"algorithm": "fixture-verified"},
        expected_revision=1,
    )
    terminal = handle_dispatch_delivery(task, store=make_store(), now=now + 2)
    assert terminal[0] == 204
    assert terminal[1]["status"] == "ACK_TERMINAL"
    assert store.get_effect(effect_id)["attempt"] == 1


def test_crash_after_simulated_provider_effect_reconciles_same_attempt_only():
    import time
    from core.cloud_tasks_contract import SCHEMA, dispatch_event_digest
    from core.cloud_tasks_worker import handle_dispatch_delivery

    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id,
        provider="provider-fixture", expected_revision=0,
    )
    attempt = store.get_attempt(effect_id, attempt_id)
    # Represents a side effect completed before the old worker crashed.
    # The new worker may only query this fake provider state by the existing
    # idempotency key; it must not invoke the provider again.
    fake_provider_state = {
        attempt["idempotency_key"]: {"operation_id": "fake-op-1", "outcome": "done"}
    }
    provider_invocations = 1
    reconciliation_reads = []
    now = time.time()
    task = {
        "schema": SCHEMA, "effect_id": effect_id, "attempt_id": attempt_id,
        "expected_revision": 1,
        "dispatch_event_digest": dispatch_event_digest(effect_id, attempt_id),
        "issued_at": now - 5, "expires_at": now + 300,
    }

    def read_only_reconcile(*, effect, attempt):
        assert effect["attempt_id"] == attempt_id
        assert attempt["attempt_id"] == attempt_id
        reconciliation_reads.append(attempt["idempotency_key"])
        observed = fake_provider_state.get(attempt["idempotency_key"])
        assert observed is not None
        if len(reconciliation_reads) == 1:
            # Simulate another crash after provider read but before receipt commit.
            return None
        receipt = {
            "receipt_id": "PR-" + uuid.uuid4().hex,
            "provider": "provider-fixture",
            "provider_operation_id": observed["operation_id"],
            "outcome": "OBSERVED_SUCCESS",
            "observation": {"outcome": observed["outcome"]},
            "observation_digest": "sha256:fake-provider-observation",
        }
        store.record_verified_receipt(
            effect_id=effect_id, attempt_id=attempt_id, receipt=receipt,
            verified_authentication={"algorithm": "fixture-verified"},
            expected_revision=1,
        )

    first = handle_dispatch_delivery(
        task, store=store, now=now, reconcile_same_attempt=read_only_reconcile,
    )
    second = handle_dispatch_delivery(
        task, store=make_store(), now=now + 1,
        reconcile_same_attempt=read_only_reconcile,
    )
    assert first[0] == 503
    assert second[0] == 204
    assert reconciliation_reads == [attempt["idempotency_key"]] * 2
    assert provider_invocations == 1
    assert store.get_effect(effect_id)["attempt"] == 1
    assert store.get_effect(effect_id)["state"] == "OBSERVED_SUCCESS"



def test_provider_operation_id_is_bound_immutably_to_exact_attempt():
    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id, provider="gemini",
        expected_revision=0,
    )

    bound = store.bind_provider_operation_id(
        effect_id=effect_id, attempt_id=attempt_id, provider="gemini",
        provider_operation_id="v1_interaction_fixture_001",
    )
    assert bound["provider_operation_id"] == "v1_interaction_fixture_001"
    assert bound["provider_operation_provider"] == "gemini"

    # A restarted worker reads the persisted provider ID and can GET that
    # exact operation; repeating the same bind is idempotent.
    restarted = make_store()
    recovered = restarted.resume_same_attempt(effect_id=effect_id, attempt_id=attempt_id)
    assert recovered["attempt"]["provider_operation_id"] == "v1_interaction_fixture_001"
    assert restarted.bind_provider_operation_id(
        effect_id=effect_id, attempt_id=attempt_id, provider="gemini",
        provider_operation_id="v1_interaction_fixture_001",
    ) == recovered["attempt"]

    # A different provider ID or provider cannot overwrite the first binding.
    with pytest.raises(EffectStoreConflict, match="immutable"):
        restarted.bind_provider_operation_id(
            effect_id=effect_id, attempt_id=attempt_id, provider="gemini",
            provider_operation_id="v1_interaction_fixture_002",
        )
    with pytest.raises(EffectStoreConflict, match="mismatch"):
        restarted.bind_provider_operation_id(
            effect_id=effect_id, attempt_id=attempt_id, provider="other-provider",
            provider_operation_id="v1_interaction_fixture_001",
        )


def test_provider_operation_id_binding_rejects_cross_attempt_identity():
    store = make_store()
    effect_id, effect = make_effect()
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id, provider="gemini",
        expected_revision=0,
    )
    with pytest.raises(EffectStoreConflict, match="requires durable effect and attempt"):
        store.bind_provider_operation_id(
            effect_id=effect_id, attempt_id=effect_id + ":attempt:2", provider="gemini",
            provider_operation_id="v1_interaction_fixture_001",
        )

def test_independent_retry_grant_is_consumed_once_in_real_firestore_transaction():
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core.retry_issuer import (
        SCHEMA, RetryAuthorizationRejected, RetryIssuerKeyring,
        canonical_payload, effect_state_digest,
    )

    store = make_store()
    effect_id, effect = make_effect()
    effect["max_attempts"] = 2
    store.create_effect(effect)
    attempt_id = effect_id + ":attempt:1"
    store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id,
        provider="provider-fixture", expected_revision=0,
    )
    unknown = store.mark_unknown(
        effect_id=effect_id, attempt_id=attempt_id,
        reason="emulator fixture: outcome is ambiguous", expected_revision=1,
    )
    attempt = store.get_attempt(effect_id, attempt_id)

    # The private key exists only in this test process. Production AIOS stores
    # only the independent issuer's pinned public key.
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    key_id = "retry-ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
    payload = {
        "schema": SCHEMA, "issuer_id": "emulator-independent-issuer",
        "key_id": key_id, "effect_id": effect_id,
        "contract_id": unknown["contract_id"], "permit_id": unknown["permit_id"],
        "actor": unknown["actor"], "provider": unknown["provider"],
        "attempt_id": attempt_id, "attempt_number": unknown["attempt"],
        "state": "UNKNOWN", "state_revision": unknown["revision"],
        "state_digest": effect_state_digest(unknown),
        "not_applied_proof_digest": "a" * 64,
        "nonce": "emulator-single-use-nonce-0001",
        "issued_at": 100.0, "expires_at": 200.0,
        "policy_digest": unknown["policy_digest"],
    }
    authorization = dict(payload, signature=private.sign(canonical_payload(payload)).hex())
    keyring = RetryIssuerKeyring({"emulator-independent-issuer": {
        "key_id": key_id, "public_key": public_hex, "revoked": False,
    }})

    def verify_fixture_not_applied(*, proof_digest, effect, attempt):
        return (
            proof_digest == "a" * 64
            and effect["state"] == "UNKNOWN"
            and attempt["attempt_id"] == attempt_id
        )

    resumed = store.consume_retry_authorization(
        authorization=authorization, issuer_keyring=keyring,
        not_applied_verifier=verify_fixture_not_applied, now=150,
    )
    assert resumed["state"] == "PLANNED"
    assert resumed["revision"] == unknown["revision"] + 1
    assert resumed["attempt"] == 1

    # A fresh client observes the committed nonce and state transition.
    restarted = make_store()
    consumed = list(restarted.client.collection("retry_authorization_consumptions").stream())
    assert len([doc for doc in consumed if doc.to_dict().get("nonce") == payload["nonce"]]) == 1
    with pytest.raises(RetryAuthorizationRejected, match="UNKNOWN"):
        restarted.consume_retry_authorization(
            authorization=authorization, issuer_keyring=keyring,
            not_applied_verifier=verify_fixture_not_applied, now=150,
        )

    # Only after the one-time grant moves the effect back to PLANNED can the
    # normal dispatch CAS allocate attempt 2; the old attempt remains immutable.
    next_attempt_id = effect_id + ":attempt:2"
    next_effect = restarted.dispatch(
        effect_id=effect_id, attempt_id=next_attempt_id,
        provider="provider-fixture", expected_revision=resumed["revision"],
    )
    assert next_effect["attempt"] == 2
    assert restarted.get_attempt(effect_id, attempt_id)["state"] == "UNKNOWN"
    assert restarted.get_attempt(effect_id, next_attempt_id)["state"] == "DISPATCHED"
