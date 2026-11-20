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
