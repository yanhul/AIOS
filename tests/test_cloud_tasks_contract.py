import copy

import pytest

from core.cloud_tasks_contract import (
    SCHEMA, DispatchTaskRejected, deterministic_task_name,
    dispatch_event_digest, validate_dispatch_task,
)


def fixture(state="DISPATCHED", attempt_state="DISPATCHED"):
    effect_id = "EF-task-001"
    attempt_id = effect_id + ":attempt:1"
    return (
        {
            "schema": SCHEMA,
            "effect_id": effect_id,
            "attempt_id": attempt_id,
            "expected_revision": 1,
            "dispatch_event_digest": dispatch_event_digest(effect_id, attempt_id),
            "issued_at": 100.0,
            "expires_at": 200.0,
        },
        {
            "effect_id": effect_id, "attempt_id": attempt_id,
            "revision": 1, "state": state,
        },
        {
            "effect_id": effect_id, "attempt_id": attempt_id,
            "state": attempt_state,
        },
    )


def test_task_name_is_deterministic_and_bound_to_effect_and_attempt():
    first = deterministic_task_name("EF-1", "EF-1:attempt:1")
    assert first == deterministic_task_name("EF-1", "EF-1:attempt:1")
    assert first != deterministic_task_name("EF-1", "EF-1:attempt:2")
    assert first.startswith("aios-")


def test_valid_delivery_only_requests_same_attempt_reconciliation():
    payload, effect, attempt = fixture()
    assert validate_dispatch_task(payload, effect=effect, attempt=attempt, now=150) == (
        "RECONCILE_SAME_ATTEMPT"
    )


def test_terminal_redelivery_is_ack_only():
    payload, effect, attempt = fixture("OBSERVED_SUCCESS", "OBSERVED_SUCCESS")
    assert validate_dispatch_task(payload, effect=effect, attempt=attempt, now=150) == "ACK_TERMINAL"


@pytest.mark.parametrize("change", [
    lambda p: p.update(effect_id="EF-other"),
    lambda p: p.update(attempt_id="EF-task-001:attempt:2"),
    lambda p: p.update(expected_revision=2),
    lambda p: p.update(dispatch_event_digest="0" * 64),
    lambda p: p.update(expires_at=99),
    lambda p: p.update(issued_at=201),
    lambda p: p.update(extra="authority"),
])
def test_malformed_stale_or_expired_task_is_rejected(change):
    payload, effect, attempt = fixture()
    change(payload)
    with pytest.raises(DispatchTaskRejected):
        validate_dispatch_task(payload, effect=effect, attempt=attempt, now=150)


def test_firestore_identity_mismatch_is_rejected():
    payload, effect, attempt = fixture()
    effect["attempt_id"] = "EF-task-001:attempt:9"
    with pytest.raises(DispatchTaskRejected, match="attempt binding"):
        validate_dispatch_task(payload, effect=effect, attempt=attempt, now=150)


def test_unknown_delivery_never_authorizes_new_attempt_execution():
    payload, effect, attempt = fixture("UNKNOWN", "UNKNOWN")
    assert validate_dispatch_task(payload, effect=effect, attempt=attempt, now=150) == (
        "RECONCILE_SAME_ATTEMPT"
    )
