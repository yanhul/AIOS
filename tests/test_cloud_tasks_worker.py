import pytest

from core.cloud_tasks_contract import (
    SCHEMA, dispatch_event_digest,
)
from core.cloud_tasks_worker import handle_dispatch_delivery


class Store:
    def __init__(self, state="DISPATCHED"):
        self.effect = {
            "effect_id": "EF-http-1", "attempt_id": "EF-http-1:attempt:1",
            "revision": 1, "state": state, "provider": "provider-fixture",
        }
        self.attempt = {
            "effect_id": "EF-http-1", "attempt_id": "EF-http-1:attempt:1",
            "state": state, "provider": "provider-fixture",
        }
        self.resumed = 0

    def get_effect(self, effect_id):
        return dict(self.effect) if effect_id == self.effect["effect_id"] else None

    def get_attempt(self, effect_id, attempt_id):
        return dict(self.attempt) if attempt_id == self.attempt["attempt_id"] else None

    def resume_same_attempt(self, *, effect_id, attempt_id):
        self.resumed += 1
        return {"effect": dict(self.effect), "attempt": dict(self.attempt)}


def payload():
    return {
        "schema": SCHEMA,
        "effect_id": "EF-http-1",
        "attempt_id": "EF-http-1:attempt:1",
        "expected_revision": 1,
        "dispatch_event_digest": dispatch_event_digest("EF-http-1", "EF-http-1:attempt:1"),
        "issued_at": 100.0,
        "expires_at": 200.0,
    }


def test_terminal_redelivery_is_acknowledged_without_reconciliation():
    store = Store("OBSERVED_SUCCESS")
    status, body = handle_dispatch_delivery(payload(), store=store, now=150)
    assert status == 204
    assert body["status"] == "ACK_TERMINAL"
    assert store.resumed == 0


def test_unresolved_delivery_fails_closed_without_reexecuting_provider():
    store = Store()
    status, body = handle_dispatch_delivery(payload(), store=store, now=150)
    assert status == 503
    assert body["status"] == "RECONCILIATION_ADAPTER_UNAVAILABLE"
    assert store.resumed == 1


def test_injected_reconciler_receives_only_the_existing_attempt():
    store = Store()
    seen = []

    def reconcile_same_attempt(*, effect, attempt):
        seen.append((effect["attempt_id"], attempt["attempt_id"]))
        # Deliberately leaves state unresolved; endpoint must ask Cloud Tasks
        # to retry this same task, not create a new attempt.
        return None

    status, body = handle_dispatch_delivery(
        payload(), store=store, now=150,
        reconcile_same_attempt=reconcile_same_attempt,
    )
    assert status == 503
    assert body["status"] == "SAME_ATTEMPT_STILL_UNRESOLVED"
    assert seen == [("EF-http-1:attempt:1", "EF-http-1:attempt:1")]


def test_mismatched_firestore_identity_is_rejected():
    store = Store()
    store.effect["attempt_id"] = "EF-http-1:attempt:2"
    status, body = handle_dispatch_delivery(payload(), store=store, now=150)
    assert status == 400
    assert body["status"] == "REJECTED"
