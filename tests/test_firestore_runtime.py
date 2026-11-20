from copy import deepcopy

import pytest

from core.durable_runtime import RuntimeSubmission
from core.firestore_runtime import FirestoreDurableRuntime, LedgerConflict


class Snapshot:
    def __init__(self, data):
        self.exists = data is not None
        self._data = deepcopy(data)

    def to_dict(self):
        return deepcopy(self._data)


class Document:
    def __init__(self, client, path):
        self.client = client
        self.path = path

    def collection(self, name):
        return Collection(self.client, f"{self.path}/{name}")

    def get(self, transaction=None):
        return Snapshot(self.client.data.get(self.path))

    def _write(self, value, merge=False, create=False):
        if create and self.path in self.client.data:
            raise RuntimeError("already exists")
        if merge and self.path in self.client.data:
            updated = deepcopy(self.client.data[self.path])
            updated.update(deepcopy(value))
            self.client.data[self.path] = updated
        else:
            self.client.data[self.path] = deepcopy(value)


class Collection:
    def __init__(self, client, path):
        self.client = client
        self.path = path

    def document(self, document_id):
        return Document(self.client, f"{self.path}/{document_id}")


class Transaction:
    def set(self, ref, value, merge=False):
        ref._write(value, merge=merge)

    def create(self, ref, value):
        ref._write(value, create=True)


class FakeClient:
    project = "aios-cloud-runtime-381714"

    def __init__(self):
        self.data = {}

    def collection(self, name):
        return Collection(self, name)


def runner(client, callback):
    return callback(Transaction())


def make_effect():
    return {
        "effect_id": "EF-test-001",
        "contract_id": "CT-test",
        "permit_id": "PM-test",
        "actor": "test-actor",
        "effect_type": "external_effect",
        "provider": "test-provider",
        "policy_digest": "sha256:test-policy",
        "state": "DISPATCHED",
        "attempt": 1,
    }


def make_runtime(client=None):
    client = client or FakeClient()
    return FirestoreDurableRuntime(
        client,
        project_id=client.project,
        transaction_runner=runner,
    ), client


def test_submit_persists_effect_attempt_and_append_only_event():
    runtime, client = make_runtime()
    effect = make_effect()
    result = runtime.submit(effect=effect, attempt_id="EF-test-001:attempt:1")

    assert result == RuntimeSubmission(
        effect_id="EF-test-001",
        attempt_id="EF-test-001:attempt:1",
        provider="test-provider",
    )
    assert len(client.data) == 3
    effect_record = client.data["effects/EF-test-001"]
    assert effect_record["state"] == "DISPATCHED"
    assert effect_record["current_attempt_id"] == "EF-test-001:attempt:1"
    attempt_record = next(value for key, value in client.data.items() if "/attempts/" in key)
    assert attempt_record["idempotency_key"].startswith("aios-")
    assert attempt_record["state"] == "DISPATCHED"
    assert any("/events/" in key for key in client.data)


def test_submit_is_idempotent_for_identical_effect_and_attempt():
    runtime, client = make_runtime()
    effect = make_effect()
    first = runtime.submit(effect=effect, attempt_id="EF-test-001:attempt:1")
    second = runtime.submit(effect=effect, attempt_id="EF-test-001:attempt:1")

    assert first == second
    assert len(client.data) == 3


def test_submit_rejects_effect_identity_conflict():
    runtime, _client = make_runtime()
    effect = make_effect()
    runtime.submit(effect=effect, attempt_id="EF-test-001:attempt:1")

    conflicting = dict(effect, permit_id="PM-other")
    with pytest.raises(LedgerConflict, match="effect identity conflict"):
        runtime.submit(effect=conflicting, attempt_id="EF-test-001:attempt:1")


def test_resume_requires_existing_exact_attempt():
    runtime, _client = make_runtime()
    effect = make_effect()
    attempt_id = "EF-test-001:attempt:1"
    runtime.submit(effect=effect, attempt_id=attempt_id)

    assert runtime.resume(effect=effect, attempt_id=attempt_id).attempt_id == attempt_id

    with pytest.raises(LedgerConflict, match="missing"):
        runtime.resume(effect=effect, attempt_id="EF-test-001:attempt:2")


def test_retry_is_blocked_until_durable_reconciliation_contract_exists():
    runtime, _client = make_runtime()
    effect = make_effect()
    with pytest.raises(LedgerConflict, match="retry is blocked"):
        runtime.retry(effect=effect, attempt_id="EF-test-001:attempt:2", attempt=2)


def test_submission_rejects_non_dispatched_or_wrong_attempt():
    runtime, _client = make_runtime()
    effect = dict(make_effect(), state="PLANNED")
    with pytest.raises(ValueError, match="DISPATCHED"):
        runtime.submit(effect=effect, attempt_id="EF-test-001:attempt:1")

    with pytest.raises(ValueError, match="deterministic"):
        runtime.submit(effect=make_effect(), attempt_id="caller-invented-attempt")
