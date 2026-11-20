from copy import deepcopy

import pytest

from core.firestore_effect_store import (
    EffectStoreConflict,
    FirestoreEffectStore,
)


class Snapshot:
    def __init__(self, value):
        self.exists = value is not None
        self.value = deepcopy(value)

    def to_dict(self):
        return deepcopy(self.value)


class Ref:
    def __init__(self, client, path):
        self.client, self.path = client, path

    def collection(self, name):
        return Collection(self.client, self.path + "/" + name)

    def get(self, transaction=None):
        source = transaction.data if transaction is not None else self.client.data
        return Snapshot(source.get(self.path))


class Collection:
    def __init__(self, client, path):
        self.client, self.path = client, path

    def document(self, key):
        return Ref(self.client, self.path + "/" + key)


class Transaction:
    def __init__(self, client):
        self.client = client
        self.data = deepcopy(client.data)
        self.writes = []

    def create(self, ref, value):
        if ref.path in self.data:
            raise RuntimeError("already exists")
        self.data[ref.path] = deepcopy(value)

    def set(self, ref, value):
        self.data[ref.path] = deepcopy(value)


class FakeClient:
    project = "aios-cloud-runtime-381714"

    def __init__(self):
        self.data = {}

    def collection(self, name):
        return Collection(self, name)


def runner(client, callback):
    tx = Transaction(client)
    result = callback(tx)
    client.data = tx.data
    return result


def make_store():
    client = FakeClient()
    return FirestoreEffectStore(client, project_id=client.project,
                                transaction_runner=runner), client


def planned_effect():
    return {
        "effect_id": "EF-crash-001",
        "contract_id": "CT-1",
        "permit_id": "PM-1",
        "actor": "worker",
        "effect_type": "external_effect",
        "policy_digest": "sha256:policy",
        "max_attempts": 1,
        "state": "PLANNED",
    }


def dispatch(store):
    store.create_effect(planned_effect())
    return store.dispatch(effect_id="EF-crash-001",
                          attempt_id="EF-crash-001:attempt:1",
                          provider="provider-a", expected_revision=0)


def test_effect_is_created_durably_before_dispatch():
    store, client = make_store()
    created = store.create_effect(planned_effect())
    assert created["state"] == "PLANNED"
    assert client.data["effects/EF-crash-001"]["revision"] == 0


def test_dispatch_intent_and_idempotency_key_survive_worker_crash():
    store, _client = make_store()
    dispatched = dispatch(store)

    # Simulate process death immediately after the transaction commits and
    # before any provider call or acknowledgement.
    recovered = store.resume_same_attempt(
        effect_id="EF-crash-001", attempt_id="EF-crash-001:attempt:1"
    )
    assert recovered["effect"]["state"] == "DISPATCHED"
    assert recovered["attempt"]["idempotency_key"] == (
        "aios-" + __import__("hashlib").sha256(
            b"EF-crash-001\0EF-crash-001:attempt:1"
        ).hexdigest()
    )
    assert recovered["effect"]["attempt_id"] == dispatched["attempt_id"]


def test_crash_after_provider_side_effect_before_receipt_reuses_same_attempt():
    store, client = make_store()
    dispatch(store)

    # Provider may have acted, but the worker died before receipt persistence.
    # The ledger remains DISPATCHED and recovery may only inspect same attempt.
    recovered = store.resume_same_attempt(
        effect_id="EF-crash-001", attempt_id="EF-crash-001:attempt:1"
    )
    assert recovered["effect"]["state"] == "DISPATCHED"
    assert len([k for k in client.data if "/attempts/" in k]) == 1
    assert recovered["attempt"]["attempt_number"] == 1


def test_unknown_is_durable_and_never_allocates_next_attempt():
    store, client = make_store()
    dispatch(store)
    unknown = store.mark_unknown(effect_id="EF-crash-001",
                                 attempt_id="EF-crash-001:attempt:1",
                                 reason="provider outcome ambiguous",
                                 expected_revision=1)
    assert unknown["state"] == "UNKNOWN"
    with pytest.raises(EffectStoreConflict):
        store.dispatch(effect_id="EF-crash-001",
                       attempt_id="EF-crash-001:attempt:2",
                       provider="provider-a", expected_revision=2)
    assert len([k for k in client.data if "/attempts/" in k]) == 1


def test_receipt_and_terminal_state_commit_atomically():
    store, client = make_store()
    dispatch(store)
    receipt = {
        "receipt_id": "PR-0123456789abcdef0123456789abcdef",
        "provider": "provider-a",
        "provider_operation_id": "op-123",
        "outcome": "OBSERVED_SUCCESS",
        "observation": {"status": "done"},
        "observation_digest": "sha256:observation",
    }
    terminal = store.record_verified_receipt(
        effect_id="EF-crash-001",
        attempt_id="EF-crash-001:attempt:1",
        receipt=receipt,
        verified_authentication={"algorithm": "Ed25519", "key_id": "provider-key-1"},
        expected_revision=1,
    )
    assert terminal["state"] == "OBSERVED_SUCCESS"
    assert terminal["revision"] == 2
    assert client.data["provider_receipts/" + receipt["receipt_id"]]["attempt_id"] == (
        "EF-crash-001:attempt:1"
    )
    attempt = store.get_attempt("EF-crash-001", "EF-crash-001:attempt:1")
    assert attempt["state"] == "OBSERVED_SUCCESS"


def test_stale_revision_cannot_overwrite_terminal_effect():
    store, _client = make_store()
    dispatch(store)
    receipt = {
        "receipt_id": "PR-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "provider": "provider-a",
        "provider_operation_id": "op-1",
        "outcome": "OBSERVED_SUCCESS",
        "observation": {"ok": True},
        "observation_digest": "sha256:x",
    }
    store.record_verified_receipt(
        effect_id="EF-crash-001", attempt_id="EF-crash-001:attempt:1",
        receipt=receipt, verified_authentication={"algorithm": "Ed25519"},
        expected_revision=1,
    )
    with pytest.raises(EffectStoreConflict):
        store.mark_unknown(effect_id="EF-crash-001",
                           attempt_id="EF-crash-001:attempt:1",
                           reason="late timeout", expected_revision=1)


def test_missing_effect_or_attempt_fails_closed_on_recovery():
    store, _client = make_store()
    with pytest.raises(EffectStoreConflict):
        store.resume_same_attempt(effect_id="missing", attempt_id="missing:attempt:1")

def test_terminal_receipt_commit_is_idempotent_after_acknowledgement_crash():
    store, client = make_store()
    dispatch(store)
    receipt = {
        "receipt_id": "PR-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "provider": "provider-a",
        "provider_operation_id": "op-ack",
        "outcome": "OBSERVED_SUCCESS",
        "observation": {"ok": True},
        "observation_digest": "sha256:ack",
    }
    kwargs = dict(
        effect_id="EF-crash-001",
        attempt_id="EF-crash-001:attempt:1",
        receipt=receipt,
        verified_authentication={"algorithm": "Ed25519", "key_id": "provider-key-1"},
        expected_revision=1,
    )
    first = store.record_verified_receipt(**kwargs)
    # Simulate retry after the process died after Firestore commit but before
    # the caller received its acknowledgement.
    second = store.record_verified_receipt(**kwargs)
    assert second == first
    assert second["revision"] == 2
    assert len([key for key in client.data if key.startswith("provider_receipts/")]) == 1


def test_failed_transaction_does_not_partially_commit():
    store, client = make_store()
    store.create_effect(planned_effect())
    before = deepcopy(client.data)
    with pytest.raises(EffectStoreConflict):
        store.dispatch(effect_id="EF-crash-001",
                       attempt_id="wrong-attempt",
                       provider="provider-a", expected_revision=0)
    assert client.data == before



def test_retry_authorization_nonce_consumed_once_and_returns_effect_to_planned():
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core.retry_issuer import SCHEMA, RetryIssuerKeyring, canonical_payload, effect_state_digest

    store, client = make_store()
    store.create_effect(dict(planned_effect(), max_attempts=2))
    store.dispatch(effect_id="EF-crash-001", attempt_id="EF-crash-001:attempt:1",
                   provider="provider-a", expected_revision=0)
    unknown = store.mark_unknown(effect_id="EF-crash-001",
                                 attempt_id="EF-crash-001:attempt:1",
                                 reason="ambiguous provider outcome", expected_revision=1)
    attempt = store.get_attempt("EF-crash-001", "EF-crash-001:attempt:1")

    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    key_id = "retry-ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
    payload = {
        "schema": SCHEMA, "issuer_id": "independent", "key_id": key_id,
        "effect_id": unknown["effect_id"], "contract_id": unknown["contract_id"],
        "permit_id": unknown["permit_id"], "actor": unknown["actor"],
        "provider": unknown["provider"], "attempt_id": unknown["attempt_id"],
        "attempt_number": unknown["attempt"], "state": "UNKNOWN",
        "state_revision": unknown["revision"], "state_digest": effect_state_digest(unknown),
        "not_applied_proof_digest": "c" * 64, "nonce": "single-use-nonce-0001",
        "issued_at": 100.0, "expires_at": 200.0, "policy_digest": unknown["policy_digest"],
    }
    authorization = dict(payload, signature=private.sign(canonical_payload(payload)).hex())
    keyring = RetryIssuerKeyring({"independent": {
        "key_id": key_id, "public_key": public_hex, "revoked": False,
    }})
    verify_proof = lambda **kwargs: kwargs["proof_digest"] == "c" * 64

    resumed = store.consume_retry_authorization(
        authorization=authorization, issuer_keyring=keyring,
        not_applied_verifier=verify_proof, now=150,
    )
    assert resumed["state"] == "PLANNED"
    assert resumed["revision"] == unknown["revision"] + 1
    assert resumed["attempt"] == 1
    assert len([key for key in client.data if key.startswith("retry_authorization_consumptions/")]) == 1

    with pytest.raises(EffectStoreConflict, match="nonce already consumed"):
        store.consume_retry_authorization(
            authorization=authorization, issuer_keyring=keyring,
            not_applied_verifier=verify_proof, now=150,
        )


def test_retry_authorization_without_verified_not_applied_proof_is_denied():
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core.retry_issuer import SCHEMA, RetryIssuerKeyring, canonical_payload, effect_state_digest

    store, _client = make_store()
    store.create_effect(dict(planned_effect(), max_attempts=2))
    store.dispatch(effect_id="EF-crash-001", attempt_id="EF-crash-001:attempt:1",
                   provider="provider-a", expected_revision=0)
    unknown = store.mark_unknown(effect_id="EF-crash-001",
                                 attempt_id="EF-crash-001:attempt:1",
                                 reason="ambiguous", expected_revision=1)
    attempt = store.get_attempt("EF-crash-001", "EF-crash-001:attempt:1")
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    key_id = "retry-ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
    payload = {
        "schema": SCHEMA, "issuer_id": "independent", "key_id": key_id,
        "effect_id": unknown["effect_id"], "contract_id": unknown["contract_id"],
        "permit_id": unknown["permit_id"], "actor": unknown["actor"],
        "provider": unknown["provider"], "attempt_id": unknown["attempt_id"],
        "attempt_number": unknown["attempt"], "state": "UNKNOWN",
        "state_revision": unknown["revision"], "state_digest": effect_state_digest(unknown),
        "not_applied_proof_digest": "d" * 64, "nonce": "single-use-nonce-0002",
        "issued_at": 100.0, "expires_at": 200.0, "policy_digest": unknown["policy_digest"],
    }
    authorization = dict(payload, signature=private.sign(canonical_payload(payload)).hex())
    keyring = RetryIssuerKeyring({"independent": {
        "key_id": key_id, "public_key": public_hex, "revoked": False,
    }})
    with pytest.raises(EffectStoreConflict, match="rejected"):
        store.consume_retry_authorization(
            authorization=authorization, issuer_keyring=keyring,
            not_applied_verifier=lambda **_kwargs: False, now=150,
        )
