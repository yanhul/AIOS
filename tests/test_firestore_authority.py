"""Fail-closed tests for immutable Firestore authority records."""
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.firestore_authority import (
    AuthorityStoreError, FirestoreAuthorityStore, record_digest,
)
from core.mutation import canonical_json


class Snapshot:
    def __init__(self, data):
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return self._data


class Ref:
    def __init__(self, collection, key):
        self.collection, self.key = collection, key

    def get(self):
        return Snapshot(self.collection.data.get(self.key))

    def create(self, payload):
        if self.key in self.collection.data:
            raise RuntimeError("already exists")
        self.collection.data[self.key] = payload


class Collection:
    def __init__(self):
        self.data = {}

    def document(self, key):
        return Ref(self, key)


class Client:
    project = "unit-test-project"

    def __init__(self):
        self.collections = {}

    def collection(self, name):
        return self.collections.setdefault(name, Collection())


def fixture():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    key_id = "ed25519:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()[:32]
    anchor = {key_id: {"public_key": public, "principal": "authority-prod", "revoked": False}}
    record = {"record_type": "EXECUTION_CONTRACT", "contract_id": "CT-001", "scope": ["staging"]}
    issued, expires = 100, 500
    signature = {
        "type": "AIOS_AUTHORITY_SIGNATURE", "algorithm": "Ed25519",
        "key_id": key_id, "principal": "authority-prod",
        "record_digest": record_digest(record), "issued_at": issued, "expires_at": expires,
    }
    signature["signature"] = private.sign(canonical_json(signature).encode()).hex()
    return Client(), anchor, record, signature


def test_create_and_read_immutable_signed_authority_record():
    client, anchor, record, signature = fixture()
    store = FirestoreAuthorityStore(client, project_id="unit-test-project")
    digest = store.put_immutable(record_type="contract", record_id="CT-001", record=record,
                                 signature=signature, trust_anchor=anchor, now=200)
    assert digest == record_digest(record)
    assert store.get_verified(digest, trust_anchor=anchor, expected_type="contract", now=200) == record
    assert store.put_immutable(record_type="contract", record_id="CT-001", record=record,
                               signature=signature, trust_anchor=anchor, now=200) == digest


def test_rejects_tampered_record_and_unpinned_or_revoked_issuer():
    client, anchor, record, signature = fixture()
    store = FirestoreAuthorityStore(client, project_id="unit-test-project")
    with pytest.raises(AuthorityStoreError, match="does not bind"):
        store.put_immutable(record_type="contract", record_id="CT-001",
                            record={**record, "scope": ["production"]},
                            signature=signature, trust_anchor=anchor, now=200)
    revoked = {k: {**v, "revoked": True} for k, v in anchor.items()}
    with pytest.raises(AuthorityStoreError, match="revoked"):
        store.put_immutable(record_type="contract", record_id="CT-001", record=record,
                            signature=signature, trust_anchor=revoked, now=200)


def test_rejects_expired_or_modified_signature_and_project_mismatch():
    client, anchor, record, signature = fixture()
    store = FirestoreAuthorityStore(client, project_id="unit-test-project")
    with pytest.raises(AuthorityStoreError, match="not currently valid"):
        store.put_immutable(record_type="contract", record_id="CT-001", record=record,
                            signature=signature, trust_anchor=anchor, now=500)
    modified = {**signature, "principal": "attacker"}
    with pytest.raises(AuthorityStoreError):
        store.put_immutable(record_type="contract", record_id="CT-001", record=record,
                            signature=modified, trust_anchor=anchor, now=200)
    with pytest.raises(AuthorityStoreError, match="project mismatch"):
        FirestoreAuthorityStore(client, project_id="wrong-project")


def test_read_rejects_tampered_stored_document():
    client, anchor, record, signature = fixture()
    store = FirestoreAuthorityStore(client, project_id="unit-test-project")
    digest = store.put_immutable(record_type="contract", record_id="CT-001", record=record,
                                 signature=signature, trust_anchor=anchor, now=200)
    client.collection("aios_authority_records").data[digest]["record"]["scope"] = ["production"]
    with pytest.raises(AuthorityStoreError, match="content hash"):
        store.get_verified(digest, trust_anchor=anchor, now=200)
