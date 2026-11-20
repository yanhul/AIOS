"""Cross-binding and fail-closed tests for Firestore authority resolution."""
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.contract import contract_identity, issue_permit
from core.firestore_authority import FirestoreAuthorityStore, record_digest
from core.firestore_authority_resolver import (
    FirestoreAuthorityResolutionError, FirestoreAuthorityResolver,
)
from core.mutation import canonical_json


class Snapshot:
    def __init__(self, data):
        self.exists, self.data = data is not None, data
    def to_dict(self):
        return self.data


class Ref:
    def __init__(self, collection, key):
        self.collection, self.key = collection, key
    def get(self):
        return Snapshot(self.collection.data.get(self.key))
    def create(self, value):
        if self.key in self.collection.data:
            raise RuntimeError("already exists")
        self.collection.data[self.key] = value


class Collection:
    def __init__(self):
        self.data = {}
    def document(self, key):
        return Ref(self, key)


class Client:
    project = "resolver-test"
    def __init__(self):
        self.collections = {}
    def collection(self, name):
        return self.collections.setdefault(name, Collection())


def signed_fixture():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    key_id = "ed25519:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()[:32]
    anchor = {key_id: {"public_key": public, "principal": "ci-test-issuer", "revoked": False}}
    client = Client()
    store = FirestoreAuthorityStore(client, project_id="resolver-test")

    policy = {"policy_id": "policy-test", "rules": []}
    cap = {"capability_id": "worker", "version": "1.0.0", "status": "ACTIVE"}
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "task-1",
        "scope": "test", "actor": "ci", "capabilities": ["worker@1.0.0"],
        "input_digest": "a" * 64, "allowed_effects": ["external_effect"],
        "evidence_required": ["receipt"], "max_attempts": 1,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": record_digest(policy),
    }
    permit = issue_permit(contract, "ci-test-issuer")
    attestation = {
        "attestation_type": "EXECUTION_PERMIT_ATTESTATION",
        "contract_id": contract_identity(contract), "permit_id": permit["permit_id"],
        "issuer": permit["issuer"], "algorithm": "Ed25519",
    }

    def put(kind, ident, record):
        envelope = {
            "type": "AIOS_AUTHORITY_SIGNATURE", "algorithm": "Ed25519",
            "key_id": key_id, "principal": "ci-test-issuer",
            "record_digest": record_digest(record), "issued_at": 1, "expires_at": 4102444800,
        }
        envelope["signature"] = private.sign(canonical_json(envelope).encode()).hex()
        return store.put_immutable(
            record_type=kind, record_id=ident, record=record, signature=envelope,
            trust_anchor=anchor, now=200,
        )

    digests = {
        "contract": put("EXECUTION_CONTRACT", "contract-1", contract),
        "permit": put("EXECUTION_PERMIT", "permit-1", permit),
        "attestation": put("EXECUTION_PERMIT_ATTESTATION", "attestation-1", attestation),
        "policy": put("POLICY", "policy-1", policy),
        "capability": put("CAPABILITY", "worker-1", cap),
    }
    return FirestoreAuthorityResolver(store, trust_anchor=anchor), digests


def test_resolves_complete_signed_cross_bound_authority_bundle():
    resolver, d = signed_fixture()
    result = resolver.resolve(
        contract_digest=d["contract"], permit_digest=d["permit"],
        attestation_digest=d["attestation"], policy_digest=d["policy"],
        capability_digests={"worker@1.0.0": d["capability"]},
    )
    assert result["authority_backend"] == "firestore-ed25519"
    assert result["capabilities"]["worker@1.0.0"]["status"] == "ACTIVE"


def test_rejects_missing_capability_or_wrong_capability_binding():
    resolver, d = signed_fixture()
    with pytest.raises(FirestoreAuthorityResolutionError, match="capability digest map"):
        resolver.resolve(
            contract_digest=d["contract"], permit_digest=d["permit"],
            attestation_digest=d["attestation"], policy_digest=d["policy"],
            capability_digests={},
        )


def test_rejects_policy_digest_not_bound_by_contract():
    resolver, d = signed_fixture()
    with pytest.raises(FirestoreAuthorityResolutionError, match="policy digest"):
        resolver.resolve(
            contract_digest=d["contract"], permit_digest=d["permit"],
            attestation_digest=d["attestation"], policy_digest="0" * 64,
            capability_digests={"worker@1.0.0": d["capability"]},
        )
