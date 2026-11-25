import json
import os
import tempfile
import pytest

from core.authority import (authorize, persist_attestation, persist_contract,
                            persist_permit, load_attestation)
from core.capabilities import Capability, CapabilityRegistry
from core.mutation import TransitionError
from core.policy_registry import persist_policy


def make_contract(policy_digest):
    return {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "RESEARCH_BC7", "scope": "research",
        "actor": "bc-controller", "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input", "allowed_effects": ["persist_evidence"],
        "evidence_required": ["is_validation_report"], "max_attempts": 3,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"], "policy_digest": policy_digest,
    }


def setup_authority(td):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "research-fixture"})
    contract = make_contract(policy)
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "AIOS_AUTHORITY")
    return contract, permit


def test_persist_and_reload_attestation():
    with tempfile.TemporaryDirectory() as td:
        c, p = setup_authority(td)
        a = load_attestation(td, p["permit_id"])
        from core.contract import contract_identity
        assert a["contract_id"] == contract_identity(c)
        assert authorize(td, contract_identity(c), p["permit_id"])


def test_authorize_fails_closed_without_trusted_keys(tmp_path, monkeypatch):
    c, p = setup_authority(str(tmp_path))
    monkeypatch.delenv("AIOS_AUTHORITY_TRUSTED_KEYS")
    from core.contract import contract_identity
    with pytest.raises(TransitionError, match="verifier unavailable"):
        authorize(str(tmp_path), contract_identity(c), p["permit_id"])


def test_authorize_rejects_tampered_issuer_attestation(tmp_path):
    c, p = setup_authority(str(tmp_path))
    path = tmp_path / "authority" / "attestations" / (p["permit_id"] + ".json")
    attestation = json.loads(path.read_text())
    attestation["signature"] = "0" * 128
    path.write_text(json.dumps(attestation))
    from core.contract import contract_identity
    with pytest.raises(TransitionError, match="attestation rejected"):
        authorize(str(tmp_path), contract_identity(c), p["permit_id"])


def test_persist_attestation_rejects_non_signer(tmp_path):
    c, p = setup_authority(str(tmp_path))
    with pytest.raises(TransitionError, match="AuthoritySigner"):
        persist_attestation(str(tmp_path), c, p, "an-hmac-secret-string")
