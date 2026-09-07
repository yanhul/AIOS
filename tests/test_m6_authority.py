import pytest

from core.authority import (
    authorize,
    load_contract,
    load_permit,
    persist_contract,
    persist_permit,
)
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.policy_registry import persist_policy


def _policy(name="v1"):
    return {"policy_type": "GOVERNING_POLICY", "name": name, "terminal_states": ["SUCCESS", "FAILURE"]}


def _contract(tmp_path, policy=None):
    if policy is None:
        policy = persist_policy(str(tmp_path), _policy("v1"))
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "TASK-1",
        "scope": "repo:AIOS",
        "actor": "agent-1",
        "capabilities": ["read@1", "write@1"],
        "input_digest": "in-1",
        "allowed_effects": ["state-write"],
        "evidence_required": ["verification"],
        "max_attempts": 3,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": policy,
    }


def _seed_registry(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("read", "1", "test", "test", status="ACTIVE"))
    registry.register(Capability("write", "1", "test", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")


def test_contract_and_permit_are_durable(tmp_path):
    _seed_registry(tmp_path)
    c = _contract(tmp_path)
    stored = persist_contract(str(tmp_path), c)
    assert stored["contract_id"] == contract_identity(c)
    p = persist_permit(str(tmp_path), c, "governing-authority")
    assert authorize(str(tmp_path), stored["contract_id"], p["permit_id"])
    assert load_contract(str(tmp_path), stored["contract_id"])["task_id"] == "TASK-1"
    assert load_permit(str(tmp_path), p["permit_id"])["contract_id"] == stored["contract_id"]


def test_contract_is_immutable_and_content_addressed(tmp_path):
    _seed_registry(tmp_path)
    c = _contract(tmp_path)
    first = persist_contract(str(tmp_path), c)
    changed = dict(c)
    changed["max_attempts"] = 4
    second = persist_contract(str(tmp_path), changed)
    assert first["contract_id"] != second["contract_id"]
    assert load_contract(str(tmp_path), first["contract_id"])["max_attempts"] == 3
    assert load_contract(str(tmp_path), second["contract_id"])["max_attempts"] == 4


def test_permit_cannot_be_rebound(tmp_path):
    _seed_registry(tmp_path)
    c = _contract(tmp_path)
    p = persist_permit(str(tmp_path), c, "governing-authority")
    other_policy = persist_policy(str(tmp_path), _policy("v2"))
    other = _contract(tmp_path, other_policy)
    persist_contract(str(tmp_path), other)
    from core.contract import verify_permit
    with pytest.raises(ValueError):
        verify_permit(other, p)


def test_replay_is_idempotent(tmp_path):
    _seed_registry(tmp_path)
    c = _contract(tmp_path)
    first = persist_permit(str(tmp_path), c, "governing-authority")
    second = persist_permit(str(tmp_path), c, "governing-authority")
    assert first == second


def test_unknown_capability_cannot_get_authority(tmp_path):
    _seed_registry(tmp_path)
    c = _contract(tmp_path)
    c["capabilities"] = ["read@1", "not-registered@1"]
    with pytest.raises(Exception, match="capability authority rejected contract"):
        persist_contract(str(tmp_path), c)


def test_missing_registry_fails_closed(tmp_path):
    with pytest.raises(Exception, match="capability authority rejected contract"):
        persist_contract(str(tmp_path), _contract(tmp_path))


def test_unknown_policy_digest_cannot_get_authority(tmp_path):
    _seed_registry(tmp_path)
    c = _contract(tmp_path, "sha256:attacker-invented")
    with pytest.raises(Exception, match="policy authority rejected contract"):
        persist_contract(str(tmp_path), c)


def test_tampered_policy_artifact_fails_closed(tmp_path):
    _seed_registry(tmp_path)
    import json, os
    digest = persist_policy(str(tmp_path), _policy())
    path = os.path.join(str(tmp_path), "policies", digest + ".json")
    with open(path, "r", encoding="utf-8") as fh:
        record = json.load(fh)
    record["name"] = "tampered"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    with pytest.raises(Exception, match="policy authority rejected contract"):
        persist_contract(str(tmp_path), _contract(tmp_path, digest))


def test_deprecated_capability_cannot_execute(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("read", "1", "test", "test", status="DEPRECATED"))
    registry.register(Capability("write", "1", "test", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
    c = _contract(tmp_path)
    with pytest.raises(Exception, match="capability authority rejected contract"):
        persist_contract(str(tmp_path), c)
