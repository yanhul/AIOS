import pytest

from core.authority import (
    authorize,
    load_contract,
    load_permit,
    persist_contract,
    persist_permit,
)
from core.contract import contract_identity, issue_permit
from core.mutation import TransitionError


def _contract(policy="policy-v1"):
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "TASK-1",
        "scope": "repo:AIOS",
        "actor": "agent-1",
        "capabilities": ["read", "write:aios-state"],
        "input_digest": "in-1",
        "allowed_effects": ["state-write"],
        "evidence_required": ["verification"],
        "max_attempts": 3,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": policy,
    }


def test_contract_and_permit_are_durable(tmp_path):
    c = _contract()
    stored = persist_contract(str(tmp_path), c)
    assert stored["contract_id"] == contract_identity(c)
    p = persist_permit(str(tmp_path), c, "governing-authority")
    assert authorize(str(tmp_path), stored["contract_id"], p["permit_id"])
    assert load_contract(str(tmp_path), stored["contract_id"])["task_id"] == "TASK-1"
    assert load_permit(str(tmp_path), p["permit_id"])["contract_id"] == stored["contract_id"]


def test_contract_is_immutable(tmp_path):
    c = _contract()
    persist_contract(str(tmp_path), c)
    changed = dict(c)
    changed["max_attempts"] = 4
    with pytest.raises(TransitionError):
        persist_contract(str(tmp_path), changed)


def test_permit_cannot_be_rebound(tmp_path):
    c = _contract()
    p = persist_permit(str(tmp_path), c, "governing-authority")
    other = _contract(policy="policy-v2")
    persist_contract(str(tmp_path), other)
    with pytest.raises(ValueError):
        from core.contract import verify_permit
        verify_permit(other, p)


def test_replay_is_idempotent(tmp_path):
    c = _contract()
    first = persist_permit(str(tmp_path), c, "governing-authority")
    second = persist_permit(str(tmp_path), c, "governing-authority")
    assert first == second
