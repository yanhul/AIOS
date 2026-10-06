# AIOS-CONTRACT: CONTINUE_CONTRACT schema and legal-action boundary
# AIOS-REGRESSION: Prevent model drift outside the durable active phase
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers deterministic contract projection and fail-closed validation
# AIOS-BASELINE: Tests target the existing durable-loop contract baseline

from core.continue_contract import (
    build_continue_contract,
    validate_continue_action,
    validate_continue_contract,
)

def _state():
    return {
        "project": "yanhul/temp",
        "design": "QI9-2605-A01",
        "authority": "AIOS_CONTROL_PLANE",
        "pipeline": {
            "schematic": "VERIFIED",
            "placement": "BLOCKED_BY_SCHEMATIC",
            "routing": "BLOCKED_BY_PLACEMENT",
        },
        "active_phase": "SCHEMATIC",
        "active_commit": "abc123",
        "latest_run": "37169016057",
        "latest_receipt": "receipt-2605-schematic",
        "active_blockers": [{"id": "HCPL-0600", "status": "BLOCKED"}],
        "next_legal_actions": ["inspect_receipt", "inspect_source", "patch", "commit", "wait_ci"],
        "forbidden_actions": ["placement", "routing", "claim_pass"],
    }

def test_continue_contract_is_deterministic_and_self_bound():
    contract = build_continue_contract(_state())
    assert contract["contract_type"] == "CONTINUE_CONTRACT"
    assert contract["active_phase"] == "SCHEMATIC"
    assert contract["pipeline"]["placement"] == "BLOCKED_BY_SCHEMATIC"
    assert validate_continue_contract(contract) is True
    assert contract["contract_id"].startswith("CC-")

def test_continue_contract_rejects_state_that_grants_conflicting_actions():
    state = _state()
    state["next_legal_actions"] = ["patch", "placement"]
    state["forbidden_actions"] = ["placement"]
    try:
        build_continue_contract(state)
    except ValueError as exc:
        assert "both legal and forbidden" in str(exc)
    else:
        raise AssertionError("expected conflict rejection")

def test_model_cannot_leave_the_active_phase():
    contract = build_continue_contract(_state())
    assert validate_continue_action(contract, "patch") is True
    for action in ("placement", "routing", "claim_pass"):
        try:
            validate_continue_action(contract, action)
        except PermissionError:
            pass
        else:
            raise AssertionError(f"{action} must be rejected")

def test_missing_legal_actions_fail_closed():
    state = _state()
    state.pop("next_legal_actions")
    try:
        build_continue_contract(state)
    except ValueError as exc:
        assert "next_legal_actions" in str(exc)
    else:
        raise AssertionError("expected fail-closed validation")
