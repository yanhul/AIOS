from core.authority import _canonical_contract
from core.contract import issue_permit, verify_permit


def _contract(**overrides):
    value = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "task-1",
        "scope": "repository:yanhul/AIOS",
        "actor": "aios-control-plane",
        "capabilities": ["repo.read"],
        "input_digest": "sha256:input",
        "allowed_effects": ["repo.inspect"],
        "evidence_required": ["source"],
        "max_attempts": 1,
        "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
        "policy_digest": "sha256:policy",
    }
    value.update(overrides)
    return value


def test_authority_canonicalization_preserves_acceptance_predicates_in_permit():
    contract = _contract(acceptance_predicates=[{
        "predicate_id": "verified",
        "path": "verification.verified",
        "operator": "eq",
        "expected": True,
    }])

    canonical = _canonical_contract(contract)
    assert canonical["acceptance_predicates"] == contract["acceptance_predicates"]

    permit = issue_permit(canonical, issuer="test-issuer")
    assert permit["acceptance_predicates"] == contract["acceptance_predicates"]
    assert verify_permit(canonical, permit) is True


def test_authority_rejects_permit_when_acceptance_predicate_changes():
    contract = _canonical_contract(_contract(acceptance_predicates=[{
        "predicate_id": "verified",
        "path": "verification.verified",
        "operator": "eq",
        "expected": True,
    }]))
    permit = issue_permit(contract, issuer="test-issuer")
    changed = dict(contract)
    changed["acceptance_predicates"] = [{
        "predicate_id": "verified",
        "path": "verification.verified",
        "operator": "eq",
        "expected": False,
    }]

    try:
        verify_permit(changed, permit)
    except ValueError as exc:
        assert "bound to this contract" in str(exc)
    else:
        raise AssertionError("permit unexpectedly accepted changed acceptance predicates")


def test_legacy_contract_without_acceptance_predicates_remains_valid():
    canonical = _canonical_contract(_contract())
    assert "acceptance_predicates" not in canonical
    permit = issue_permit(canonical, issuer="test-issuer")
    assert "acceptance_predicates" not in permit
    assert verify_permit(canonical, permit) is True
