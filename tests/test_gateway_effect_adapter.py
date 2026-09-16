import pytest

from core.gateway_effect_adapter import build_gateway_effect_contract


CONTRACT = {
    "contract_type": "research",
    "task_id": "task-1",
    "scope": "try",
    "actor": "aios",
    "capabilities": ["try.research@1"],
    "input_digest": "sha256:input",
    "allowed_effects": ["run_research"],
    "evidence_required": ["experiment_ledger"],
    "max_attempts": 2,
    "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
    "policy_digest": "sha256:policy",
}


def _build(**overrides):
    args = {
        "effect_id": "effect-1",
        "action": "run_research",
        "capability_ref": "try.research@1",
        "authority_ref": "permit-1",
        "evidence_ref": "evidence-1",
        "lineage_ref": "lineage-1",
        "idempotency_key": "idem-1",
    }
    args.update(overrides)
    return build_gateway_effect_contract(CONTRACT, **args)


def test_builds_gateway_v3_contract_without_changing_authority():
    result = _build()
    assert result == {
        "protocol_version": 3,
        "effect_id": "effect-1",
        "action": "run_research",
        "capability_ref": "try.research@1",
        "authority_ref": "permit-1",
        "evidence_ref": "evidence-1",
        "lineage_ref": "lineage-1",
        "idempotency_key": "idem-1",
    }


def test_unregistered_capability_is_fail_closed():
    with pytest.raises(ValueError, match="not granted"):
        _build(capability_ref="try.research@2")


def test_undeclared_effect_is_fail_closed():
    with pytest.raises(ValueError, match="not allowed"):
        _build(action="push_to_github")


def test_missing_authority_ref_is_fail_closed():
    with pytest.raises(ValueError, match="authority_ref"):
        _build(authority_ref="")


def test_unversioned_capability_in_workload_contract_is_rejected():
    contract = dict(CONTRACT, capabilities=["try.research"])
    with pytest.raises(ValueError, match="versioned refs"):
        build_gateway_effect_contract(
            contract,
            effect_id="effect-1",
            action="run_research",
            capability_ref="try.research",
            authority_ref="permit-1",
            evidence_ref="evidence-1",
            lineage_ref="lineage-1",
            idempotency_key="idem-1",
        )


def test_missing_workload_field_is_rejected():
    contract = dict(CONTRACT)
    del contract["policy_digest"]
    with pytest.raises(ValueError, match="policy_digest"):
        build_gateway_effect_contract(
            contract,
            effect_id="effect-1",
            action="run_research",
            capability_ref="try.research@1",
            authority_ref="permit-1",
            evidence_ref="evidence-1",
            lineage_ref="lineage-1",
            idempotency_key="idem-1",
        )
