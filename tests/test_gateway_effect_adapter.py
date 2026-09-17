import pytest

from core.attestation import issue_attestation
from core.contract import issue_permit
from core.gateway_effect_adapter import build_gateway_effect_contract


CONTRACT = {
    "contract_type": "EXECUTION_CONTRACT",
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
SECRET = "test-secret"
PERMIT = issue_permit(CONTRACT, "AIOS_AUTHORITY")
ATTESTATION = issue_attestation(CONTRACT, PERMIT, SECRET)


def _build(**overrides):
    args = {
        "effect_id": "effect-1",
        "action": "run_research",
        "capability_ref": "try.research@1",
        "authority_ref": PERMIT["permit_id"],
        "authority_permit": PERMIT,
        "authority_attestation": ATTESTATION,
        "attestation_secret": SECRET,
        "evidence_ref": "evidence-1",
        "lineage_ref": "lineage-1",
        "idempotency_key": "idem-1",
    }
    args.update(overrides)
    return build_gateway_effect_contract(CONTRACT, **args)


def test_builds_gateway_v3_contract_with_verified_authority():
    result = _build()
    assert result == {
        "protocol_version": 3,
        "effect_id": "effect-1",
        "action": "run_research",
        "capability_ref": "try.research@1",
        "authority_ref": PERMIT["permit_id"],
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


def test_forged_authority_ref_is_fail_closed():
    with pytest.raises(ValueError, match="does not match verified permit"):
        _build(authority_ref="PT-forged")


def test_unverified_authority_permit_is_fail_closed():
    forged = dict(PERMIT)
    forged["issuer"] = "FORGED_ISSUER"
    with pytest.raises(ValueError, match="identity mismatch"):
        _build(authority_permit=forged)


def test_invalid_authority_attestation_is_fail_closed():
    forged = dict(ATTESTATION)
    forged["signature"] = "0" * 64
    with pytest.raises(ValueError, match="signature mismatch"):
        _build(authority_attestation=forged)


def test_unversioned_capability_in_workload_contract_is_rejected():
    contract = dict(CONTRACT, capabilities=["try.research"])
    with pytest.raises(ValueError, match="versioned refs"):
        build_gateway_effect_contract(
            contract,
            effect_id="effect-1",
            action="run_research",
            capability_ref="try.research",
            authority_ref=PERMIT["permit_id"],
            authority_permit=PERMIT,
            authority_attestation=ATTESTATION,
            attestation_secret=SECRET,
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
            authority_ref=PERMIT["permit_id"],
            authority_permit=PERMIT,
            authority_attestation=ATTESTATION,
            attestation_secret=SECRET,
            evidence_ref="evidence-1",
            lineage_ref="lineage-1",
            idempotency_key="idem-1",
        )
