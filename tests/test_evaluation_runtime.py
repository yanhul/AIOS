import tempfile

import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe
from core.evidence import EvidenceRecord
from core.evaluation import evaluate, make_receipt
from core.mutation import TransitionError
from core.policy_registry import persist_policy


def make_authorized(td):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "evaluation-runtime"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "RESEARCH_BC7", "scope": "research",
        "actor": "bc-controller", "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input", "allowed_effects": ["process_execution"],
        "evidence_required": ["execution_receipt"], "max_attempts": 2,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"], "policy_digest": policy,
    }
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "AIOS_AUTHORITY")
    effect = create_effect(td, contract_identity(contract), "evaluation-runtime", "bc-controller",
                           permit["permit_id"], "process_execution")
    return effect


def execute_observed(td):
    effect = make_authorized(td)
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(td, effect["effect_id"], "bc-controller", attempt_id, "provider-a")
    evidence = EvidenceRecord(
        evidence_id="EV-eval-1", level="OBSERVED", source_ref="runtime/provider-a",
        claim="execution completed", run_id="run-eval-1", provider="provider-a",
    ).as_record()
    observed = observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS",
                       {"attempt_id": attempt_id, "provider": "provider-a", "evidence": evidence})
    receipt = make_receipt(td, observed, observed["provider_observation"])
    return effect, observed, receipt


def test_observation_can_be_promoted_only_to_exact_execution_receipt():
    with tempfile.TemporaryDirectory() as td:
        effect, observed, receipt = execute_observed(td)
        assert receipt["effect_id"] == effect["effect_id"]
        assert receipt["attempt_id"] == observed["attempt_id"]
        assert receipt["provider"] == observed["provider"]

        result = evaluate(td, effect["effect_id"], receipt["receipt_id"],
                          "evaluator-test", "1", "rubric-1", "PASS",
                          [{"case": "completion", "passed": True}],
                          [{"criterion": "execution", "passed": True}])
        assert result["effect_id"] == effect["effect_id"]
        assert result["attempt_id"] == receipt["attempt_id"]
        assert result["receipt_id"] == receipt["receipt_id"]
        assert result["verdict"] == "PASS"


def test_evaluation_rejects_missing_receipt():
    with tempfile.TemporaryDirectory() as td:
        effect = make_authorized(td)
        with pytest.raises(TransitionError):
            evaluate(td, effect["effect_id"], "RC-does-not-exist", "evaluator-test", "1", "rubric-1", "PASS")


def test_evaluation_rejects_receipt_bound_to_another_effect():
    with tempfile.TemporaryDirectory() as td:
        effect, _observed, receipt = execute_observed(td)
        with pytest.raises(TransitionError):
            evaluate(td, "EF-forged", receipt["receipt_id"], "evaluator-test", "1", "rubric-1", "PASS")


def test_evaluation_rejects_tampered_receipt_digest():
    with tempfile.TemporaryDirectory() as td:
        effect, _observed, receipt = execute_observed(td)
        path = f"{td}/receipts/{receipt['receipt_id']}.json"
        import json
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        rec["attempt_id"] = "forged-attempt"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        with pytest.raises(TransitionError):
            evaluate(td, effect["effect_id"], receipt["receipt_id"], "evaluator-test", "1", "rubric-1", "PASS")


def test_evaluation_is_derived_and_carries_no_execution_authority():
    with tempfile.TemporaryDirectory() as td:
        effect, _observed, receipt = execute_observed(td)
        result = evaluate(td, effect["effect_id"], receipt["receipt_id"],
                          "evaluator-test", "1", "rubric-1", "PASS")
        assert "permit_id" not in result
        assert "capability" not in result
        assert "provider" not in result
        assert "dispatch" not in result
