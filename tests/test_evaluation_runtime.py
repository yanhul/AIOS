import json
import os
import tempfile

import pytest

from core.authority import persist_contract, persist_permit
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe, retry_dispatch, unknown
from core.evidence import EvidenceRecord
from core.evaluation import evaluate
from core.mutation import TransitionError
from core.policy_registry import persist_policy


def make_authorized(td):
    from core.capabilities import Capability, CapabilityRegistry
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
    return create_effect(td, contract_identity(contract), "evaluation-runtime", "bc-controller",
                         permit["permit_id"], "process_execution")


def evidence(evidence_id, run_id, provider):
    return EvidenceRecord(
        evidence_id=evidence_id, level="OBSERVED", source_ref=f"runtime/{provider}",
        claim="execution completed", run_id=run_id, provider=provider,
    ).as_record()


def execute_observed(td):
    effect = make_authorized(td)
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(td, effect["effect_id"], "bc-controller", attempt_id, "provider-a")
    observed = observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS",
                       {"attempt_id": attempt_id, "provider": "provider-a",
                        "evidence": evidence("EV-eval-1", "run-eval-1", "provider-a")})
    receipt_path = f"{td}/receipts/{observed['receipt_id']}.json"
    with open(receipt_path, "r", encoding="utf-8") as fh:
        receipt = json.load(fh)
    return effect, observed, receipt


def test_observe_is_the_authoritative_receipt_boundary():
    with tempfile.TemporaryDirectory() as td:
        effect, observed, receipt = execute_observed(td)
        assert receipt["effect_id"] == effect["effect_id"]
        assert receipt["attempt_id"] == observed["attempt_id"]
        assert receipt["provider"] == observed["provider"]
        assert os.path.exists(f"{td}/attempts/{observed['attempt_id'].replace('/', '_')}.json")

        with pytest.raises(TransitionError):
            observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS",
                    observed["provider_observation"])

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
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        rec["attempt_id"] = "forged-attempt"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        with pytest.raises(TransitionError):
            evaluate(td, effect["effect_id"], receipt["receipt_id"], "evaluator-test", "1", "rubric-1", "PASS")


def test_old_attempt_receipt_remains_evaluable_after_retry():
    with tempfile.TemporaryDirectory() as td:
        effect, observed1, receipt1 = execute_observed(td)
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
        attempt2 = f"{effect['effect_id']}:attempt:2"
        retry_dispatch(td, effect["effect_id"], "bc-controller", attempt2, "provider-b", 2)
        observed2 = observe(td, effect["effect_id"], "bc-controller", "OBSERVED_FAILURE",
                            {"attempt_id": attempt2, "provider": "provider-b",
                             "evidence": evidence("EV-eval-2", "run-eval-2", "provider-b")})
        assert observed2["attempt"] == 2
        assert receipt1["attempt_id"] == observed1["attempt_id"]
        result1 = evaluate(td, effect["effect_id"], receipt1["receipt_id"],
                           "evaluator-test", "1", "rubric-1", "PASS")
        assert result1["attempt_id"] == observed1["attempt_id"]

        with open(f"{td}/receipts/{observed2['receipt_id']}.json", "r", encoding="utf-8") as fh:
            receipt2 = json.load(fh)
        result2 = evaluate(td, effect["effect_id"], receipt2["receipt_id"],
                           "evaluator-test", "1", "rubric-1", "FAIL")
        assert result2["attempt_id"] == attempt2


def test_observation_rejects_cross_attempt_evidence():
    with tempfile.TemporaryDirectory() as td:
        effect = make_authorized(td)
        attempt1 = f"{effect['effect_id']}:attempt:1"
        dispatch(td, effect["effect_id"], "bc-controller", attempt1, "provider-a")
        unknown(td, effect["effect_id"], "bc-controller", "timeout")
        attempt2 = f"{effect['effect_id']}:attempt:2"
        retry_dispatch(td, effect["effect_id"], "bc-controller", attempt2, "provider-b", 2)
        with pytest.raises(TransitionError):
            observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS",
                    {"attempt_id": attempt2, "provider": "provider-b",
                     "evidence": evidence("EV-wrong", "run-1", "provider-a")})


def test_evaluation_is_derived_and_carries_no_execution_authority():
    with tempfile.TemporaryDirectory() as td:
        effect, _observed, receipt = execute_observed(td)
        result = evaluate(td, effect["effect_id"], receipt["receipt_id"],
                          "evaluator-test", "1", "rubric-1", "PASS")
        assert "permit_id" not in result
        assert "capability" not in result
        assert "provider" not in result
        assert "dispatch" not in result
