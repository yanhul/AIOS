# AIOS-CONTRACT: run_governed_execution() may only reach a success terminal for an action whose external effect
#                the effect authority holds as OBSERVED_SUCCESS with a sealed receipt of record, bound to the
#                decided operation; the bound loop policy keeps every caller governance field
#                (PR #126 independent audit comment 6761492715, finding 1).
# AIOS-REGRESSION: Pre-fix, the bridge rebuilt LoopPolicy dropping require_execution_receipt, receipt/state-patch
#                  validators, acceptance predicates, fix_plan/fix_success_state, continue_contract_builder and the
#                  caller resume_validator, and never checked the effect returned by core.runtime.execute(). A
#                  provider timeout (UNKNOWN) with a verifier answering {"verified": true} persisted a success
#                  terminal while the effect authority record stayed UNKNOWN.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: In-process MemoryStateStore only (file-backed reload: test_p1_governed_bridge_receipt_lineage_126).
#                    Durable-loop receipt mode (require_execution_receipt / receipt or state-patch validators) is
#                    not mapped to effect-authority ids and is refused by the bridge before any side effect.
# AIOS-BASELINE: 826fca0 (629 passed, 1 skipped)

import dataclasses
import json
import os

import pytest

import core.orchestrator as orchestrator
from core.acceptance import AcceptancePredicate
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.durable_loop import LoopPolicy, MemoryStateStore
from core.effect_authority import load_receipt
from core.fix_protocol import FixPlan
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution
from core.policy_registry import persist_policy
from core.runtime import execute as real_execute
from tests.provider_trust_helpers import signed_receipt
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, PROVIDER, Provider

SUCCESS_STATES = ["PASS", "BLOCKED", "INCONCLUSIVE"]


def _authority(tmp_path, max_attempts=1):
    aios = str(tmp_path)
    registry = CapabilityRegistry()
    registry.register(Capability(PROVIDER, "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(aios, "test-fixture")
    policy_digest = persist_policy(aios, {"policy_type": "GOVERNING_POLICY", "name": "governed-bridge"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "task-bridge", "scope": "bridge-test", "actor": ACTOR,
        "capabilities": [f"{PROVIDER}@1"], "input_digest": "input-1", "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"], "max_attempts": max_attempts,
        "terminal_states": SUCCESS_STATES, "policy_digest": policy_digest,
    }
    persist_contract(aios, contract)
    permit = persist_permit(aios, contract, "root")
    return aios, contract_identity(contract), permit["permit_id"], policy_digest


class Verifier:
    def __init__(self, answer=None):
        self.calls = 0
        self.answer = answer or {"verified": True}

    def __call__(self, result, state):
        self.calls += 1
        return dict(self.answer)


def _executor(aios, cid, pid, adapter, verifier, op="op-1"):
    return GovernedRuntimeExecutor(
        aios_dir=aios, contract_id=cid, permit_id=pid, actor=ACTOR, adapter=adapter,
        observer=lambda state: {"ready": True},
        decider=lambda observation, state: {"logical_operation_id": op},
        verifier=verifier)


def _policy(digest, **overrides):
    values = dict(max_steps=1,
                  terminal_evaluator=lambda verification, state: "PASS" if verification.get("verified") else None,
                  action_authorizer=lambda decision, state: None,
                  policy_digest=digest, terminal_states=frozenset(SUCCESS_STATES))
    values.update(overrides)
    return LoopPolicy(**values)


def _effect_file(aios):
    d = os.path.join(aios, "effects")
    (name,) = os.listdir(d)
    with open(os.path.join(d, name), encoding="utf-8") as fh:
        return json.load(fh)


def _assert_not_pass(result):
    assert result["status"] == "BLOCKED", result
    assert result["terminal_evidence"]["status"] == "BLOCKED"


# ------------------------------------------------------------------ UNKNOWN effect + "verified" verifier

def test_unknown_effect_with_verified_verifier_cannot_persist_pass(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)
    prov, verifier, store = Provider("timeout"), Verifier(), MemoryStateStore()
    result = run_governed_execution(executor=_executor(aios, cid, pid, prov, verifier), store=store,
                                    policy=_policy(digest))
    _assert_not_pass(result)
    assert store.state["status"] == "BLOCKED"            # what was durably persisted
    assert "UNKNOWN" in result["block_reason"]
    assert verifier.calls == 0                           # gate runs before the caller verifier
    assert result["history"] == []
    assert _effect_file(aios)["state"] == "UNKNOWN"      # authority record untouched, reconcilable
    assert prov.calls == 1


def test_unknown_effect_verifier_state_patch_is_never_persisted(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)
    verifier = Verifier({"verified": True, "state_patch": {"verified_evidence_refs": ["forged-ref"]}})
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider("timeout"), verifier),
                                    store=MemoryStateStore(), policy=_policy(digest))
    _assert_not_pass(result)
    assert "verified_evidence_refs" not in result


def test_result_copy_claiming_success_for_unknown_effect_is_refused(tmp_path, monkeypatch):
    aios, cid, pid, digest = _authority(tmp_path)

    def lying_execute(*args):
        real = real_execute(*args)
        assert real["state"] == "UNKNOWN"
        return {**real, "state": "OBSERVED_SUCCESS", "receipt_id": "RC-" + "a" * 64,
                "provider_observation": {"forged": True}}
    monkeypatch.setattr(orchestrator, "execute", lying_execute)
    verifier = Verifier()
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider("timeout"), verifier),
                                    store=MemoryStateStore(), policy=_policy(digest))
    _assert_not_pass(result)
    assert verifier.calls == 0


def test_observed_effect_whose_receipt_of_record_was_removed_cannot_pass(tmp_path, monkeypatch):
    aios, cid, pid, digest = _authority(tmp_path)

    def execute_then_drop_receipt(*args):
        real = real_execute(*args)
        os.remove(os.path.join(aios, "receipts", real["receipt_id"] + ".json"))
        return real
    monkeypatch.setattr(orchestrator, "execute", execute_then_drop_receipt)
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider(), Verifier()),
                                    store=MemoryStateStore(), policy=_policy(digest))
    _assert_not_pass(result)
    assert "receipt" in result["block_reason"]


def test_observed_failure_cannot_reach_a_success_terminal(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)

    class Failing:
        name = PROVIDER

        def execute(self, *, contract, effect, attempt_id):
            return signed_receipt(PROVIDER, effect["effect_id"], attempt_id, "op-f", outcome="OBSERVED_FAILURE")
    result = run_governed_execution(executor=_executor(aios, cid, pid, Failing(), Verifier()),
                                    store=MemoryStateStore(), policy=_policy(digest))
    _assert_not_pass(result)
    assert _effect_file(aios)["state"] == "OBSERVED_FAILURE"
    assert "OBSERVED_SUCCESS" in result["block_reason"]


def test_older_observed_effect_cannot_stand_in_for_the_decided_operation(tmp_path, monkeypatch):
    aios, cid, pid, digest = _authority(tmp_path, max_attempts=1)
    old = real_execute(aios, cid, pid, "op-old", ACTOR, Provider())
    assert old["state"] == "OBSERVED_SUCCESS"
    monkeypatch.setattr(orchestrator, "execute", lambda *args: dict(old))
    verifier = Verifier()
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider(), verifier, op="op-new"),
                                    store=MemoryStateStore(), policy=_policy(digest))
    _assert_not_pass(result)
    assert verifier.calls == 0


# ------------------------------------------------------------------ caller governance fields are kept

def test_bound_policy_keeps_every_caller_governance_field(tmp_path, monkeypatch):
    aios, cid, pid, digest = _authority(tmp_path)
    captured = {}
    monkeypatch.setattr(orchestrator, "run_durable_loop",
                        lambda executor, store, policy: captured.setdefault("policy", policy) and {})
    caller = _policy(
        digest,
        acceptance_predicates=(AcceptancePredicate("p1", "verification.verified", "eq", True),),
        fix_plan=FixPlan(*["x"] * 8), fix_success_state="PASS",
        blocked_continuation=lambda verification, state: None,
        continue_contract_builder=lambda state: {},
        resume_validator=lambda state: None,
    )
    run_governed_execution(executor=_executor(aios, cid, pid, Provider(), Verifier()),
                           store=MemoryStateStore(), policy=caller)
    bound = captured["policy"]
    overridden = {"terminal_evaluator", "resume_validator", "policy_digest", "terminal_states"}
    for f in dataclasses.fields(LoopPolicy):
        if f.name not in overridden:
            assert getattr(bound, f.name) is getattr(caller, f.name), f.name
    assert bound.terminal_evaluator is not caller.terminal_evaluator      # wrapped by the authority gate
    assert bound.resume_validator is not caller.resume_validator          # composed, not replaced


def test_caller_acceptance_predicates_are_enforced(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)
    policy = _policy(digest, acceptance_predicates=(
        AcceptancePredicate("independent-review", "verification.reviewed_by", "eq", "independent"),))
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider(), Verifier()),
                                    store=MemoryStateStore(), policy=policy)
    _assert_not_pass(result)
    assert "acceptance predicates failed" in result["block_reason"]


def test_caller_fix_proof_requirement_is_enforced(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)
    policy = _policy(digest, fix_plan=FixPlan(*["x"] * 8), fix_success_state="PASS")
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider(), Verifier()),
                                    store=MemoryStateStore(), policy=policy)
    _assert_not_pass(result)
    assert "FIXED" in result["block_reason"]


@pytest.mark.parametrize("fields", [
    {"require_execution_receipt": True, "execution_receipt_validator": lambda r, s: None,
     "state_patch_validator": lambda p, r, s: None},
    {"execution_receipt_validator": lambda r, s: None},
    {"state_patch_validator": lambda p, r, s: None},
])
def test_durable_loop_receipt_mode_is_refused_before_any_side_effect(tmp_path, fields):
    """Not supported by this bridge (lineage not mapped): refused, never silently ignored or half-run."""
    aios, cid, pid, digest = _authority(tmp_path)
    prov, store = Provider(), MemoryStateStore()
    with pytest.raises(PermissionError, match="durable-loop receipt mode"):
        run_governed_execution(executor=_executor(aios, cid, pid, prov, Verifier()), store=store,
                               policy=_policy(digest, **fields))
    assert prov.calls == 0
    assert store.state == {}
    assert not os.path.exists(os.path.join(aios, "effects"))


def test_caller_resume_validator_is_still_run(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)
    store = MemoryStateStore({"contract_id": cid, "permit_id": pid, "step": 0, "status": "RUNNING",
                              "history": [], "policy_digest": digest})

    def refuse(state):
        raise ValueError("caller resume validator refused")
    prov = Provider()
    result = run_governed_execution(executor=_executor(aios, cid, pid, prov, Verifier()), store=store,
                                    policy=_policy(digest, resume_validator=refuse))
    _assert_not_pass(result)
    assert "caller resume validator refused" in result["block_reason"]
    assert prov.calls == 0


# ------------------------------------------------------------------ valid flow still works

def test_authoritative_observed_success_still_passes(tmp_path):
    aios, cid, pid, digest = _authority(tmp_path)
    verifier = Verifier()
    result = run_governed_execution(executor=_executor(aios, cid, pid, Provider(), verifier),
                                    store=MemoryStateStore(), policy=_policy(digest))
    assert result["status"] == "PASS", result
    assert verifier.calls == 1
    action = result["history"][-1]["action"]
    assert load_receipt(aios, action["receipt_id"])["outcome"] == "OBSERVED_SUCCESS"
