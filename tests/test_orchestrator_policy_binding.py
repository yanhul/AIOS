# AIOS-CONTRACT: governed execution binds loop policy to the governing contract and permit.
# AIOS-REGRESSION: Policy/contract drift (digest, budget, terminal states, acceptance predicates).
# AIOS-OWNER: AIOS control-plane orchestrator
# AIOS-COVERAGE-GAP: Authority-bound policy fields overridden from the contract.
# AIOS-BASELINE: Extends tests/test_m6_runtime.py.
"""L3<-L6 binding: the orchestrator must forward every LoopPolicy gate and must
bind acceptance predicates to the governing contract (D1/D2 regression tests)."""
import dataclasses

import pytest

from core.acceptance import AcceptancePredicate
from core.authority import load_contract, load_permit, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.durable_loop import LoopPolicy, MemoryStateStore
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution
from core.policy_registry import persist_policy

PRED = {"predicate_id": "verified", "path": "verification.verified", "operator": "eq", "expected": True}
CONTRACT = {"policy_digest": "policy-1", "max_attempts": 1,
            "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"]}


def _executor(verified=True):
    return GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent", adapter=object(),
        observer=lambda s: None, decider=lambda o, s: {"logical_operation_id": "op"},
        verifier=lambda r, s: {"verified": verified},
    )


def _policy(**kw):
    values = dict(max_steps=1, action_authorizer=lambda d, s: None, policy_digest="policy-1",
                  terminal_evaluator=lambda v, s: "PASS",
                  terminal_states=frozenset(CONTRACT["terminal_states"]))
    values.update(kw)
    return LoopPolicy(**values)


@pytest.fixture
def authority(monkeypatch):
    def install(contract):
        monkeypatch.setattr("core.orchestrator.authorize", lambda *a: None)
        monkeypatch.setattr("core.orchestrator.load_contract", lambda *a: dict(contract))
        monkeypatch.setattr("core.orchestrator.execute", lambda *a: {"ok": True})
    return install


def test_every_loop_policy_field_is_forwarded(authority, monkeypatch):
    authority(CONTRACT)
    captured = {}
    monkeypatch.setattr("core.orchestrator.run_durable_loop",
                        lambda ex, store, policy: captured.setdefault("p", policy) and {})
    receipt_validator = lambda r, s: None
    patch_validator = lambda a, b, c: None
    continuation = lambda v, s: None
    builder = lambda s: {}
    policy = _policy(require_execution_receipt=True, operation_identity=lambda d, s: {}, execution_receipt_validator=receipt_validator,
                     state_patch_validator=patch_validator, blocked_continuation=continuation,
                     continue_contract_builder=builder)
    run_governed_execution(executor=_executor(), store=MemoryStateStore(), policy=policy)
    bound = captured["p"]
    overridden = {"resume_validator", "policy_digest", "terminal_states", "acceptance_predicates",
                  "operation_identity"}
    for field in dataclasses.fields(LoopPolicy):
        if field.name not in overridden:
            assert getattr(bound, field.name) is getattr(policy, field.name), field.name


def test_contract_predicates_missing_from_policy_fail_closed(authority):
    authority({**CONTRACT, "acceptance_predicates": [PRED]})
    with pytest.raises(PermissionError, match="acceptance predicates"):
        run_governed_execution(executor=_executor(), store=MemoryStateStore(), policy=_policy())


def test_policy_cannot_substitute_weaker_predicates(authority):
    authority({**CONTRACT, "acceptance_predicates": [PRED]})
    weaker = (AcceptancePredicate("verified", "verification.verified", "exists"),)
    with pytest.raises(PermissionError, match="acceptance predicates"):
        run_governed_execution(executor=_executor(), store=MemoryStateStore(),
                               policy=_policy(acceptance_predicates=weaker))


def test_contract_predicates_are_enforced_by_loop(authority):
    authority({**CONTRACT, "acceptance_predicates": [PRED]})
    bound = (AcceptancePredicate(**PRED),)
    ok = run_governed_execution(executor=_executor(True), store=MemoryStateStore(),
                                policy=_policy(acceptance_predicates=bound))
    assert ok["status"] == "PASS"
    bad = run_governed_execution(executor=_executor(False), store=MemoryStateStore(),
                                 policy=_policy(acceptance_predicates=bound))
    assert bad["status"] != "PASS"


def test_caller_resume_validator_is_chained_not_dropped(authority, monkeypatch):
    authority(CONTRACT)
    captured = {}
    monkeypatch.setattr("core.orchestrator.run_durable_loop",
                        lambda ex, store, policy: captured.setdefault("p", policy) and {})
    seen = []
    run_governed_execution(executor=_executor(), store=MemoryStateStore(),
                           policy=_policy(resume_validator=lambda s: seen.append(s)))
    captured["p"].resume_validator({"contract_id": "c1", "permit_id": "p1"})
    assert seen == [{"contract_id": "c1", "permit_id": "p1"}]


def test_authority_persists_and_reloads_acceptance_predicates(tmp_path, monkeypatch):
    reg = CapabilityRegistry()
    reg.register(Capability("cap", "1", "AIOS", "external_effect", inputs=("x",), outputs=("y",),
                            status="ACTIVE"))
    reg.persist(tmp_path, actor="test")
    digest = persist_policy(tmp_path, {"policy_type": "GOVERNING_POLICY", "task": "t",
                                       "allowed_effects": ["external_effect"]})
    contract = {"contract_type": CONTRACT_TYPE, "task_id": "t", "scope": "repository", "actor": "a",
                "capabilities": ["cap@1"], "input_digest": "sha256:" + "0" * 64,
                "allowed_effects": ["external_effect"], "evidence_required": ["OBSERVED"],
                "max_attempts": 1, "terminal_states": ["PASS", "BLOCKED"],
                "policy_digest": digest, "acceptance_predicates": [PRED]}
    stored = persist_contract(tmp_path, contract)
    assert load_contract(tmp_path, stored["contract_id"])["acceptance_predicates"] == [PRED]
    permit = persist_permit(tmp_path, stored, issuer="test-authority")
    assert load_permit(tmp_path, permit["permit_id"])["acceptance_predicates"] == [PRED]
    # Predicates are part of identity: dropping them yields a different contract.
    without = {k: v for k, v in contract.items() if k != "acceptance_predicates"}
    assert persist_contract(tmp_path, without)["contract_id"] != stored["contract_id"]
