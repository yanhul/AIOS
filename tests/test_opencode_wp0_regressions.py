from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.agent_repair_worker import AgentRepairWorker, RepairWorkerError
from core.delegation import DelegationError, DelegationRequest
from core.durable_loop import LoopPolicy, MemoryStateStore
from core.durable_wal import DurableTransitionLog
from core.effect_authority import TransitionError
from core.repository_patch_adapter import _safe_repo_path
from core.policy_registry import _policy_filename
from research.absorption_apply import absorb
from scripts.run_pcb_eda_durable import PcbExecutor


class _NoAuthority:
    def authorize_patch(self, *, base_sha, paths):
        return "permit"


def test_repository_patch_adapter_rejects_dot_prefixed_protected_paths(tmp_path):
    root = tmp_path.resolve()
    with pytest.raises(ValueError, match="protected"):
        _safe_repo_path(root, "./.git/hooks/pre-commit")
    with pytest.raises(ValueError, match="protected"):
        _safe_repo_path(root, "./.github/workflows/ci.yml")


def test_repair_worker_rejects_dot_prefixed_protected_paths(tmp_path):
    worker = AgentRepairWorker(tmp_path, _NoAuthority())
    with pytest.raises(RepairWorkerError, match="protected"):
        worker._safe_path("./.git/hooks/pre-commit")
    with pytest.raises(RepairWorkerError, match="protected"):
        worker._safe_path("./.github/workflows/ci.yml")


def test_pcb_durable_receipt_uses_persisted_intent_ids():
    executor = PcbExecutor(SimpleNamespace())
    state = {
        "step": 0,
        "in_flight_attempt": {
            "effect_id": "effect-uuid-from-loop",
            "attempt_id": "attempt-uuid-from-loop",
        },
    }
    result = executor.verify(
        {
            "operation": "pcb.eda.discover_evidence",
            "status": "PASS",
            "verified_evidence_refs": ["/evidence/summary.json"],
            "unresolved_requirements": [],
        },
        state,
    )
    assert result["receipt"]["effect_id"] == "effect-uuid-from-loop"
    assert result["receipt"]["attempt_id"] == "attempt-uuid-from-loop"


def test_orchestrator_preserves_receipt_governance_fields(monkeypatch):
    import core.orchestrator as orchestrator

    monkeypatch.setattr(orchestrator, "authorize", lambda *args: None)
    monkeypatch.setattr(
        orchestrator,
        "load_contract",
        lambda *args: {
            "policy_digest": "policy-1",
            "max_attempts": 1,
            "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
        },
    )
    receipt_validator = lambda receipt, state: None
    patch_validator = lambda patch, receipt, state: None
    resume_calls = []
    caller_resume_validator = lambda state: resume_calls.append(state["contract_id"])
    captured = {}

    def fake_loop(executor, store, policy):
        captured["policy"] = policy
        policy.resume_validator({"contract_id": "c1", "permit_id": "p1"})
        return {"status": "PASS"}

    monkeypatch.setattr(orchestrator, "run_durable_loop", fake_loop)
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        policy_digest="policy-1",
        terminal_states=frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"}),
        resume_validator=caller_resume_validator,
        require_execution_receipt=True,
        execution_receipt_validator=receipt_validator,
        state_patch_validator=patch_validator,
    )
    executor = orchestrator.GovernedRuntimeExecutor(
        aios_dir=".",
        contract_id="c1",
        permit_id="p1",
        actor="agent",
        adapter=SimpleNamespace(name="fake"),
        observer=lambda state: {},
        decider=lambda observation, state: {"logical_operation_id": "op"},
        verifier=lambda result, state: {},
    )
    orchestrator.run_governed_execution(
        executor=executor, store=MemoryStateStore({"contract_id": "c1", "permit_id": "p1", "status": "RUNNING", "history": []}), policy=policy
    )
    assert captured["policy"].require_execution_receipt is True
    assert captured["policy"].execution_receipt_validator is receipt_validator
    assert captured["policy"].state_patch_validator is patch_validator
    assert resume_calls == ["c1"]


def test_delegation_request_rejects_path_like_identifier():
    with pytest.raises(DelegationError, match="canonical"):
        DelegationRequest(
            delegation_id="../authority/permits/PT-forged",
            source_contract_id="c",
            source_permit_id="p",
            source_actor="a",
            target_role="worker",
            authority_mode="none",
            credential_ref=None,
            memory_scope="private",
            target_capability="worker@1",
            operation_id="op",
            input_digest="digest",
            evidence_required=("receipt",),
            lineage=None,
        )


def test_wal_discards_valid_json_without_final_newline_before_append(tmp_path):
    path = tmp_path / "wal.jsonl"
    wal = DurableTransitionLog(str(path))
    wal.append(transition="ENQUEUED", payload={"id": "first"})
    original = path.read_bytes()
    path.write_bytes(original[:-1])
    replay = wal.replay()
    assert replay.dropped_tail_records == 1
    assert len(replay.records) == 0
    wal.append(transition="ENQUEUED", payload={"id": "second"})
    replay = wal.replay()
    assert replay.dropped_tail_records == 0
    assert len(replay.records) == 1
    assert replay.records[0]["payload"]["id"] == "second"


def test_dispatch_rejects_non_owner_before_claiming_attempt(tmp_path, monkeypatch):
    import core.effect_authority as authority

    effect_id = "EF-test"
    effect_path = tmp_path / "effects" / (effect_id + ".json")
    effect_path.parent.mkdir(parents=True)
    effect_path.write_text("{}", encoding="utf-8")
    current = {
        "effect_id": effect_id,
        "contract_id": "contract",
        "permit_id": "permit",
        "actor": "owner",
        "effect_type": "external_effect",
        "policy_digest": "policy",
        "max_attempts": 1,
        "state": "PLANNED",
        "attempt": 0,
    }
    monkeypatch.setattr(authority, "recover_pending", lambda *args: None)
    monkeypatch.setattr(authority, "_load", lambda *args: dict(current))
    monkeypatch.setattr(authority, "_validate_persisted_effect", lambda *args: None)
    monkeypatch.setattr(authority, "_transition_dispatch", lambda *args, **kwargs: pytest.fail("dispatch mutation must not occur"))

    with pytest.raises(TransitionError, match="actor"):
        authority.dispatch(str(tmp_path), effect_id, "intruder", effect_id + ":attempt:1", "provider")


def test_absorption_does_not_treat_global_runtime_proof_as_candidate_proof(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_OUT", str(tmp_path / "absorption.json"))
    executor = {
        "records": [{
            "candidate_id": "c1",
            "source_ref": "source",
            "source_digest": "source-digest",
            "evidence_digest": "evidence-digest",
            "adaptation": {
                "primitive": "durable_execution",
                "signals": ["retry"],
                "proposal": "proposal",
                "target_surface": "new AIOS adapter/task only",
            },
        }]
    }
    verification = {
        "records": [{
            "candidate_id": "c1",
            "claim": "AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS",
            "test_digest": "test-digest",
        }]
    }
    promotion = {
        "decisions": [{"candidate_id": "c1", "allowed": True, "verdict": "PROMOTE"}],
        "blocked": [],
    }
    result = absorb(
        executor, verification, promotion,
        {"overall": "PASS", "digest": "shared-global-proof"},
        run_id="regression",
    )
    assert result["overall"] == "BLOCKED"
    assert result["absorbed_count"] == 0
    assert result["blocked"][0]["reason"] == "missing candidate-bound runtime proof"


def test_policy_artifact_filename_is_windows_safe():
    assert _policy_filename("sha256:0640840b0d5ab455470a7069163a928bd6d14a79168e834bb218a79559ba46b7") == "sha256-0640840b0d5ab455470a7069163a928bd6d14a79168e834bb218a79559ba46b7.json"


def test_promotion_rejects_global_runtime_proof_without_candidate_binding(tmp_path, monkeypatch):
    import research.absorption_promotion as promotion

    monkeypatch.setenv("AIOS_ABSORPTION_PROMOTION_OUT", str(tmp_path / "promotion.json"))
    monkeypatch.setattr(
        promotion,
        "gate_promotion",
        lambda *args, **kwargs: SimpleNamespace(allowed=True, reason="verified"),
    )
    data = {
        "run_id": "r1",
        "overall": "PASS",
        "records": [{
            "candidate_id": "c1",
            "run_id": "r1",
            "source_ref": "source",
            "claim": "claim",
            "level": "VERIFIED_DIGITAL",
            "primitive": "durable_execution",
            "target_surface": "new AIOS adapter/task only",
        }],
        "failures": [],
    }
    result = promotion.promote(data, {"overall": "PASS", "digest": "shared-global-proof"})
    assert result["promoted_count"] == 0
    assert result["implementation_runtime_proof"] is False
    assert result["blocked"][0]["reason"] == "candidate-bound implementation/runtime proof is missing or mismatched"


def test_policy_persistence_uses_sanitized_path(tmp_path, monkeypatch):
    import core.policy_registry as registry

    writes = []
    monkeypatch.setattr(registry, "recover_pending", lambda *args: None)
    monkeypatch.setattr(registry, "commit_batch", lambda root, ops: writes.extend(ops))
    policy = {"policy_type": "GOVERNING_POLICY", "policy_id": "test", "version": "1"}
    digest = registry.persist_policy(str(tmp_path), policy)
    assert writes[0][0] == "policies/" + registry._policy_filename(digest)
    assert ":" not in writes[0][0]
