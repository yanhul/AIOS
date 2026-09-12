from core.adversarial_verification import VerificationResult, require_independent_verifier, verify_repair_reverify
from core.evidence import EvidenceRecord, verify_evidence
from core.experiment_lineage import new_run, verify_record
from core.research_worker import ResearchFinding, ResearchRequest, reconcile_research
from core.worker_lifecycle import WorkerState, restore_worker


def test_experiment_lineage_is_integrity_checked():
    run = new_run("r1", "research.worker", "1", "abc123", "wt/r1", "policy-x")
    record = run.as_record()
    assert verify_record(record)
    record["source_commit"] = "tampered"
    assert not verify_record(record)


def test_adversarial_rail_requires_independent_verifier_and_repair():
    require_independent_verifier("executor", "critic")
    try:
        require_independent_verifier("same", "same")
        assert False
    except PermissionError:
        pass
    calls = []
    def verifier(subject):
        calls.append(subject)
        return VerificationResult("FAIL" if subject == 0 else "PASS", "critic", repair_required=subject == 0)
    result, history = verify_repair_reverify(0, verifier, lambda subject, _: subject + 1)
    assert result == 1 and [r.status for r in history] == ["FAIL", "PASS"]


def test_worker_lifecycle_is_monotonic_and_resumable():
    worker = WorkerState("w1")
    worker.checkpoint_at(2, "resume-2")
    worker.transition("BLOCKED", "waiting")
    restored = restore_worker(worker.as_record())
    restored.transition("WORKING")
    assert restored.checkpoint == 2 and restored.resume_token == "resume-2"


def test_evidence_digest_detects_mutation():
    record = EvidenceRecord("e1", "OBSERVED", "source:x", "claim", "r1", "provider:x").as_record()
    assert verify_evidence(record)
    record["claim"] = "changed"
    assert not verify_evidence(record)


def test_research_worker_returns_to_aios_reconciliation():
    request = ResearchRequest("t1", "find evidence", max_steps=3)
    findings = (ResearchFinding("f1", "source:x", "claim", "e1"),)
    result = reconcile_research(request, findings)
    assert result["requires_aios_verification"] is True
    assert result["promotion_authority"] == "AIOS_CONTROL_PLANE"
