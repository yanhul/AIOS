import json
import pytest
from core.autonomous_repair import AutonomousRepairController, Diagnosis, DurableRepairStore, RepairResult, RunEvidence, Verification

class Runner:
    def __init__(self): self.n = 0
    def run(self): self.n += 1; return RunEvidence("PASS" if self.n >= 2 else "FAIL", (f"run-{self.n}",))
class Diagnoser:
    def diagnose(self, run): return Diagnosis("broken boundary", "local patch", "search patch", run.evidence_refs)
class Local:
    def fix(self, diagnosis): return RepairResult(True, "local-1", ("patch-local",))
class Search:
    def search(self, diagnosis): return RepairResult(True, "external-1", ("search-result",))
class Adapter:
    def adapt(self, candidate, diagnosis): return RepairResult(True, "adapted-1", ("adapted-patch",))
class Verifier:
    def verify(self, run, history): return Verification(run.status == "PASS", run.evidence_refs, run.status)

def make(tmp_path, **kwargs):
    return AutonomousRepairController(Runner(), Diagnoser(), Local(), Search(), Adapter(), Verifier(),
                                      DurableRepairStore(str(tmp_path / "repair.json")), **kwargs)

def test_auto_repairs_then_verifies(tmp_path):
    result = make(tmp_path).run()
    assert result["phase"] == "PASS"
    assert result["repair_attempts"] == 1
    assert result["last_run"]["status"] == "PASS"

def test_state_survives_resume(tmp_path):
    controller = make(tmp_path)
    assert controller.run()["phase"] == "PASS"
    saved = json.loads((tmp_path / "repair.json").read_text())
    assert saved["phase"] == "PASS"
    assert make(tmp_path).run()["phase"] == "PASS"

def test_diagnosis_without_evidence_is_rejected(tmp_path):
    class NoEvidence(Diagnoser):
        def diagnose(self, run): return Diagnosis("cause", "fix", "search", ())
    controller = make(tmp_path); controller.diagnoser = NoEvidence()
    with pytest.raises(RuntimeError, match="evidence_refs"): controller.run()

def test_external_search_is_bounded(tmp_path):
    class NoLocal(Local):
        def fix(self, diagnosis): return RepairResult(False, "", ())
    controller = make(tmp_path, max_repairs=1, max_external_repairs=1)
    controller.local_fixer = NoLocal()
    assert controller.run()["phase"] == "PASS"

def test_unverified_result_never_passes(tmp_path):
    class NeverVerify(Verifier):
        def verify(self, run, history): return Verification(False, (), "no independent proof")
    result = make(tmp_path, max_repairs=1, max_external_repairs=1)
    result.verifier = NeverVerify()
    out = result.run()
    assert out["phase"] == "BLOCKED"
    assert "proof" in out["block_reason"]
