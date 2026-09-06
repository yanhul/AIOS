import sys

import pytest

from core.workload_adapter import validate_adapter_result
from core.workload_runner import WorkloadAdapterError, run_workload_adapter


def test_pass_requires_evidence_and_verification(tmp_path):
    for ref in ("artifact", "evidence", "verification"):
        (tmp_path / ref).write_text("fixture", encoding="utf-8")
    result = validate_adapter_result(
        workload_id="try.research@1", execution_id="e1",
        result={"status": "PASS", "artifact_refs":["artifact"],
                "evidence_refs":["evidence"], "verification_refs":["verification"],
                "provenance":{"producer":"try"}}, cwd=tmp_path)
    assert result.to_aios_terminal() == "PASS"


def test_agent_cannot_invent_terminal_status():
    with pytest.raises(ValueError, match="invalid terminal"):
        validate_adapter_result(workload_id="x", execution_id="e2",
                                result={"status":"PROMOTE"})


def test_pass_without_refs_is_rejected():
    with pytest.raises(ValueError, match="requires evidence"):
        validate_adapter_result(workload_id="x", execution_id="e3",
                                result={"status":"PASS", "provenance":{"producer":"x"}})


def test_runner_rejects_invalid_json(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text("print('not-json')", encoding="utf-8")
    with pytest.raises(WorkloadAdapterError, match="valid JSON"):
        run_workload_adapter(workload_id="x", execution_id="e4",
                             command=[sys.executable, str(script)], cwd=tmp_path, problem="test")


def test_runner_rejects_missing_local_evidence(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text("import json; print(json.dumps({'status':'PASS','evidence_refs':['missing'],'verification_refs':['missing'],'provenance':{'producer':'x'}}))", encoding="utf-8")
    with pytest.raises(WorkloadAdapterError, match="missing local artifact"):
        run_workload_adapter(workload_id="x", execution_id="e5",
                             command=[sys.executable, str(script)], cwd=tmp_path, problem="test")


def test_blocked_result_is_valid_without_fake_evidence():
    result = validate_adapter_result(workload_id="rx50.engineering@1", execution_id="e6",
                                     result={"status":"BLOCKED", "provenance":{"producer":"RX50"}})
    assert result.status == "BLOCKED"
