import sys

import pytest

from core.workload_runner import WorkloadAdapterError, run_workload_adapter


def test_runner_normalizes_external_adapter_result(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text(
        "import json,sys; print(json.dumps({'status':'BLOCKED','artifact_refs':[],'evidence_refs':[],'verification_refs':[],'provenance':{'producer':'fixture'}}))"
    )
    result = run_workload_adapter(
        workload_id="fixture@1", execution_id="exec-1",
        command=[sys.executable, str(script)], cwd=tmp_path, problem="test",
    )
    assert result.status == "BLOCKED"


def test_runner_rejects_invalid_json(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text("print('not-json')")
    with pytest.raises(WorkloadAdapterError, match="valid JSON"):
        run_workload_adapter(
            workload_id="fixture@1", execution_id="exec-2",
            command=[sys.executable, str(script)], cwd=tmp_path, problem="test",
        )


def test_runner_rejects_nonzero_exit(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text("raise SystemExit(7)")
    with pytest.raises(WorkloadAdapterError, match="exited 7"):
        run_workload_adapter(
            workload_id="fixture@1", execution_id="exec-3",
            command=[sys.executable, str(script)], cwd=tmp_path, problem="test",
        )
