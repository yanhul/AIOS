import json
import subprocess
import sys
from pathlib import Path


def _manifest():
    return {
        "protocol_version": 1,
        "capability": "try.research@1",
        "owner": "yanhul/try",
        "aios_authority": "yanhul/AIOS",
        "adapter": "aios/adapter.py",
        "entrypoint": "execute",
        "terminal_states": ["EDGE_FOUND", "NO_EDGE_FOUND", "INCONCLUSIVE", "BLOCKED"],
        "verification_classes": ["provenance"],
    }


def test_runner_rejects_undeclared_adapter(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()))
    (tmp_path / "aios" / "adapter.py").write_text("print('{}')\n")
    (tmp_path / "aios" / "other.py").write_text("print('{}')\n")
    runner = Path(__file__).parents[1] / "scripts" / "run_workload_adapter.py"
    p = subprocess.run([
        sys.executable, str(runner), "--workload-id", "yanhul/try",
        "--execution-id", "e1", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/other.py"], capture_output=True, text=True)
    assert p.returncode != 0
    assert "does not match manifest adapter" in p.stdout


def test_runner_rejects_non_json_adapter(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()))
    (tmp_path / "aios" / "adapter.py").write_text("print('not json')\n")
    runner = Path(__file__).parents[1] / "scripts" / "run_workload_adapter.py"
    p = subprocess.run([
        sys.executable, str(runner), "--workload-id", "yanhul/try",
        "--execution-id", "e1", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/adapter.py"], capture_output=True, text=True)
    assert p.returncode != 0
    assert "valid JSON" in p.stdout
