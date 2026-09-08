import json
import subprocess
import sys
from pathlib import Path


def _manifest(adapter="aios/adapter.py", terminal_states=None):
    return {
        "protocol_version": 1,
        "capability": "try.research@1",
        "owner": "yanhul/try",
        "aios_authority": "yanhul/AIOS",
        "adapter": adapter,
        "entrypoint": "execute",
        "terminal_states": terminal_states or ["EDGE_FOUND", "NO_EDGE_FOUND", "INCONCLUSIVE", "BLOCKED"],
        "verification_classes": ["provenance"],
    }


def _runner():
    return Path(__file__).parents[1] / "scripts" / "run_workload_adapter.py"


def _result(status="BLOCKED"):
    return {
        "status": status,
        "evidence_refs": ["e"],
        "verification_refs": ["provenance"],
        "provenance": {"producer": "yanhul/try", "adapter": "try.research@1"},
    }


def test_runner_rejects_undeclared_adapter(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()))
    (tmp_path / "aios" / "adapter.py").write_text("print('{}')\n")
    (tmp_path / "aios" / "other.py").write_text("print('{}')\n")
    p = subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "e1", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/other.py"], capture_output=True, text=True)
    assert p.returncode != 0
    assert "does not match manifest adapter" in p.stdout


def test_runner_rejects_non_json_adapter(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()))
    (tmp_path / "aios" / "adapter.py").write_text("print('not json')\n")
    p = subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "e1", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/adapter.py"], capture_output=True, text=True)
    assert p.returncode != 0
    assert "valid JSON" in p.stdout


def test_runner_accepts_pretty_json_python_adapter(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()))
    (tmp_path / "aios" / "adapter.py").write_text(
        "import json\nprint(json.dumps(" + repr(_result()) + ", indent=2))\n"
    )
    p = subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "pretty", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/adapter.py"], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout
    receipt = json.loads(p.stdout)
    assert receipt["status"] == "BLOCKED"
    assert receipt["provenance"]["producer"] == "yanhul/try"


def test_runner_accepts_declared_shell_adapter(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest("aios/adapter.sh")))
    (tmp_path / "aios" / "adapter.sh").write_text(
        "printf '%s\\n' '{\"status\":\"BLOCKED\",\"evidence_refs\":[\"e\"],"
        "\"verification_refs\":[\"provenance\"],\"provenance\":{\"producer\":\"yanhul/try\",\"adapter\":\"try.research@1\"}}'\n"
    )
    p = subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "shell", "--cwd", str(tmp_path), "--problem", "p",
        "--", "bash", "aios/adapter.sh"], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout
    assert json.loads(p.stdout)["status"] == "BLOCKED"
