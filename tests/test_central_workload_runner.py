import json
import subprocess
import sys
from pathlib import Path

from scripts.run_workload_adapter import parse_single_json_document


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


def _invoke(tmp_path, command):
    (tmp_path / "aios").mkdir(exist_ok=True)
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    (tmp_path / "aios" / "adapter.py").write_text(command, encoding="utf-8")
    return subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "test", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/adapter.py"
    ], capture_output=True, text=True)


def test_runner_rejects_undeclared_adapter_before_execution(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    (tmp_path / "aios" / "adapter.py").write_text("print('{}')\n", encoding="utf-8")
    (tmp_path / "aios" / "other.py").write_text("print('{}')\n", encoding="utf-8")
    p = subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "e1", "--cwd", str(tmp_path), "--problem", "p",
        "--", sys.executable, "aios/other.py"], capture_output=True, text=True)
    assert p.returncode == 2
    assert "does not match manifest adapter" in p.stdout


def test_runner_blocks_valid_python_adapter_before_launch(tmp_path):
    marker = tmp_path / "PWNED"
    p = _invoke(tmp_path, f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')\n")
    assert p.returncode == 2
    assert "independent actor issuer" in p.stdout
    assert not marker.exists()


def test_runner_blocks_valid_shell_adapter_before_launch(tmp_path):
    (tmp_path / "aios").mkdir()
    (tmp_path / "aios" / "workload.json").write_text(json.dumps(_manifest("aios/adapter.sh")), encoding="utf-8")
    marker = tmp_path / "PWNED"
    (tmp_path / "aios" / "adapter.sh").write_text(f"touch {str(marker)!r}\n", encoding="utf-8")
    p = subprocess.run([
        sys.executable, str(_runner()), "--workload-id", "yanhul/try",
        "--execution-id", "shell", "--cwd", str(tmp_path), "--problem", "p",
        "--", "bash", "aios/adapter.sh"], capture_output=True, text=True)
    assert p.returncode == 2
    assert "independent actor issuer" in p.stdout
    assert not marker.exists()


def test_parse_single_json_document_accepts_pretty_json():
    assert parse_single_json_document('{\n  "status": "BLOCKED"\n}') == {"status": "BLOCKED"}


def test_parse_single_json_document_rejects_non_json_and_trailing_data():
    import pytest
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_single_json_document("not json")
    with pytest.raises(ValueError, match="exactly one"):
        parse_single_json_document('{"status":"BLOCKED"}\nextra')
