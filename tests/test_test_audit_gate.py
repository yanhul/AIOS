# AIOS-CONTRACT: test authoring gate rejects tests without contract ownership and regression evidence
# AIOS-REGRESSION: a changed test can otherwise land without an observable contract
# AIOS-OWNER: scripts/test_audit_gate.py
# AIOS-COVERAGE-GAP: the gate itself is not covered by product tests
# AIOS-BASELINE: executable gate behavior is verified directly

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "test_audit_gate.py"

META = """# AIOS-CONTRACT: contract
# AIOS-REGRESSION: regression
# AIOS-OWNER: owner
# AIOS-COVERAGE-GAP: gap
# AIOS-BASELINE: baseline
"""


def run_gate(path):
    return subprocess.run(
        [sys.executable, str(GATE), str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_gate_accepts_complete_authoring_metadata(tmp_path):
    test = tmp_path / "test_ok.py"
    test.write_text(META + "def test_ok():\n    assert 1 == 1\n", encoding="utf-8")
    result = run_gate(test)
    assert result.returncode == 0
    assert "TEST_AUDIT: PASS" in result.stdout


def test_gate_rejects_missing_contract_metadata(tmp_path):
    test = tmp_path / "test_bad.py"
    test.write_text("def test_bad():\n    assert 1 == 1\n", encoding="utf-8")
    result = run_gate(test)
    assert result.returncode != 0
    assert "AIOS-CONTRACT" in result.stdout
