"""Strict output semantics for MiniMind capability discovery."""
# AIOS-CONTRACT: Capability check process success is distinct from capability availability.
# AIOS-REGRESSION: A BLOCKED provider must never be emitted under a CHECK_PASS key.
# AIOS-OWNER: MiniMind capability adapter contract and CI discovery output.
# AIOS-COVERAGE-GAP: Malformed reference collections can look truthy without being valid evidence.
# AIOS-BASELINE: Preserve explicit capability status and typed evidence references.
import json
import subprocess

import pytest

from scripts import check_minimind_capability as check


def _receipt(**overrides):
    receipt = {
        "status": "BLOCKED",
        "evidence_refs": ["minimind:path_missing=model.py"],
        "verification_refs": ["artifact_lineage"],
        "provenance": {
            "producer": "jingyaogong/minimind",
            "adapter": "minimind.model@1",
        },
    }
    receipt.update(overrides)
    return receipt


def _run_adapter(monkeypatch, receipt):
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout=json.dumps(receipt), stderr=""
        ),
    )
    monkeypatch.setattr(check.sys, "argv", ["check_minimind_capability.py", "--root", "."])


def test_blocked_capability_is_never_emitted_as_check_pass(monkeypatch, capsys):
    _run_adapter(monkeypatch, _receipt())

    assert check.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["MINIMIND_CAPABILITY_CHECK"]["status"] == "BLOCKED"
    assert "MINIMIND_CAPABILITY_CHECK_PASS" not in output


@pytest.mark.parametrize("field", ["evidence_refs", "verification_refs"])
def test_capability_receipt_rejects_non_list_refs(monkeypatch, field):
    _run_adapter(monkeypatch, _receipt(**{field: "looks-nonempty-but-is-not-a-list"}))

    with pytest.raises(SystemExit, match="must be a non-empty list of strings"):
        check.main()


@pytest.mark.parametrize(("status", "code"), [("BLOCKED", 2), ("INCONCLUSIVE", 2), ("AVAILABLE", 0)])
def test_production_gate_fails_unless_available(monkeypatch, tmp_path, status, code):
    _run_adapter(monkeypatch, _receipt(status=status))
    monkeypatch.setattr(check.sys, "argv", ["check_minimind_capability.py", "--root", ".", "--require-available"])
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert check.main() == code
    text = summary.read_text(encoding="utf-8")
    assert f"**{status}**" in text and "production gate" in text and "not MiniMind runtime readiness" in text


def test_report_mode_never_claims_readiness(monkeypatch, tmp_path):
    _run_adapter(monkeypatch, _receipt())
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert check.main() == 0
    assert "non-production readiness report" in summary.read_text(encoding="utf-8")
