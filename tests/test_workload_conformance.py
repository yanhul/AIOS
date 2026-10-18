import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import run_3_workload_conformance as conformance


def receipt(status="BLOCKED", reason="physical evidence required before engineering promotion",
            verification_refs=None):
    return {
        "receipt_type": "AIOS_EXECUTION_RECEIPT",
        "execution_id": "conformance-yanhul-RX50",
        "workload_id": "yanhul/RX50",
        "capability": "rx50.engineering@1",
        "policy_digest": "sha256:" + "a" * 64,
        "contract_id": "CT-" + "b" * 64,
        "permit_id": "PT-" + "c" * 64,
        "status": status,
        "reason": reason,
        "evidence_refs": ["requirements.json"],
        "verification_refs": verification_refs or ["requirements_coverage", "contradiction_check"],
        "provenance": {"producer": "yanhul/RX50"},
    }


def run_with_receipt(monkeypatch, value):
    proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(value), stderr="")
    monkeypatch.setattr(conformance.subprocess, "run", lambda *args, **kwargs: proc)
    return conformance.run_one(Path("runner.py"), "yanhul/RX50", Path("."), Path("receipt.json"))


def test_rx50_expected_physical_evidence_hold_is_accepted_without_becoming_pass(monkeypatch):
    result = run_with_receipt(monkeypatch, receipt())
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "physical evidence required before engineering promotion"


@pytest.mark.parametrize("bad", [
    receipt(status="PASS", reason="physical evidence required before engineering promotion"),
    receipt(reason="different blocker"),
    receipt(verification_refs=["requirements_coverage"]),
    receipt(verification_refs=["requirements_coverage", "contradiction_check", "physical_evidence"]),
])
def test_rx50_unexpected_outcomes_remain_blocked_from_conformance(monkeypatch, bad):
    with pytest.raises(RuntimeError, match="unexpected workload outcome"):
        run_with_receipt(monkeypatch, bad)
