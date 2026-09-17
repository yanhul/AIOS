import importlib.util
import json
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "run_workload_adapter.py"
SPEC = importlib.util.spec_from_file_location("run_workload_adapter", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


PRODUCER = "yanhul/example"
CAPABILITY = "example.capability@1"
TERMINAL = ["PASS", "BLOCKED"]
VERIFICATION = ["conformance"]
BASE_RESULT = {
    "status": "BLOCKED",
    "reason": "physical evidence required",
    "evidence_refs": ["EV-1"],
    "verification_refs": ["conformance"],
    "provenance": {"producer": PRODUCER, "adapter": CAPABILITY},
    "artifact_refs": ["ART-1"],
}


def _receipt(tmp_path: Path, result: dict) -> dict:
    result_path = tmp_path / "receipt.json.result.json"
    result_path.write_text(MODULE.canonical_json(result) + "\n", encoding="utf-8")
    receipt = {
        "receipt_type": "AIOS_GOVERNED_EXECUTION_RECEIPT",
        "execution_id": "conformance-example",
        "workload_id": PRODUCER,
        "capability": CAPABILITY,
        "policy_digest": "sha256:policy",
        "contract_id": "sha256:contract",
        "permit_id": "permit-1",
        "status": result["status"],
        "evidence_refs": result["evidence_refs"],
        "verification_refs": result["verification_refs"],
        "provenance": result["provenance"],
        "manifest_sha256": "sha256:manifest",
        "result_ref": result_path.name,
        "result_sha256": MODULE.result_digest(result),
    }
    receipt["receipt_sha256"] = MODULE.receipt_digest(receipt)
    return receipt


def _validate(tmp_path: Path, receipt: dict) -> dict:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    return MODULE.validate_saved_receipt(
        receipt,
        receipt_path=receipt_path,
        execution_id="conformance-example",
        workload_id=PRODUCER,
        capability_ref=CAPABILITY,
        contract_id="sha256:contract",
        policy_digest="sha256:policy",
        producer=PRODUCER,
        terminal_states=TERMINAL,
        verification=VERIFICATION,
    )


def test_saved_receipt_requires_durable_result_artifact(tmp_path):
    result = dict(BASE_RESULT)
    receipt = _receipt(tmp_path, result)
    (tmp_path / receipt["result_ref"]).unlink()
    with pytest.raises(ValueError, match="result artifact missing"):
        _validate(tmp_path, receipt)


def test_saved_receipt_rejects_tampered_result(tmp_path):
    result = dict(BASE_RESULT)
    receipt = _receipt(tmp_path, result)
    tampered = dict(result, reason="different blocker")
    (tmp_path / receipt["result_ref"]).write_text(MODULE.canonical_json(tampered) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="result integrity mismatch"):
        _validate(tmp_path, receipt)


def test_saved_receipt_rejects_result_receipt_status_mismatch(tmp_path):
    result = dict(BASE_RESULT)
    receipt = _receipt(tmp_path, result)
    receipt["status"] = "PASS"
    receipt["receipt_sha256"] = MODULE.receipt_digest(receipt)
    with pytest.raises(ValueError, match="result status disagrees with receipt"):
        _validate(tmp_path, receipt)


def test_saved_receipt_rejects_result_ref_escape(tmp_path):
    result = dict(BASE_RESULT)
    receipt = _receipt(tmp_path, result)
    receipt["result_ref"] = "../outside.json"
    receipt["receipt_sha256"] = MODULE.receipt_digest(receipt)
    with pytest.raises(ValueError, match="escapes receipt directory"):
        _validate(tmp_path, receipt)
