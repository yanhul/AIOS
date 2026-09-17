import json

import pytest

from core.mutation import canonical_json
from scripts.run_workload_adapter import (
    persist_json,
    receipt_digest,
    result_digest,
    validate_saved_receipt,
)


def _result(status="BLOCKED"):
    return {
        "status": status,
        "reason": "physical evidence required",
        "evidence_refs": ["evidence:physical/index.json"],
        "verification_refs": ["engineering-evidence"],
        "provenance": {"producer": "yanhul/RX50", "adapter": "rx50.engineering@1"},
        "artifact_refs": ["evidence/physical/index.json"],
    }


def _receipt(tmp_path, result):
    receipt_path = tmp_path / "rx50.json"
    result_path = receipt_path.with_name(receipt_path.name + ".result.json")
    persist_json(result_path, result)
    receipt = {
        "receipt_type": "AIOS_GOVERNED_EXECUTION_RECEIPT",
        "execution_id": "conformance-yanhul-RX50",
        "workload_id": "yanhul/RX50",
        "capability": "rx50.engineering@1",
        "policy_digest": "sha256:policy",
        "contract_id": "contract-1",
        "permit_id": "permit-1",
        "status": result["status"],
        "evidence_refs": result["evidence_refs"],
        "verification_refs": result["verification_refs"],
        "provenance": result["provenance"],
        "manifest_sha256": "sha256:manifest",
        "result_ref": result_path.name,
        "result_sha256": result_digest(result),
    }
    receipt["receipt_sha256"] = receipt_digest(receipt)
    persist_json(receipt_path, receipt)
    return receipt_path, receipt


def test_persisted_blocked_result_is_replayable_and_reason_survives(tmp_path):
    result = _result()
    receipt_path, receipt = _receipt(tmp_path, result)
    loaded = validate_saved_receipt(
        receipt,
        receipt_path=receipt_path,
        execution_id=receipt["execution_id"],
        workload_id=receipt["workload_id"],
        capability_ref=receipt["capability"],
        contract_id=receipt["contract_id"],
        policy_digest=receipt["policy_digest"],
        producer="yanhul/RX50",
        terminal_states=["PASS", "BLOCKED"],
        verification=["engineering-evidence"],
    )
    assert loaded["status"] == "BLOCKED"
    assert loaded["reason"] == "physical evidence required"
    assert loaded["artifact_refs"] == ["evidence/physical/index.json"]


def test_tampered_adapter_result_is_rejected(tmp_path):
    result = _result()
    receipt_path, receipt = _receipt(tmp_path, result)
    result_path = receipt_path.with_name(receipt_path.name + ".result.json")
    result["reason"] = "changed after receipt"
    result_path.write_text(canonical_json(result) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="persisted result integrity mismatch"):
        validate_saved_receipt(
            receipt,
            receipt_path=receipt_path,
            execution_id=receipt["execution_id"],
            workload_id=receipt["workload_id"],
            capability_ref=receipt["capability"],
            contract_id=receipt["contract_id"],
            policy_digest=receipt["policy_digest"],
            producer="yanhul/RX50",
            terminal_states=["PASS", "BLOCKED"],
            verification=["engineering-evidence"],
        )


def test_tampered_result_status_cannot_disagree_with_receipt(tmp_path):
    result = _result()
    receipt_path, receipt = _receipt(tmp_path, result)
    result_path = receipt_path.with_name(receipt_path.name + ".result.json")
    tampered = dict(result)
    tampered["status"] = "PASS"
    tampered["reason"] = "forged"
    result_path.write_text(canonical_json(tampered) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="persisted result integrity mismatch"):
        validate_saved_receipt(
            receipt,
            receipt_path=receipt_path,
            execution_id=receipt["execution_id"],
            workload_id=receipt["workload_id"],
            capability_ref=receipt["capability"],
            contract_id=receipt["contract_id"],
            policy_digest=receipt["policy_digest"],
            producer="yanhul/RX50",
            terminal_states=["PASS", "BLOCKED"],
            verification=["engineering-evidence"],
        )
