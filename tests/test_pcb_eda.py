import json

import pytest

from core.pcb_eda import PcbEdaRequest, reconcile_pcb_eda, validate_kit_receipt


def receipt(status="BLOCKED"):
    return {
        "schema": "altium-audit-kit-result.v4",
        "status": status,
        "terminal_reason": "evidence_missing",
        "gates": {
            "G3_CONNECTIVITY": "VERIFIED",
            "G6_PLACEMENT": "VERIFIED",
            "G7_ROUTING": "FAIL",
        },
    }


def request():
    return PcbEdaRequest(
        task_id="pcb-e2e-1",
        input_dir="/input",
        output_dir="/output",
        kit_root="/kit",
    )


def test_blocked_kit_receipt_is_consumable_but_not_promoted():
    result = reconcile_pcb_eda(request(), receipt())
    assert result["status"] == "BLOCKED"
    assert result["promotion_authority"] == "AIOS_CONTROL_PLANE"


def test_pass_requires_closure_gates():
    good = receipt("PASS")
    good["gates"]["G7_ROUTING"] = "VERIFIED"
    validate_kit_receipt(good)
    bad = receipt("PASS")
    with pytest.raises(ValueError, match="closure"):
        validate_kit_receipt(bad)


def test_unknown_or_missing_schema_is_fail_closed():
    bad = receipt()
    bad["schema"] = "unknown"
    with pytest.raises(ValueError, match="schema"):
        validate_kit_receipt(bad)


def test_request_rejects_negative_retry_budget():
    with pytest.raises(ValueError, match="max_retries"):
        PcbEdaRequest("x", "/i", "/o", "/k", max_retries=-1).validate()
