# AIOS-CONTRACT: schematic evidence boundary and PCB EDA receipt validation
# AIOS-REGRESSION: schematic PASS must not require placement/routing closure
# AIOS-OWNER: core.pcb_eda
# AIOS-COVERAGE-GAP: durable placement transition remains a separate phase
# AIOS-BASELINE: existing PCB EDA receipt contract and deferred finding lineage

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

def schematic_receipt(status="PASS"):
    return {
        "schema": "altium-audit-e2e-phase/v2",
        "phase": "SCHEMATIC",
        "status": status,
        "evidence": {
            "required_gates": {
                "G0_INTAKE": "VERIFIED", "G1_PARSE": "VERIFIED",
                "G2_COMPILE": "VERIFIED", "G3_CONNECTIVITY": "VERIFIED",
            },
            "finding_inventory": {
                "errors": [], "blocking": [],
                "deferred_non_gating": [{"id": "G2-SCH-NC-PIN-CONNECTED-U19", "status": "FAIL"}],
            },
        },
    }


def test_schematic_pass_does_not_require_placement_or_routing():
    from core.pcb_eda import validate_schematic_receipt
    validate_schematic_receipt(schematic_receipt())


def test_schematic_pass_rejects_effective_blocker():
    from core.pcb_eda import validate_schematic_receipt
    r = schematic_receipt()
    r["evidence"]["finding_inventory"]["errors"] = [{"id": "REAL-BLOCKER", "status": "FAIL"}]
    with pytest.raises(ValueError, match="blocking"):
        validate_schematic_receipt(r)


def test_schematic_receipt_rejects_missing_deferred_projection():
    from core.pcb_eda import validate_schematic_receipt
    r = schematic_receipt()
    del r["evidence"]["finding_inventory"]["deferred_non_gating"]
    with pytest.raises(ValueError, match="deferred"):
        validate_schematic_receipt(r)


def test_request_accepts_schematic_phase():
    from core.pcb_eda import PcbEdaRequest
    PcbEdaRequest("x", "/i", "/o", "/k", phase="SCHEMATIC").validate()
