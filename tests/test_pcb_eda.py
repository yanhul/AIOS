# AIOS-CONTRACT: PCB and schematic receipts must satisfy phase-specific evidence contracts.
# AIOS-REGRESSION: Reject missing schematic gates, blocking findings, and malformed terminal receipts.
# AIOS-OWNER: AIOS governed PCB EDA capability boundary.
# AIOS-COVERAGE-GAP: Verify schematic-phase evidence independently of placement/routing closure.
# AIOS-BASELINE: Preserve existing PCB receipt and request validation behavior.

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
    gates = {name: "VERIFIED" for name in (
        "G0_INTAKE", "G1_PARSE", "G2_COMPILE", "G3_CONNECTIVITY"
    )}
    return {
        "schema": "altium-audit-e2e-phase/v2",
        "phase": "SCHEMATIC",
        "status": status,
        "evidence": {
            "required_gates": gates,
            "finding_inventory": {
                "errors": [],
                "blocking": [],
                "deferred_non_gating": [],
                "unknown": [],
            },
            "required_unknown_findings": [],
        },
    }


def test_schematic_pass_requires_all_schematic_gates_and_inventory():
    from core.pcb_eda import validate_schematic_receipt

    validate_schematic_receipt(schematic_receipt())
    bad = schematic_receipt()
    bad["evidence"]["required_gates"]["G2_COMPILE"] = "BLOCKED"
    with pytest.raises(ValueError, match="G0/G1/G2/G3"):
        validate_schematic_receipt(bad)


def test_schematic_pass_cannot_hide_blocking_findings():
    from core.pcb_eda import validate_schematic_receipt

    bad = schematic_receipt()
    bad["evidence"]["finding_inventory"]["blocking"] = [{"id": "HCPL-0600"}]
    with pytest.raises(ValueError, match="blocking findings"):
        validate_schematic_receipt(bad)


def test_schematic_receipt_must_preserve_deferred_findings():
    from core.pcb_eda import validate_schematic_receipt

    bad = schematic_receipt()
    bad["evidence"]["finding_inventory"].pop("deferred_non_gating")
    with pytest.raises(ValueError, match="deferred findings"):
        validate_schematic_receipt(bad)



def test_schematic_pass_rejects_required_unknown_findings():
    from core.pcb_eda import validate_schematic_receipt

    bad = schematic_receipt()
    bad["evidence"]["required_unknown_findings"] = [
        {"id": "G2-SCH-IDENTITY-UNRESOLVED-Y1", "domain": "schematic", "status": "UNKNOWN"}
    ]
    with pytest.raises(ValueError, match="unresolved required UNKNOWN"):
        validate_schematic_receipt(bad)


def test_schematic_pass_rejects_unknown_schematic_findings_not_explicitly_deferred():
    from core.pcb_eda import validate_schematic_receipt

    bad = schematic_receipt()
    bad["evidence"]["finding_inventory"]["unknown"] = [
        {"id": "G2-SCH-IDENTITY-UNRESOLVED-Y1", "domain": "schematic", "status": "UNKNOWN"}
    ]
    with pytest.raises(ValueError, match="outside explicit deferrals"):
        validate_schematic_receipt(bad)


def test_schematic_pass_keeps_explicitly_deferred_findings_separate_from_required_unknowns():
    from core.pcb_eda import validate_schematic_receipt

    item = {"id": "G2-HCPL-NC-PIN4-CONNECTED-U19", "domain": "schematic", "status": "FAIL", "severity": "BLOCKER"}
    good = schematic_receipt()
    good["evidence"]["finding_inventory"]["deferred_non_gating"] = [item]
    validate_schematic_receipt(good)
