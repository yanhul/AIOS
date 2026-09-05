import pytest

from core.workload_adapter import validate_adapter_result


def test_pass_result_requires_evidence_and_verification():
    result = validate_adapter_result(
        workload_id="try.research@1",
        execution_id="exec-1",
        result={
            "status": "PASS",
            "artifact_refs": ("artifact-1",),
            "evidence_refs": ("evidence-1",),
            "verification_refs": ("verification-1",),
            "provenance": {"producer": "try"},
        },
    )
    assert result.to_aios_terminal() == "PASS"


def test_blocked_result_is_valid_without_fake_evidence():
    result = validate_adapter_result(
        workload_id="rx50.engineering@1",
        execution_id="exec-2",
        result={"status": "BLOCKED", "provenance": {"producer": "RX50"}},
    )
    assert result.status == "BLOCKED"


def test_agent_cannot_invent_terminal_status():
    with pytest.raises(ValueError):
        validate_adapter_result(
            workload_id="android.assistant@1",
            execution_id="exec-3",
            result={"status": "PROMOTE"},
        )


def test_pass_without_refs_is_blocked_by_schema():
    with pytest.raises(ValueError):
        validate_adapter_result(
            workload_id="try.research@1",
            execution_id="exec-4",
            result={"status": "PASS"},
        )
