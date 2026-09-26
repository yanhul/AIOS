# AIOS-CONTRACT: execution lineage context must remain immutable and complete
# AIOS-REGRESSION: reject tampered or incomplete policy/environment/provider lineage
# AIOS-OWNER: control-plane execution provenance
# AIOS-COVERAGE-GAP: provider/environment revision was not previously bound to trajectory
# AIOS-BASELINE: no pre-existing test covered strict trajectory-context digesting
from core.execution_lineage import ExecutionLineage, require_lineage_fields, validate_lineage
import pytest


def test_lineage_round_trip_and_digest():
    lineage = ExecutionLineage(
        policy_revision="policy:v1",
        environment_revision="env:2026-09-26",
        capability_snapshot={"research": "v3", "web": "v2"},
        provider_revision="gemini:model:v1",
        attempt_id="EF-1:attempt:2",
        trajectory_id="traj-2",
        raw_output_digest="sha256:raw",
    )
    record = lineage.as_record()
    assert validate_lineage(record).digest == record["lineage_digest"]


def test_tampered_revision_fails_closed():
    lineage = ExecutionLineage(
        "policy:v1", "env:v1", {"research": "v1"}, "provider:v1",
        "attempt:1", "trajectory:1"
    )
    record = lineage.as_record()
    record["provider_revision"] = "provider:evil"
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_lineage(record)


def test_missing_context_fails_closed():
    lineage = ExecutionLineage(
        "policy:v1", "env:v1", {"research": "v1"}, "provider:v1",
        "attempt:1", "trajectory:1"
    )
    record = lineage.as_record()
    del record["environment_revision"]
    with pytest.raises(ValueError, match="incomplete"):
        require_lineage_fields(record)


def test_capability_snapshot_cannot_be_empty():
    with pytest.raises(ValueError, match="capability_snapshot"):
        ExecutionLineage(
            "policy:v1", "env:v1", {}, "provider:v1",
            "attempt:1", "trajectory:1"
        )
