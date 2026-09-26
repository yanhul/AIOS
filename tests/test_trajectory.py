# AIOS-CONTRACT: raw execution evidence is immutable and normalization is derived
# AIOS-REGRESSION: reject raw/normalized tampering and stale step context
# AIOS-OWNER: control-plane trajectory provenance
# AIOS-COVERAGE-GAP: execution lineage lacked step-level raw/normalized binding
# AIOS-BASELINE: no strict trajectory step validator existed
import pytest
from core.trajectory import TrajectoryStep, validate_step

def make():
    return TrajectoryStep("traj:1","step:1","attempt:2","env:v3",{"tool":"v2"},
        '{"tool":"search","args":{"q":"x"}}',({"name":"search","args":{"q":"x"}},),"int:1")

def test_round_trip_and_separate_raw_normalized_digests():
    s=make(); r=s.as_record()
    assert validate_step(r).digest == r["step_digest"]
    assert r["raw_output_digest"] != r["normalized_digest"]

def test_raw_tamper_rejected():
    r=make().as_record(); r["raw_output"]='{"tool":"evil"}'
    with pytest.raises(ValueError,match="raw output digest"):
        validate_step(r)

def test_normalized_tamper_rejected():
    r=make().as_record(); r["normalized_tool_calls"]=[{"name":"evil"}]
    with pytest.raises(ValueError,match="normalized tool-call digest"):
        validate_step(r)

def test_stale_environment_context_rejected():
    r=make().as_record(); r["environment_revision"]="env:evil"
    with pytest.raises(ValueError,match="trajectory step digest"):
        validate_step(r)
