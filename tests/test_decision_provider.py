import pytest

from core.decision_provider import (
    ABSTAINED,
    DECIDED,
    INCONCLUSIVE,
    DecisionRequest,
    DecisionResult,
    validate_result,
)


def request():
    return DecisionRequest(
        decision_id="decision-1",
        state_ref="state:1",
        question="Which candidate should be evaluated next?",
        decision_type="choice",
        candidates=("a", "b", "c"),
        evidence_refs=("evidence:1",),
        policy_ref="policy:v1",
        provider_ref="julia-1@adapter-v1",
    )


def result(req, *, status=DECIDED, selected="b", **overrides):
    payload = dict(
        decision_id=req.decision_id,
        provider_ref=req.provider_ref,
        provider_revision="rev-1",
        status=status,
        selected=selected,
        distribution={"a": 0.1, "b": 0.7, "c": 0.2},
        raw_scores={"a": 1.0, "b": 7.0, "c": 2.0},
        calibrated_scores={},
        calibration_ref=None,
        input_hash=req.input_hash,
        output_hash="sha256:provider-output",
    )
    payload.update(overrides)
    return DecisionResult(**payload)


def test_request_is_bounded_and_hashed():
    req = request()
    assert req.input_hash.startswith("sha256:")
    with pytest.raises(ValueError, match="2..20"):
        DecisionRequest(
            decision_id="d", state_ref="s", question="q", decision_type="choice",
            candidates=("only",), evidence_refs=("e",), policy_ref="p", provider_ref="x",
        )


def test_result_is_advisory_not_authority():
    req = request()
    value = result(req)
    assert value.advisory is True
    assert not hasattr(value, "execute")
    assert not hasattr(value, "commit")
    assert not hasattr(value, "authorize")


def test_result_binds_request_and_candidate_set():
    req = request()
    validate_result(req, result(req))
    with pytest.raises(ValueError, match="different decision_id"):
        validate_result(req, result(req, decision_id="other"))
    with pytest.raises(ValueError, match="outside"):
        validate_result(req, result(req, selected="forged"))


def test_abstention_is_first_class_and_has_no_selection():
    req = request()
    validate_result(req, result(req, status=ABSTAINED, selected=None))
    validate_result(req, result(req, status=INCONCLUSIVE, selected=None))


def test_decided_requires_selection():
    req = request()
    with pytest.raises(ValueError, match="requires selected"):
        validate_result(req, result(req, selected=None))


def test_unknown_candidate_in_provider_output_blocks():
    req = request()
    with pytest.raises(ValueError, match="unknown candidates"):
        validate_result(req, result(req, distribution={"a": 1.0, "forged": 2.0}))


def test_calibration_is_metadata_not_assumed():
    req = request()
    value = result(req, calibrated_scores={"a": 0.2, "b": 0.7, "c": 0.1}, calibration_ref="cal:v1")
    validate_result(req, value)
    assert value.calibration_ref == "cal:v1"


def test_result_is_immutable():
    value = result(request())
    with pytest.raises(Exception):
        value.selected = "a"
    with pytest.raises(TypeError):
        value.distribution["a"] = 0.9
