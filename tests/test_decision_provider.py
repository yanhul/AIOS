# AIOS-CONTRACT: decision-provider outputs remain advisory and lineage-bound.
# AIOS-REGRESSION: provider revision, candidate set, hashes, abstention, and calibration fences must fail closed.
# AIOS-OWNER: core.decision_provider owns the model-neutral provider boundary.
# AIOS-COVERAGE-GAP: execution/authority integration is intentionally outside this provider-only contract.
# AIOS-BASELINE: main has no decision-provider primitive; this test establishes the absorbed boundary.
import hashlib
import json
from dataclasses import replace

import pytest

from core.decision_provider import (
    ABSTAINED,
    DECIDED,
    INCONCLUSIVE,
    DecisionRequest,
    DecisionResult,
    result_hash_payload,
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
        provider_revision="rev-1",
    )


def result(req, *, status=DECIDED, selected="b", **overrides):
    payload = dict(
        decision_id=req.decision_id,
        provider_ref=req.provider_ref,
        provider_revision=req.provider_revision,
        status=status,
        selected=selected,
        distribution={candidate: score for candidate, score in zip(req.candidates, (0.1, 0.7, 0.2))},
        raw_scores={candidate: score for candidate, score in zip(req.candidates, (1.0, 7.0, 2.0))},
        calibrated_scores={},
        calibration_ref=None,
        input_hash=req.input_hash,
        output_hash="sha256:placeholder",
    )
    payload.update(overrides)
    value = DecisionResult(**payload)
    digest = "sha256:" + hashlib.sha256(
        json.dumps(
            result_hash_payload(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return DecisionResult(**{**payload, "output_hash": digest})


def test_request_is_bounded_and_hashed():
    req = request()
    assert req.input_hash.startswith("sha256:")
    with pytest.raises(ValueError, match="2..20"):
        DecisionRequest(
            decision_id="d", state_ref="s", question="q", decision_type="choice",
            candidates=("only",), evidence_refs=("e",), policy_ref="p",
            provider_ref="x", provider_revision="r",
        )


def test_result_is_advisory_not_authority():
    req = request()
    value = result(req)
    assert value.advisory is True
    assert not hasattr(value, "execute")
    assert not hasattr(value, "commit")
    assert not hasattr(value, "authorize")


def test_result_binds_request_candidate_set_and_output_hash():
    req = request()
    validate_result(req, result(req))
    with pytest.raises(ValueError, match="different decision_id"):
        validate_result(req, result(req, decision_id="other"))
    with pytest.raises(ValueError, match="outside"):
        validate_result(req, result(req, selected="forged"))
    forged = replace(result(req), selected="a")
    with pytest.raises(ValueError, match="output_hash"):
        validate_result(req, forged)


def test_abstention_is_first_class_and_has_no_selection():
    req = request()
    validate_result(req, result(req, status=ABSTAINED, selected=None))
    validate_result(req, result(req, status=INCONCLUSIVE, selected=None))


def test_decided_choice_requires_selection():
    req = request()
    with pytest.raises(ValueError, match="requires selected"):
        validate_result(req, result(req, selected=None))


def test_unknown_candidate_in_provider_output_blocks():
    req = request()
    with pytest.raises(ValueError, match="unknown candidates"):
        validate_result(req, result(req, distribution={"a": 1.0, "forged": 2.0}))


def test_provider_revision_is_pinned():
    req = request()
    with pytest.raises(ValueError, match="provider_revision"):
        validate_result(req, result(req, provider_revision="rev-2"))


def test_calibrated_scores_require_explicit_calibration_ref():
    req = request()
    with pytest.raises(ValueError, match="calibration_ref"):
        validate_result(req, result(req, calibrated_scores={"a": 0.2}))


def test_calibration_metadata_is_preserved():
    req = request()
    value = result(req, calibrated_scores={"a": 0.2, "b": 0.7, "c": 0.1}, calibration_ref="cal:v1")
    validate_result(req, value)
    assert value.calibration_ref == "cal:v1"


def test_score_mode_preserves_scoring_without_forcing_selection():
    req = DecisionRequest(
        decision_id="score-1", state_ref="state:1", question="Rank candidates",
        decision_type="score", candidates=("a", "b"), evidence_refs=("evidence:1",),
        policy_ref="policy:v1", provider_ref="julia-1@adapter-v1", provider_revision="rev-1",
    )
    validate_result(req, result(req, selected=None, raw_scores={"a": 3.0, "b": 1.0}))


def test_boolean_mode_is_binary():
    with pytest.raises(ValueError, match="exactly 2"):
        DecisionRequest(
            decision_id="d", state_ref="s", question="q", decision_type="boolean",
            candidates=("a", "b", "c"), evidence_refs=("e",), policy_ref="p",
            provider_ref="x", provider_revision="r",
        )


def test_result_rejects_non_finite_scores():
    req = request()
    with pytest.raises(ValueError, match="finite"):
        result(req, raw_scores={"a": float("nan")})


def test_result_is_immutable():
    value = result(request())
    with pytest.raises(Exception):
        value.selected = "a"
    with pytest.raises(TypeError):
        value.distribution["a"] = 0.9
