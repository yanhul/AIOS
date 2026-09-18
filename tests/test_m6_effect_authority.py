import pytest

from core.effect_authority import create_effect, dispatch, observe, retry_dispatch, unknown, transition
from tests.m6_fixtures import make_effect
from core.evidence import EvidenceRecord
from core.mutation import TransitionError


def _evidence(provider="provider-1"):
    return EvidenceRecord(
        evidence_id="EV-1",
        level="OBSERVED",
        source_ref="provider://receipt/1",
        claim="provider completed operation",
        run_id="run-1",
        provider=provider,
    ).as_record()


def _observation(effect_id, provider="provider-1"):
    return {
        "attempt_id": f"{effect_id}:attempt:1",
        "provider": provider,
        "evidence": _evidence(provider),
    }


def test_effect_transition_is_atomic_and_audited(tmp_path):
    effect = make_effect(tmp_path)
    assert effect["state"] == "PLANNED"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    retried = retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect["effect_id"]}:attempt:2", "provider-1", 2)
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {**_observation(effect["effect_id"]), "attempt_id": retried["attempt_id"]})
    assert done["state"] == "OBSERVED_SUCCESS"
    assert any(name.name.startswith("effect-" + effect["effect_id"] + "-OBSERVED_SUCCESS-") for name in (tmp_path / "events").iterdir())


def test_unknown_cannot_return_to_dispatch(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "timeout")
    with pytest.raises(TransitionError):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:2", "provider-1")


def test_terminal_state_requires_verified_attempt_bound_evidence(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {})

    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            **_observation(effect["effect_id"]), "attempt_id": "forged-attempt"
        })


def test_observation_provider_must_match_effect(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", _observation(effect["effect_id"], "provider-2"))


def test_tampered_evidence_digest_is_rejected(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    evidence = _evidence()
    evidence["claim"] = "tampered"
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            "attempt_id": f"{effect['effect_id']}:attempt:1",
            "provider": "provider-1",
            "evidence": evidence,
        })
