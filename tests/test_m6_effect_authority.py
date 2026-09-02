import pytest

from core.effect_authority import create_effect, dispatch, observe, unknown
from core.mutation import TransitionError


def test_effect_transition_is_atomic_and_audited(tmp_path):
    effect = create_effect(str(tmp_path), "CT-1", "op-1", "agent-1")
    assert effect["state"] == "PLANNED"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", "attempt-1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {"receipt": "r-1"})
    assert done["state"] == "OBSERVED_SUCCESS"
    assert (tmp_path / "events" / ("effect-" + effect["effect_id"] + "-OBSERVED_SUCCESS.json")).exists()


def test_unknown_cannot_return_to_dispatch(tmp_path):
    effect = create_effect(str(tmp_path), "CT-1", "op-1", "agent-1")
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", "attempt-1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "timeout")
    with pytest.raises(TransitionError):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", "attempt-2", "provider-1")


def test_terminal_state_requires_observation(tmp_path):
    effect = create_effect(str(tmp_path), "CT-1", "op-1", "agent-1")
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", "attempt-1", "provider-1")
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {})
