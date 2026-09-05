import pytest

from core.experience import ExperienceError, load_experience, record_experience
from core.mutation import TransitionError


def _kwargs():
    return dict(
        task_id="task-1",
        capability_id="try.research",
        capability_version="1",
        action="research.run",
        outcome="PASS",
        evidence_refs=["EV-100"],
        verification_levels=["VERIFIED_DIGITAL"],
        actor="agent:test",
    )


def test_experience_is_append_only_and_replay_idempotent(tmp_path):
    first = record_experience(tmp_path, **_kwargs())
    second = record_experience(tmp_path, **_kwargs())
    assert first["experience_id"] == second["experience_id"]
    assert second["replayed"] is True
    assert len(load_experience(tmp_path)) == 1


def test_experience_rejects_unknown_verification_level(tmp_path):
    args = _kwargs()
    args["verification_levels"] = ["MODEL_SAYS_TRUE"]
    with pytest.raises(ExperienceError):
        record_experience(tmp_path, **args)


def test_experience_never_accepts_non_terminal_outcome(tmp_path):
    args = _kwargs()
    args["outcome"] = "PROMOTED"
    with pytest.raises(ExperienceError):
        record_experience(tmp_path, **args)


def test_experience_identity_collision_is_blocked(tmp_path):
    record_experience(tmp_path, **_kwargs())
    args = _kwargs()
    args["notes"] = "different content"
    with pytest.raises(TransitionError):
        record_experience(tmp_path, **args)
