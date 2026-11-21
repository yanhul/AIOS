import os
import shutil
import pytest
from core.effect_authority import create_effect, dispatch, unknown
from core.effect_state_export import export_unknown_effect_snapshot
from core.mutation import TransitionError
from tests.test_m6_effect_authority import _effect


def test_export_requires_current_validated_unknown_effect(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    snapshot = export_unknown_effect_snapshot(str(tmp_path), effect["effect_id"], "agent-1")
    assert snapshot["state"] == "UNKNOWN"
    assert snapshot["effect_id"] == effect["effect_id"]
    assert snapshot["provider"] == "provider-1"


def test_export_rejects_wrong_actor_and_non_unknown_state(tmp_path):
    effect = _effect(tmp_path)
    with pytest.raises(TransitionError, match="only UNKNOWN"):
        export_unknown_effect_snapshot(str(tmp_path), effect["effect_id"], "agent-1")
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    with pytest.raises(TransitionError, match="actor mismatch"):
        export_unknown_effect_snapshot(str(tmp_path), effect["effect_id"], "agent-2")


def test_export_blocks_pending_journal_without_mutating_it(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    pending = tmp_path / ".staging" / "unfinished"
    pending.mkdir(parents=True)
    marker = pending / "journal.json"
    marker.write_text("{}")
    with pytest.raises(TransitionError, match="pending journal"):
        export_unknown_effect_snapshot(str(tmp_path), effect["effect_id"], "agent-1")
    assert marker.exists()


def test_export_rejects_path_traversal_effect_identity(tmp_path):
    (tmp_path / "effects").mkdir()
    with pytest.raises(TransitionError, match="effect identity is malformed"):
        export_unknown_effect_snapshot(str(tmp_path), "../../outside", "agent-1")


def test_export_rejects_symlinked_effects_directory(tmp_path):
    effect = _effect(tmp_path)
    effects = tmp_path / "effects"
    real_effects = tmp_path / "effects-real"
    effects.rename(real_effects)
    effects.symlink_to(real_effects, target_is_directory=True)
    with pytest.raises(TransitionError, match="effect snapshot directory is missing or symlinked"):
        export_unknown_effect_snapshot(str(tmp_path), effect["effect_id"], "agent-1")


def test_export_rejects_symlinked_staging_directory(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1",
             f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    staging_target = tmp_path / "staging-target"
    staging_target.mkdir()
    staging = tmp_path / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.symlink_to(staging_target, target_is_directory=True)
    with pytest.raises(TransitionError, match="staging journal directory is symlinked"):
        export_unknown_effect_snapshot(str(tmp_path), effect["effect_id"], "agent-1")
