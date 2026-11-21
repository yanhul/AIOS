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
