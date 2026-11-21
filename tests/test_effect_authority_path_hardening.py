import pytest

from core.effect_authority import _path
from core.mutation import TransitionError


_EFFECT_ID = "EF-" + "a" * 64


def test_effect_path_rejects_symlinked_storage_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "effects").symlink_to(outside, target_is_directory=True)

    with pytest.raises(TransitionError, match="storage directory must not be symlinked"):
        _path(str(tmp_path), _EFFECT_ID)


def test_effect_path_rejects_symlinked_record_file(tmp_path):
    effects = tmp_path / "effects"
    effects.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"outside":true}', encoding="utf-8")
    (effects / (_EFFECT_ID + ".json")).symlink_to(outside)

    with pytest.raises(TransitionError, match="record must not be symlinked"):
        _path(str(tmp_path), _EFFECT_ID)
