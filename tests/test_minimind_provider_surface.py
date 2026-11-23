import json
from pathlib import Path

from adapters.minimind import adapter


def _checkout(root: Path) -> None:
    (root / "README.md").write_text("MiniMind pinned source\n", encoding="utf-8")
    for rel in adapter.REQUIRED_PATHS:
        path = root / rel
        path.mkdir(parents=True, exist_ok=True) if rel in {"model", "dataset", "trainer"} else path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix:
            path.write_text("# pinned source\n", encoding="utf-8")


def test_modular_upstream_layout_is_available(tmp_path, monkeypatch, capsys):
    _checkout(tmp_path)
    monkeypatch.setenv("MINIMIND_ROOT", str(tmp_path))
    monkeypatch.delenv("MINIMIND_EXPECTED_REV", raising=False)
    assert adapter.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "AVAILABLE"
    assert "minimind:path_present=model/model_minimind.py" in result["evidence_refs"]
    assert "minimind:path_present=dataset/lm_dataset.py" in result["evidence_refs"]


def test_missing_modular_model_file_remains_blocked(tmp_path, monkeypatch, capsys):
    _checkout(tmp_path)
    (tmp_path / "model" / "model_minimind.py").unlink()
    monkeypatch.setenv("MINIMIND_ROOT", str(tmp_path))
    monkeypatch.delenv("MINIMIND_EXPECTED_REV", raising=False)
    assert adapter.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "BLOCKED"
    assert "minimind:path_missing=model/model_minimind.py" in result["evidence_refs"]
