import json, sys
import pytest
from pathlib import Path
import scripts.run_pcb_eda_durable as r

import hashlib, subprocess
from core import mutation as m
from scripts import architecture_boundary_check as abc
def test_pcb_eda_receipt_lineage_matches_canonical_intent(tmp_path, monkeypatch, capsys):
    def fake_run_kit(req):
        out = Path(req.output_dir); out.mkdir(parents=True, exist_ok=True)
        rec = {"schema": "x", "status": "PASS", "terminal_reason": "ok", "gates": {}}
        (out / "summary.json").write_text(json.dumps(rec), encoding="utf-8")
        return 0, rec
    monkeypatch.setattr(r, "run_kit", fake_run_kit)
    monkeypatch.setattr(r, "validate_kit_receipt", lambda x: None)
    for d in ("in", "out", "kit"): (tmp_path / d).mkdir()
    state = tmp_path / "state.json"
    monkeypatch.setattr(sys, "argv", ["x", "--task-id", "T", "--input", str(tmp_path/"in"), "--output", str(tmp_path/"out"),
        "--kit-root", str(tmp_path/"kit"), "--state", str(state), "--max-steps", "1"])
    try: r.main()
    except SystemExit: pass
    final = r.JsonStateStore(str(state)).load()
    assert "lineage does not match" not in str(final.get("block_reason")), final.get("block_reason")
    assert final["history"][-1]["verification"]["receipt"]["effect_id"].startswith("EF-")


def _evil_batch(aios, tmp_dest, dest):
    batch = aios / ".staging" / "batch-evil"; batch.mkdir(parents=True, exist_ok=True)
    payload = b"attacker-controlled\n"
    tmp_dest.write_bytes(payload)
    ops = [{"tmp": str(tmp_dest), "dest": str(dest), "digest": hashlib.sha256(payload).hexdigest()}]
    j = {"format": 2, "batch_id": "evil", "ops": ops, "body_digest": m._journal_body_digest("evil", ops)}
    (batch / "journal.v2.json").write_text(m.canonical_json(j))
    return batch


def test_rollforward_quarantines_dest_outside_store(tmp_path):
    aios = tmp_path / "store" / ".aios"; aios.mkdir(parents=True)
    victim = tmp_path / "outside.txt"
    (aios / ".staging" / "batch-evil").mkdir(parents=True)
    _evil_batch(aios, aios / ".staging" / "batch-evil" / "x.tmp", victim)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert not victim.exists()
    assert m.unresolved_quarantine(str(aios)) == ["batch-evil"]


def test_rollforward_quarantines_tmp_outside_batch(tmp_path):
    aios = tmp_path / "store" / ".aios"; aios.mkdir(parents=True)
    outside_tmp = tmp_path / "planted.tmp"
    dest = aios / "entities" / "x.json"
    _evil_batch(aios, outside_tmp, dest)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert not dest.exists() and outside_tmp.exists()


def test_commit_batch_rejects_escaping_destination(tmp_path):
    aios = tmp_path / "store" / ".aios"; aios.mkdir(parents=True)
    with pytest.raises(m.StateConflictError):
        m.commit_batch(str(aios), [("../../escape.json", {"a": 1})])
    assert not (tmp_path / "escape.json").exists()


def test_boundary_check_flags_relative_and_dynamic_imports(tmp_path):
    core = tmp_path / "core"; core.mkdir()
    for rel in abc.L5_MODULES:
        (tmp_path / rel).write_text("")
    (tmp_path / "core/mutation.py").write_text(
        "from .effect_authority import x\nfrom . import runtime\nimport importlib\nimportlib.import_module('socket')\n__import__('os')\n")
    details = {f["detail"] for f in abc.audit(tmp_path)}
    assert "forbidden dependency: core.effect_authority" in details
    assert "forbidden dependency: core.runtime" in details
    assert "forbidden dependency: importlib" in details
    assert "forbidden dependency: __import__" in details
    assert len(abc.audit(tmp_path)) == 5  # one finding per offending statement


def test_boundary_check_current_tree_is_clean_in_strict_mode():
    root = Path(__file__).resolve().parents[1]
    assert abc.audit(root) == []
