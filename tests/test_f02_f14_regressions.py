"""Regression tests for audit findings F-02 (L5 store confinement) and F-14
(architecture boundary checker coverage). See core/mutation.py and
scripts/architecture_boundary_check.py for the documented residual scope."""
import hashlib
import os
from pathlib import Path

import pytest

from core import mutation as m
from scripts import architecture_boundary_check as abc

needs_symlink = pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt",
                                   reason="POSIX symlinks required")
needs_fd = pytest.mark.skipif(not m._FD_SAFE, reason="dir_fd/O_NOFOLLOW not supported")
PAYLOAD = b"attacker-controlled\n"


# ----------------------------------------------------------------------------
# F-02 helpers
# ----------------------------------------------------------------------------

def _store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_bytes(b"original\n")
    return aios, outside


def _batch(aios, name, ops_spec):
    """ops_spec: list of (tmp_name, dest_path, payload|None). None = no tmp file."""
    batch = aios / ".staging" / name
    batch.mkdir(parents=True, exist_ok=True)
    ops = []
    for tmp_name, dest, payload in ops_spec:
        tmp = batch / tmp_name
        data = payload if payload is not None else PAYLOAD
        if payload is not None:
            tmp.write_bytes(payload)
        ops.append({"tmp": str(tmp), "dest": str(dest), "digest": hashlib.sha256(data).hexdigest()})
    j = {"format": 2, "batch_id": name, "ops": ops, "body_digest": m._journal_body_digest(name, ops)}
    (batch / "journal.v2.json").write_text(m.canonical_json(j))
    return batch


def _tree(root):
    """Snapshot of every path under root (bytes for files, link target for links)."""
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            if os.path.islink(p):
                snap[p] = ("link", os.readlink(p))
            elif os.path.isfile(p):
                snap[p] = ("file", Path(p).read_bytes())
            else:
                snap[p] = ("dir", None)
    return snap


def _assert_blocked(aios, batch_name):
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert batch_name in m.unresolved_quarantine(str(aios))
    assert not (aios / ".staging" / batch_name).exists()


# ----------------------------------------------------------------------------
# F-02: symlink and reserved-path confinement (check time)
# ----------------------------------------------------------------------------

@needs_symlink
def test_tmp_symlink_pointing_outside_store_is_quarantined(tmp_path):
    aios, outside = _store(tmp_path)
    (outside / "planted.tmp").write_bytes(PAYLOAD)
    batch = _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", None)])
    os.symlink(outside / "planted.tmp", batch / "x.tmp")
    before = _tree(outside)
    _assert_blocked(aios, "batch-a")
    assert not (aios / "entities" / "x.json").exists()
    assert _tree(outside) == before


@needs_symlink
def test_tmp_symlink_inside_store_is_quarantined(tmp_path):
    """A staged entry must be a regular file: renaming a link would plant it in the store."""
    aios, _ = _store(tmp_path)
    batch = _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", None)])
    (batch / "real.bin").write_bytes(PAYLOAD)
    os.symlink(batch / "real.bin", batch / "x.tmp")
    _assert_blocked(aios, "batch-a")
    assert not os.path.lexists(aios / "entities" / "x.json")


@needs_symlink
def test_dest_symlink_pointing_outside_store_is_quarantined(tmp_path):
    aios, outside = _store(tmp_path)
    os.symlink(outside / "victim.json", aios / "entities" / "x.json")
    _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", PAYLOAD)])
    before = _tree(outside)
    _assert_blocked(aios, "batch-a")
    assert _tree(outside) == before
    assert (outside / "victim.json").read_bytes() == b"original\n"


@needs_symlink
def test_dest_parent_replaced_by_symlink_is_quarantined(tmp_path):
    aios, outside = _store(tmp_path)
    (aios / "entities").rmdir()
    os.symlink(outside, aios / "entities")
    _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "new.json", PAYLOAD)])
    before = _tree(outside)
    _assert_blocked(aios, "batch-a")
    assert _tree(outside) == before


@needs_symlink
def test_symlinked_batch_directory_is_quarantined(tmp_path):
    aios, outside = _store(tmp_path)
    real = _batch(aios, "batch-real", [("x.tmp", aios / "entities" / "x.json", PAYLOAD)])
    evil_target = outside / "batchdir"
    os.replace(real, evil_target)
    # Rewrite the journal so its paths name the symlinked batch, as an attacker would.
    os.symlink(evil_target, aios / ".staging" / "batch-a")
    ops = [{"tmp": str(aios / ".staging" / "batch-a" / "x.tmp"),
            "dest": str(aios / "entities" / "x.json"), "digest": hashlib.sha256(PAYLOAD).hexdigest()}]
    (evil_target / "journal.v2.json").write_text(m.canonical_json(
        {"format": 2, "batch_id": "a", "ops": ops, "body_digest": m._journal_body_digest("a", ops)}))
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "x.json").exists()


@pytest.mark.parametrize("rel", [
    ".staging/batch-a/journal.v2.json",
    ".staging/other/payload.json",
    ".quarantine/batch-old/RESOLVED.json",
    ".quarantine/QUARANTINE.json",
])
def test_rollforward_dest_into_reserved_l5_paths_is_quarantined(tmp_path, rel):
    aios, _ = _store(tmp_path)
    dest = aios / rel
    _batch(aios, "batch-a", [("x.tmp", dest, PAYLOAD)])
    _assert_blocked(aios, "batch-a")
    if "RESOLVED" in rel:
        assert not dest.exists()  # attacker must not self-resolve a quarantine


def test_rollforward_dest_is_mutation_lock_file_is_quarantined(tmp_path):
    aios, _ = _store(tmp_path)
    lock = Path(m._mutation_lock_path(str(aios)))
    _batch(aios, "batch-a", [("x.tmp", lock, PAYLOAD)])
    _assert_blocked(aios, "batch-a")
    assert not lock.exists() or lock.read_bytes() != PAYLOAD


@pytest.mark.parametrize("tmp_name", ["journal.v2.json", "journal.json"])
def test_rollforward_tmp_naming_the_journal_is_quarantined(tmp_path, tmp_name):
    aios, _ = _store(tmp_path)
    batch = aios / ".staging" / "batch-a"
    batch.mkdir(parents=True)
    ops = [{"tmp": str(batch / tmp_name), "dest": str(aios / "entities" / "x.json"),
            "digest": hashlib.sha256(b"x").hexdigest()}]
    (batch / "journal.v2.json").write_text(m.canonical_json(
        {"format": 2, "batch_id": "a", "ops": ops, "body_digest": m._journal_body_digest("a", ops)}))
    _assert_blocked(aios, "batch-a")
    assert not (aios / "entities" / "x.json").exists()


@pytest.mark.parametrize("rel", [
    ".staging/x.json", ".quarantine/b/RESOLVED.json", "entities/../../escape.json",
    "../.aios.mutation.lock",
])
def test_commit_batch_rejects_reserved_or_escaping_destinations(tmp_path, rel):
    aios, outside = _store(tmp_path)
    before = _tree(tmp_path / "store")
    with pytest.raises(m.StateConflictError):
        m.commit_batch(str(aios), [(rel, {"a": 1})])
    after = _tree(tmp_path / "store")
    # ensure_state_dirs may create the standard dirs; nothing else may appear.
    lock = m._mutation_lock_path(str(aios))
    extra = {p for p in after if p not in before and p != lock}
    assert all(after[p][0] == "dir" for p in extra), extra
    assert after.get(lock, ("file", b""))[1] in (b"", None)  # lock file only, never payload
    assert not os.listdir(aios / ".staging")


@needs_symlink
def test_commit_batch_rejects_symlinked_parent(tmp_path):
    aios, outside = _store(tmp_path)
    (aios / "entities").rmdir()
    os.symlink(outside, aios / "entities")
    before = _tree(outside)
    with pytest.raises(m.StateConflictError):
        m.commit_batch(str(aios), [("entities/x.json", {"a": 1})])
    assert _tree(outside) == before


# ----------------------------------------------------------------------------
# F-02: TOCTOU (swap after the check, before open/os.replace)
# ----------------------------------------------------------------------------

def _swap_parent_on_digest(monkeypatch, aios, outside):
    """Swap entities/ for a symlink the first time a digest is computed,
    i.e. after path validation and before any rename."""
    real, done = m._digest_staged_confined, {"v": False}

    def hook(*args):
        out = real(*args)
        if not done["v"]:
            done["v"] = True
            os.replace(aios / "entities", aios / "entities.moved")
            os.symlink(outside, aios / "entities")
        return out
    monkeypatch.setattr(m, "_digest_staged_confined", hook)
    return done


@needs_symlink
@needs_fd
def test_toctou_parent_swapped_after_check_during_rollforward(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", PAYLOAD)])
    before = _tree(outside)
    done = _swap_parent_on_digest(monkeypatch, aios, outside)
    _assert_blocked(aios, "batch-a")
    assert done["v"], "race window was not exercised"
    assert _tree(outside) == before


@needs_symlink
@needs_fd
def test_toctou_parent_swapped_after_check_during_commit(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    before = _tree(outside)
    real, done = m._digest_bytes, {"v": False}
    def hook(data):
        out = real(data)
        if not done["v"]:
            done["v"] = True
            os.replace(aios / "entities", aios / "entities.moved")
            os.symlink(outside, aios / "entities")
        return out
    monkeypatch.setattr(m, "_digest_bytes", hook)
    with pytest.raises(m.LedgerBlockedError):
        m.commit_batch(str(aios), [("entities/x.json", {"a": 1})])
    assert done["v"]
    assert _tree(outside) == before
    assert len(m.unresolved_quarantine(str(aios))) == 1


@needs_symlink
@needs_fd
def test_toctou_tmp_swapped_for_symlink_after_check(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    batch = _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", PAYLOAD)])
    real, done = m._digest_staged_confined, {"v": False}

    def hook(*args):
        out = real(*args)
        if not done["v"]:
            done["v"] = True
            os.unlink(batch / "x.tmp")
            os.symlink(outside / "victim.json", batch / "x.tmp")
        return out
    monkeypatch.setattr(m, "_digest_staged_confined", hook)
    _assert_blocked(aios, "batch-a")
    assert done["v"]
    assert not os.path.lexists(aios / "entities" / "x.json")
    assert (outside / "victim.json").read_bytes() == b"original\n"


# ----------------------------------------------------------------------------
# F-02: fail-closed ordering
# ----------------------------------------------------------------------------

def test_violation_in_later_op_prevents_earlier_ops_from_applying(tmp_path):
    aios, outside = _store(tmp_path)
    _batch(aios, "batch-a", [("ok.tmp", aios / "entities" / "ok.json", PAYLOAD),
                             ("bad.tmp", outside / "victim.json", PAYLOAD)])
    _assert_blocked(aios, "batch-a")
    assert not (aios / "entities" / "ok.json").exists()
    assert (outside / "victim.json").read_bytes() == b"original\n"


def test_quarantine_stops_rollforward_of_later_batches(tmp_path):
    aios, outside = _store(tmp_path)
    _batch(aios, "batch-a", [("x.tmp", outside / "victim.json", PAYLOAD)])
    _batch(aios, "batch-b", [("y.tmp", aios / "entities" / "y.json", PAYLOAD)])
    _assert_blocked(aios, "batch-a")
    assert not (aios / "entities" / "y.json").exists()
    assert (aios / ".staging" / "batch-b").is_dir()
    with pytest.raises(m.LedgerBlockedError):  # stays blocked until operator resolution
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "y.json").exists()
    with pytest.raises(m.LedgerBlockedError):
        m.commit_batch(str(aios), [("entities/z.json", {"a": 1})])


def test_valid_batch_still_rolls_forward(tmp_path):
    aios, _ = _store(tmp_path)
    _batch(aios, "batch-a", [("x.tmp", aios / "entities" / "sub" / "x.json", PAYLOAD)])
    m.recover_pending(str(aios))
    assert (aios / "entities" / "sub" / "x.json").read_bytes() == PAYLOAD
    assert m.unresolved_quarantine(str(aios)) == []


def test_valid_commit_with_nested_destination(tmp_path):
    aios, _ = _store(tmp_path)
    out = m.commit_batch(str(aios), [("entities/a/b/x.json", {"a": 1})])
    assert Path(out[0]).is_file() and not os.path.islink(out[0])


# ----------------------------------------------------------------------------
# F-14: boundary checker coverage
# ----------------------------------------------------------------------------

def _scan(tmp_path, source, relative="core/mutation.py"):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    return abc.inspect_file(tmp_path, relative)


def _details(findings):
    return {f["detail"] for f in findings}


def test_resolve_relative_nested_packages():
    assert abc._resolve_relative("core/a/b/m.py", 1, "x") == "core.a.b.x"
    assert abc._resolve_relative("core/a/b/m.py", 2, "x") == "core.a.x"
    assert abc._resolve_relative("core/a/b/m.py", 3, None) == "core"
    assert abc._resolve_relative("core/pkg/__init__.py", 1, "x") == "core.pkg.x"


def test_nested_relative_imports_are_resolved(tmp_path):
    src = "from ...effect_authority import grant\nfrom ... import runtime\n"
    f = _scan(tmp_path, src, "core/a/b/m.py")
    assert _details(f) == {"forbidden dependency: core.effect_authority",
                           "forbidden dependency: core.runtime"}
    assert [x["line"] for x in f] == [1, 2]


def test_from_dot_import_module(tmp_path):
    f = _scan(tmp_path, "from . import effect_authority\n")
    assert "forbidden dependency: core.effect_authority" in _details(f)


def test_submodule_of_forbidden_module(tmp_path):
    f = _scan(tmp_path, "import core.effect_authority.helpers\n")
    assert len(f) == 1


@pytest.mark.parametrize("src,line", [
    ("from importlib import import_module as im\n", 1),
    ("import importlib as il\nx = 1\nloader = il.import_module\n", 3),
    ("import importlib.util\n", 1),
    ("import runpy\n", 1),
])
def test_importlib_aliases(tmp_path, src, line):
    assert line in {f["line"] for f in _scan(tmp_path, src)}


def test_getattr_importlib_import_module(tmp_path):
    f = _scan(tmp_path, "x = 1\nloader = getattr(mod, 'import_module')\n")
    assert [x["line"] for x in f] == [2]


@pytest.mark.parametrize("src", [
    "import builtins\nx = 1\nf = getattr(builtins, '__import__')\n",
    "x = 1\ny = 2\nf = __builtins__['__import__']\n",
])
def test_getattr_builtins_import(tmp_path, src):
    assert 3 in {f["line"] for f in _scan(tmp_path, src)}


@pytest.mark.parametrize("builtin", ["exec", "eval", "compile"])
def test_dynamic_execution_builtins(tmp_path, builtin):
    f = _scan(tmp_path, f"x = 1\n{builtin}('import socket')\n")
    assert _details(f) == {f"forbidden dependency: {builtin}"}


def test_import_function_assigned_then_called_via_alias(tmp_path):
    f = _scan(tmp_path, "x = 1\nload = __import__\nload('socket')\n")
    assert 2 in {x["line"] for x in f}


def test_legitimate_imports_are_not_flagged(tmp_path):
    src = (
        "import datetime, hashlib, json, os, re, shutil, stat, uuid\n"
        "from . import state as state_layout\n"
        "from .state import STATE_DIRS\n"
        "from ..core import state\n"
        "from typing import Iterable\n"
        "PATTERN = re.compile(r'x')\n"
        "obj.compile()\n"
        "importer = 'imported'\n"
        "def import_entities(): return 'import'\n"
        "MSG = 'uses import_module elsewhere'\n"
    )
    assert _scan(tmp_path, src) == []


def test_known_limitation_runtime_assembled_names_are_not_detected(tmp_path):
    """Pins the documented scope: AST checks cannot see names built at runtime."""
    assert _scan(tmp_path, "import builtins\nf = getattr(builtins, '__imp' + 'ort__')\n") == []


def test_current_tree_still_clean():
    root = Path(__file__).resolve().parents[1]
    assert abc.audit(root) == []
