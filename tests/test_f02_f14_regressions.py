# AIOS-CONTRACT: F-02 store confinement holds on the P0 engine: planted batches are never executed; roll-forward of an authorised txn never follows symlinks or escapes the store.
# AIOS-REGRESSION: Unkeyed planted journals executed (F03-1); symlink/TOCTOU redirection during roll-forward (F-02).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Planted vs authorised residue split; TOCTOU against the CAS check.
# AIOS-BASELINE: audit baseline 74941fff2d28e1955c4b1ca263a2d866ac90d56d
"""Regression tests for audit findings F-02 (L5 store confinement) and F-14
(architecture boundary checker coverage). See core/mutation.py and
scripts/architecture_boundary_check.py for the documented residual scope."""
import os
from pathlib import Path

import pytest

from core import mutation as m
from scripts import architecture_boundary_check as abc
from tests.l5_helpers import (PAYLOAD, assert_txn_quarantined, assert_untracked_quarantined,
                              inflight, journal, planted_batch, staged_files, state, store, tree)

needs_symlink = pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt",
                                   reason="POSIX symlinks required")
needs_fd = pytest.mark.skipif(not m._FD_SAFE, reason="dir_fd/O_NOFOLLOW not supported")

# F-03/F-04 P0: a planted (attacker) batch is never executed, whatever its
# journal says. Its destinations below are therefore never written; the batch
# is preserved as evidence in a service-owned quarantine wrapper. Roll-forward
# attacks are exercised against REAL in-flight transactions (``inflight``).


# ----------------------------------------------------------------------------
# F-02: planted batches (staging writer) are never executed
# ----------------------------------------------------------------------------

@needs_symlink
def test_tmp_symlink_pointing_outside_store_is_quarantined(tmp_path):
    aios, outside = store(tmp_path)
    (outside / "planted.tmp").write_bytes(PAYLOAD)
    batch = planted_batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", None)])
    os.symlink(outside / "planted.tmp", batch / "x.tmp")
    before = tree(outside)
    assert_untracked_quarantined(aios, "batch-a")
    assert not (aios / "entities" / "x.json").exists()
    assert tree(outside) == before


@needs_symlink
def test_dest_symlink_pointing_outside_store_is_quarantined(tmp_path):
    aios, outside = store(tmp_path)
    os.symlink(outside / "victim.json", aios / "entities" / "x.json")
    planted_batch(aios, "batch-a", [("x.tmp", aios / "entities" / "x.json", PAYLOAD)])
    before = tree(outside)
    assert_untracked_quarantined(aios, "batch-a")
    assert tree(outside) == before


@needs_symlink
def test_symlinked_batch_directory_is_quarantined_without_following(tmp_path):
    aios, outside = store(tmp_path)
    (aios / ".staging").mkdir(mode=0o700)
    target = outside / "batchdir"
    target.mkdir()
    (target / "x.tmp").write_bytes(PAYLOAD)
    os.symlink(target, aios / ".staging" / "batch-a")
    assert_untracked_quarantined(aios, "batch-a")
    assert not (aios / "entities" / "x.json").exists()
    assert (target / "x.tmp").read_bytes() == PAYLOAD           # never followed
    (qid,) = [q for q in os.listdir(aios / ".quarantine")]
    assert os.path.islink(aios / ".quarantine" / qid / "evidence")


@pytest.mark.parametrize("rel", [
    ".staging/batch-a/journal.v2.json", ".staging/other/payload.json",
    ".quarantine/batch-old/RESOLVED.json", ".quarantine/QUARANTINE.json",
])
def test_planted_dest_into_reserved_l5_paths_is_never_written(tmp_path, rel):
    aios, _ = store(tmp_path)
    dest = aios / rel
    planted_batch(aios, "batch-a", [("x.tmp", dest, PAYLOAD)])
    assert_untracked_quarantined(aios, "batch-a")
    assert not dest.exists() or dest.read_bytes() != PAYLOAD


def test_planted_dest_is_mutation_lock_file_is_never_written(tmp_path):
    aios, _ = store(tmp_path)
    lock = Path(m._mutation_lock_path(str(aios)))
    planted_batch(aios, "batch-a", [("x.tmp", lock, PAYLOAD)])
    assert_untracked_quarantined(aios, "batch-a")
    assert not lock.exists() or lock.read_bytes() != PAYLOAD


@pytest.mark.parametrize("rel", [
    ".staging/x.json", ".quarantine/b/RESOLVED.json", ".l5/state.json", ".L5/state.json",
    ".Staging/x.json", "entities/../../escape.json", "../.aios.mutation.lock",
    "/etc/passwd", "entities/.x.json.l5tmp",
])
def test_commit_batch_rejects_reserved_or_escaping_destinations(tmp_path, rel):
    aios, outside = store(tmp_path)
    before = tree(tmp_path / "store")
    with pytest.raises(m.StateConflictError):
        m.commit_batch(str(aios), [(rel, {"a": 1})])
    after = tree(tmp_path / "store")
    lock = m._mutation_lock_path(str(aios))
    allowed = {lock, str(aios / ".l5" / "state.json")}
    extra = {p for p in after if p not in before and p not in allowed}
    assert all(after[p][0] == "dir" for p in extra), extra
    assert after.get(lock, ("file", b""))[1] in (b"", None)  # lock file only, never payload
    assert not os.listdir(aios / ".staging")
    assert state(aios)["next_seq"] == 1                      # no sequence allocated


@needs_symlink
def test_commit_batch_rejects_symlinked_parent(tmp_path):
    aios, outside = store(tmp_path)
    (aios / "entities").rmdir()
    os.symlink(outside, aios / "entities")
    before = tree(outside)
    with pytest.raises(m.StateConflictError):
        m.commit_batch(str(aios), [("entities/x.json", {"a": 1})])
    assert tree(outside) == before


# ----------------------------------------------------------------------------
# F-02: roll-forward of a REAL in-flight transaction (TOCTOU / redirection)
# ----------------------------------------------------------------------------

@needs_symlink
@needs_fd
def test_inflight_staged_payload_symlinked_outside_is_quarantined(tmp_path, monkeypatch):
    aios, outside = store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"a": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    staged.unlink()
    os.symlink(outside / "victim.json", staged)
    before = tree(outside)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not os.path.lexists(aios / "entities" / "x.json")
    assert tree(outside) == before


@needs_symlink
@needs_fd
def test_inflight_dest_parent_replaced_by_symlink_is_quarantined(tmp_path, monkeypatch):
    aios, outside = store(tmp_path)
    inflight(aios, [("entities/new.json", {"a": 1})], monkeypatch)
    os.replace(aios / "entities", aios / "entities.moved")
    os.symlink(outside, aios / "entities")
    before = tree(outside)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert tree(outside) == before


@needs_symlink
@needs_fd
def test_toctou_parent_swapped_after_cas_check_during_rollforward(tmp_path, monkeypatch):
    aios, outside = store(tmp_path)
    inflight(aios, [("entities/x.json", {"a": 1})], monkeypatch)
    real, done = m._dest_state_at, {"v": False}

    def hook(*args):
        out = real(*args)
        if not done["v"]:
            done["v"] = True
            os.replace(aios / "entities", aios / "entities.moved")
            os.symlink(outside, aios / "entities")
        return out
    monkeypatch.setattr(m, "_dest_state_at", hook)
    before = tree(outside)
    # The swap happens during the all-op pre-verification; the install walk
    # then refuses the symlinked component (O_NOFOLLOW) and quarantines.
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert done["v"], "race window was not exercised"
    assert tree(outside) == before
    assert not (aios / "entities.moved" / "x.json").exists()


@needs_symlink
@needs_fd
def test_toctou_parent_swapped_after_check_during_commit(tmp_path, monkeypatch):
    aios, outside = store(tmp_path)
    before = tree(outside)
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
    assert tree(outside) == before
    assert len(m.unresolved_quarantine(str(aios))) == 1


@needs_symlink
@needs_fd
def test_toctou_staged_swapped_for_symlink_after_cas_check(tmp_path, monkeypatch):
    aios, outside = store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"a": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    real, done = m._dest_state_at, {"v": False}

    def hook(*args):
        out = real(*args)
        if not done["v"]:
            done["v"] = True
            staged.unlink()
            os.symlink(outside / "victim.json", staged)
        return out
    monkeypatch.setattr(m, "_dest_state_at", hook)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert done["v"]
    assert not os.path.lexists(aios / "entities" / "x.json")
    assert (outside / "victim.json").read_bytes() == b"original\n"


# ----------------------------------------------------------------------------
# F-02: fail-closed ordering
# ----------------------------------------------------------------------------

def test_planted_batch_with_outside_dest_writes_nothing(tmp_path):
    aios, outside = store(tmp_path)
    planted_batch(aios, "batch-a", [("ok.tmp", aios / "entities" / "ok.json", PAYLOAD),
                                    ("bad.tmp", outside / "victim.json", PAYLOAD)])
    assert_untracked_quarantined(aios, "batch-a")
    assert not (aios / "entities" / "ok.json").exists()
    assert (outside / "victim.json").read_bytes() == b"original\n"


def test_quarantine_stops_all_later_l5_activity(tmp_path):
    aios, outside = store(tmp_path)
    planted_batch(aios, "batch-a", [("x.tmp", outside / "victim.json", PAYLOAD)])
    assert_untracked_quarantined(aios, "batch-a")
    with pytest.raises(m.LedgerBlockedError):
        m.commit_batch(str(aios), [("entities/z.json", {"a": 1})])
    assert not (aios / "entities" / "z.json").exists()


def test_planted_valid_looking_batch_is_not_rolled_forward(tmp_path):
    """Formerly 'valid batch still rolls forward': an unkeyed self-consistent
    journal is NOT authorisation (audit F03-1)."""
    aios, _ = store(tmp_path)
    planted_batch(aios, "batch-a", [("x.tmp", aios / "entities" / "sub" / "x.json", PAYLOAD)])
    assert_untracked_quarantined(aios, "batch-a")
    assert not (aios / "entities" / "sub" / "x.json").exists()


def test_authorised_inflight_batch_rolls_forward(tmp_path, monkeypatch):
    aios, _ = store(tmp_path)
    inflight(aios, [("entities/sub/x.json", {"a": 1}), ("entities/y.json", {"b": 2})], monkeypatch)
    m.recover_pending(str(aios))
    assert (aios / "entities" / "sub" / "x.json").read_bytes() == m.canonical_json({"a": 1}).encode() + b"\n"
    assert (aios / "entities" / "y.json").is_file()
    assert m.unresolved_quarantine(str(aios)) == [] and state(aios)["phase"] == "IDLE"
    assert os.listdir(aios / ".staging") == []


def test_valid_commit_with_nested_destination(tmp_path):
    aios, _ = store(tmp_path)
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
