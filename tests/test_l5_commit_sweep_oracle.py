"""Adversarial tests for the L5 commit crash-sweep oracle (F-NEW-01).

Each negative case is a state the protocol in core/mutation.py cannot produce;
the oracle (scripts/l5_commit_oracle.py) must reject it. Several cases are
also shown to PASS the previous (destination-only, content-hash) oracle, which
is the gap being closed.
"""
import copy
import hashlib
import json
import os
import stat
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import l5_commit_oracle as oracle  # noqa: E402
from core import mutation as m  # noqa: E402

OLD = [("decisions/a.json", {"v": 0}), ("decisions/b.json", {"v": 0})]
NEW = [("decisions/a.json", {"v": 1}), ("decisions/b.json", {"v": 1})]
SETS = {"OLD": OLD, "NEW": NEW}


def legacy_snapshot(aios):
    """Verbatim logic of the pre-fix sweep snapshot (d10803f): files only,
    content via open() (follows symlinks), no type/mode/nlink/directories."""
    snap = {}
    for dp, dns, fns in os.walk(aios):
        rel = os.path.relpath(dp, aios)
        if rel.split(os.sep)[0] in (".staging", ".quarantine", ".l5"):
            dns[:] = []
            continue
        for f in fns:
            p = os.path.join(dp, f)
            snap[os.path.relpath(p, aios)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return snap


def legacy_commit_accepts(st, lsnap, legacy_old, legacy_new):
    """Pre-fix commit oracle (OLD_OR_NEW branch of check()) given a recovered store."""
    return (lsnap in (legacy_old, legacy_new) and st["phase"] == "IDLE" and st["txn"] is None
            and st["last_finalized_seq"] < st["next_seq"])


def _state(aios):
    with open(os.path.join(aios, ".l5", "state.json")) as fh:
        return json.load(fh)


def _store(tmp_path, name, payload_sets):
    aios = str(tmp_path / name / ".aios")
    for p in payload_sets:
        m.commit_batch(aios, p)
    return aios


@pytest.fixture
def env(tmp_path):
    old = _store(tmp_path, "old", [OLD])
    new = _store(tmp_path, "new", [OLD, NEW])
    st = _state(old)
    base = {"N": st["next_seq"], "L": st["last_finalized_seq"], "store_id": st["store_id"],
            "old": oracle.snapshot(old), "new": oracle.snapshot(new),
            "new_payloads": [r for r, _ in NEW]}
    return {"old": old, "new": new, "base": base, "tmp": tmp_path,
            "legacy_old": legacy_snapshot(old), "legacy_new": legacy_snapshot(new)}


def _idle(base, ns, lf):
    return {"format": 1, "store_id": base["store_id"], "next_seq": ns, "last_finalized_seq": lf,
            "phase": "IDLE", "txn": None}


def _post(env, cls, st, snap):
    return oracle.check_post(cls, st, snap, [], [], ["ok"] * 3, env["base"], SETS)[1]


# --------------------------------------------------------------------------
# Positive controls: the real protocol states are accepted
# --------------------------------------------------------------------------

def test_real_old_and_new_pass(env):
    b = env["base"]
    assert _post(env, "NOT_ALLOCATED", _idle(b, b["N"], b["L"]), b["old"]) == []
    assert _post(env, "PREPARED", _idle(b, b["N"] + 1, b["L"]), b["old"]) == []
    assert _post(env, "COMPLETED", _idle(b, b["N"] + 1, b["N"]), b["new"]) == []
    assert oracle.policy_problems(b["old"], OLD) == [] and oracle.policy_problems(b["new"], NEW) == []


def _crash_after_n_applies(aios, n):
    real, c = m._apply_op, {"n": 0}

    def f(*a, **k):
        c["n"] += 1
        if c["n"] > n:
            raise KeyboardInterrupt()
        return real(*a, **k)
    m._apply_op = f
    try:
        m.commit_batch(aios, NEW)
    except BaseException:
        pass
    finally:
        m._apply_op = real


def _pre(env, aios):
    st = _state(aios)
    txn = st["txn"]
    journal = None
    if txn:
        jp = os.path.join(aios, ".staging", txn["batch_name"], oracle.JOURNAL_NAME)
        if os.path.exists(jp):
            journal = open(jp, "rb").read()
    return st, journal, sorted(os.listdir(os.path.join(aios, ".staging")))


def test_real_partial_applying_classified_and_recovered(env):
    aios = env["old"]
    _crash_after_n_applies(aios, 1)
    st, journal, staging = _pre(env, aios)
    cls, probs = oracle.classify_pre(st, oracle.snapshot(aios), staging, env["base"], journal)
    assert (cls, probs) == ("APPLYING", [])
    m.recover_pending(aios)
    assert _post(env, cls, _state(aios), oracle.snapshot(aios)) == []


# --------------------------------------------------------------------------
# OLD destination with sequence/finalization advanced incorrectly
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cls", ["NOT_ALLOCATED", "PREPARED", "COMPLETED", "APPLYING"])
def test_old_tree_with_finalized_seq_rejected(env, cls):
    b = env["base"]
    st = _idle(b, b["N"] + 1, b["N"])        # claims seq N finalized
    probs = _post(env, cls, st, b["old"])
    assert any("OLD destination with last_finalized_seq" in p for p in probs), probs
    # the pre-fix oracle accepted exactly this combination
    assert legacy_commit_accepts(st, env["legacy_old"], env["legacy_old"], env["legacy_new"])


def test_old_tree_with_next_seq_allocated_twice_rejected(env):
    b = env["base"]
    st = _idle(b, b["N"] + 2, b["L"])
    probs = _post(env, "PREPARED", st, b["old"])
    assert any("next_seq" in p for p in probs), probs
    assert legacy_commit_accepts(st, env["legacy_old"], env["legacy_old"], env["legacy_new"])


def test_old_tree_after_prepared_but_next_seq_not_advanced_rejected(env):
    b = env["base"]
    probs = _post(env, "PREPARED", _idle(b, b["N"], b["L"]), b["old"])
    assert any("PREPARED: next_seq" in p for p in probs), probs


def test_pre_idle_old_tree_with_finalized_counters_rejected(env):
    b = env["base"]
    cls, probs = oracle.classify_pre(_idle(b, b["N"] + 1, b["N"]), b["old"], [], b)
    assert cls == "COMPLETED" and any("NEW (COMPLETED)" in p for p in probs), probs


# --------------------------------------------------------------------------
# NEW destination without the required sequence/finalization transition
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cls", ["COMMIT_POINT", "APPLYING", "FINALIZED", "CLEANUP", "COMPLETED"])
def test_new_tree_without_finalization_rejected(env, cls):
    b = env["base"]
    st = _idle(b, b["N"] + 1, b["L"])        # nothing finalized
    probs = _post(env, cls, st, b["new"])
    assert any("NEW destination with last_finalized_seq" in p for p in probs), probs
    assert legacy_commit_accepts(st, env["legacy_new"], env["legacy_old"], env["legacy_new"])


def test_new_tree_when_commit_point_not_reached_rejected(env):
    b = env["base"]
    for cls in ("NOT_ALLOCATED", "PREPARED"):
        probs = _post(env, cls, _idle(b, b["N"] + 1, b["N"]), b["new"])
        assert any("destination tree != OLD" in p for p in probs), (cls, probs)


def test_pre_idle_new_tree_without_allocation_impossible(env):
    b = env["base"]
    cls, probs = oracle.classify_pre(_idle(b, b["N"] + 1, b["L"]), b["new"], [], b)
    assert cls is None and any("impossible IDLE counters" in p for p in probs)
    cls, probs = oracle.classify_pre(_idle(b, b["N"], b["L"]), b["new"], [], b)
    assert cls == "NOT_ALLOCATED" and any("destination tree != OLD" in p for p in probs)


# --------------------------------------------------------------------------
# Inconsistent phase / transaction metadata (pre-recovery)
# --------------------------------------------------------------------------

def _crashed_state(env, phase_to_crash_on):
    """Real store crashed right before the given state publication."""
    aios = env["old"]
    real = m._state_replace

    def f(src, dst, **k):
        fd = os.open(src, os.O_RDONLY, dir_fd=k["src_dir_fd"])
        try:
            ph = json.loads(os.read(fd, 1 << 16))["phase"]
        finally:
            os.close(fd)
        if ph == phase_to_crash_on:
            raise KeyboardInterrupt()
        return real(src, dst, **k)
    m._state_replace = f
    try:
        m.commit_batch(aios, NEW)
    except BaseException:
        pass
    finally:
        m._state_replace = real
    return aios


def test_real_commit_point_accepted_then_tampered_rejected(env):
    aios = _crashed_state(env, "APPLYING")
    st, journal, staging = _pre(env, aios)
    b, snap = env["base"], oracle.snapshot(aios)
    assert oracle.classify_pre(st, snap, staging, b, journal) == ("COMMIT_POINT", [])
    cases = {
        "lf advanced": dict(st, last_finalized_seq=b["N"]),
        "next_seq not advanced": dict(st, next_seq=b["N"]),
        "txn seq wrong": dict(st, txn=dict(st["txn"], seq=b["N"] - 1 or 99)),
        "unbound": dict(st, txn=dict(st["txn"], journal_sha256=None)),
        "quarantine id": dict(st, txn=dict(st["txn"], quarantine_id="x")),
        "store id": dict(st, store_id="0" * 32),
    }
    for label, bad in cases.items():
        assert oracle.classify_pre(bad, snap, staging, b, journal)[1], label
    # journal tampering / foreign batch / missing batch
    assert oracle.classify_pre(st, snap, staging, b, journal + b" ")[1]
    assert oracle.classify_pre(st, snap, staging + ["batch-" + "f" * 32], b, journal)[1]
    assert oracle.classify_pre(st, snap, [], b, None)[1]
    # destination already NEW while only COMMIT_POINT is durable (writes precede APPLYING)
    assert any("must be untouched" in p for p in oracle.classify_pre(st, b["new"], staging, b, journal)[1])


def test_phase_txn_inconsistencies_rejected(env):
    b = env["base"]
    txn = {"seq": b["N"], "batch_id": "a" * 32, "batch_name": "batch-" + "a" * 32,
           "batch_dev": None, "batch_ino": None, "journal_sha256": None, "quarantine_id": None}
    prepared = {"format": 1, "store_id": b["store_id"], "next_seq": b["N"] + 1,
                "last_finalized_seq": b["L"], "phase": "PREPARED", "txn": txn}
    assert oracle.classify_pre(prepared, b["old"], [], b) == ("PREPARED", [])
    bad = copy.deepcopy(prepared)
    bad["txn"].update(batch_dev=1, batch_ino=2, journal_sha256="0" * 64)
    assert any("journal binding present" in p for p in oracle.classify_pre(bad, b["old"], [], b)[1])
    assert oracle.classify_pre(prepared, b["new"], [], b)[1]               # PREPARED wrote destinations
    fin = dict(prepared, phase="FINALIZED", txn=dict(txn, batch_dev=1, batch_ino=2, journal_sha256="0" * 64))
    assert any("last_finalized_seq" in p for p in oracle.classify_pre(fin, b["new"], [], b)[1])
    assert oracle.classify_pre(dict(fin, last_finalized_seq=b["N"]), b["new"], [], b) == ("FINALIZED", [])
    assert oracle.classify_pre(dict(fin, phase="CLEANUP", last_finalized_seq=b["N"]), b["old"], [], b)[1]
    assert oracle.classify_pre(_idle(b, b["N"], b["L"]) | {"txn": txn}, b["old"], [], b)[1]
    assert oracle.classify_pre(dict(prepared, phase="BOGUS"), b["old"], [], b)[0] is None
    assert oracle.classify_pre(None, b["old"], [], b)[0] is None
    with pytest.raises(oracle.Unknown):
        oracle.classify_pre(dict(prepared, phase="QUARANTINED"), b["old"], [], b)
    with pytest.raises(oracle.Unknown):
        oracle.expected_final("QUARANTINED", b)


def test_post_recovery_residue_and_phase_rejected(env):
    b = env["base"]
    ok = _idle(b, b["N"] + 1, b["N"])
    assert oracle.check_post("COMPLETED", ok, b["new"], ["batch-x"], [], ["ok"] * 3, b, SETS)[1]
    assert oracle.check_post("COMPLETED", ok, b["new"], [], ["q"], ["ok"] * 3, b, SETS)[1]
    assert oracle.check_post("COMPLETED", ok, b["new"], [], [], ["ok", "LedgerBlockedError"], b, SETS)[1]
    assert oracle.check_post("COMPLETED", dict(ok, phase="CLEANUP"), b["new"], [], [], ["ok"], b, SETS)[1]
    assert oracle.check_post("COMPLETED", dict(ok, store_id="1" * 32), b["new"], [], [], ["ok"], b, SETS)[1]


# --------------------------------------------------------------------------
# Filesystem object type / metadata substitutions with equivalent content
# --------------------------------------------------------------------------

def _outside_copy(env, rel, aios):
    p = str(env["tmp"] / ("outside-" + rel.replace("/", "_")))
    with open(os.path.join(aios, rel), "rb") as src, open(p, "wb") as dst:
        dst.write(src.read())
    os.chmod(p, 0o644)
    return p


def test_file_replaced_by_symlink_with_same_content_rejected(env):
    aios, rel = env["new"], "decisions/a.json"
    target = _outside_copy(env, rel, aios)
    os.unlink(os.path.join(aios, rel))
    os.symlink(target, os.path.join(aios, rel))
    assert legacy_snapshot(aios) == env["legacy_new"]          # pre-fix oracle blind to it
    snap = oracle.snapshot(aios)
    assert snap[rel] == ("lnk", target)
    probs = _post(env, "COMPLETED", _idle(env["base"], env["base"]["N"] + 1, env["base"]["N"]), snap)
    assert any("destination tree != NEW" in p for p in probs)
    assert any("object type lnk" in p for p in probs) and any("not a regular file" in p for p in probs)


def test_directory_replaced_by_symlink_to_equivalent_dir_rejected(env):
    aios = env["new"]
    empty = env["tmp"] / "outside-empty-dir"
    empty.mkdir(mode=0o755)
    d = os.path.join(aios, "tasks")
    os.rmdir(d)
    os.symlink(str(empty), d)
    assert legacy_snapshot(aios) == env["legacy_new"]
    probs = oracle.tree_problems(oracle.snapshot(aios), env["base"]["new"], "NEW")
    assert probs and oracle.snapshot(aios)["tasks"][0] == "lnk"


def test_hardlinked_file_same_content_rejected(env):
    aios, rel = env["new"], "decisions/a.json"
    os.link(os.path.join(aios, rel), str(env["tmp"] / "outside-hardlink"))
    assert legacy_snapshot(aios) == env["legacy_new"]
    probs = oracle.policy_problems(oracle.snapshot(aios), NEW)
    assert any("nlink 2" in p for p in probs)
    assert oracle.tree_problems(oracle.snapshot(aios), env["base"]["new"], "NEW")


def test_mode_change_same_content_rejected(env):
    aios, rel = env["new"], "decisions/b.json"
    os.chmod(os.path.join(aios, rel), 0o755)
    assert legacy_snapshot(aios) == env["legacy_new"]
    assert any("mode 0o755" in p for p in oracle.policy_problems(oracle.snapshot(aios), NEW))
    assert oracle.tree_problems(oracle.snapshot(aios), env["base"]["new"], "NEW")


def test_extra_empty_directory_rejected(env):
    aios = env["new"]
    os.mkdir(os.path.join(aios, "decisions", "planted"), 0o755)
    assert legacy_snapshot(aios) == env["legacy_new"]
    assert oracle.tree_problems(oracle.snapshot(aios), env["base"]["new"], "NEW")


def test_fifo_type_change_detected_without_blocking(env):
    """A FIFO would block the pre-fix oracle (open() on it); the new snapshot never opens it."""
    aios, rel = env["new"], "decisions/a.json"
    os.unlink(os.path.join(aios, rel))
    os.mkfifo(os.path.join(aios, rel), 0o644)
    snap = oracle.snapshot(aios)
    assert snap[rel][0] == "other" and stat.S_ISFIFO(snap[rel][1])
    assert any("object type other" in p for p in oracle.policy_problems(snap, NEW))


def test_applying_residue_only_service_tmp_allowed(env):
    b = env["base"]
    good = dict(b["old"])
    good["decisions/a.json"] = b["new"]["decisions/a.json"]
    good["decisions/.b.json." + "c" * 32 + ".l5tmp"] = ("reg", 0o600, 0, 0, 1, 0, "x")
    assert oracle._applying_tree_problems(good, b["old"], b["new"]) == []
    for name, entry in {"decisions/.b.json." + "c" * 32 + ".l5tmp": ("lnk", "/etc/passwd"),
                        "decisions/.zz.json." + "c" * 32 + ".l5tmp": ("reg", 0o600, 0, 0, 1, 0, "x"),
                        "decisions/evil.l5tmp": ("reg", 0o600, 0, 0, 1, 0, "x"),
                        "decisions/.b.json." + "c" * 32 + ".l5tmp ": ("reg", 0o600, 0, 0, 1, 0, "x")}.items():
        bad = dict(b["old"], **{name: entry})
        assert oracle._applying_tree_problems(bad, b["old"], b["new"]), name
    mixed = dict(b["old"], **{"decisions/a.json": ("reg", 0o644, 0, 0, 1, 8, "0" * 64)})
    assert oracle._applying_tree_problems(mixed, b["old"], b["new"])
