# AIOS-CONTRACT: Shared L5 fixtures: planted (untrusted) vs authorised in-flight residue.
# AIOS-REGRESSION: Tests that exercised forged journals instead of the trust anchor.
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Helper module; contracts asserted by importing tests.
# AIOS-BASELINE: audit baseline 74941fff2d28e1955c4b1ca263a2d866ac90d56d
"""Shared helpers for L5 (core.mutation) security regression tests.

Two kinds of residue are produced:

* ``planted_batch``: what a staging writer can create on its own. It is never
  referenced by the protected L5 state, so it must never be executed.
* ``inflight``: a REAL transaction committed by L5 and interrupted after its
  commit point (an injected I/O error before the first destination install).
  Attacks against roll-forward mutate this residue, so they exercise the
  verification of a transaction the trust anchor actually authorised.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

from core import mutation as m

PAYLOAD = b"attacker-controlled\n"


def store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_bytes(b"original\n")
    return aios, outside


def planted_batch(aios, name, ops_spec, fmt=2):
    """Attacker-planted batch with a self-consistent (unkeyed) v2 journal."""
    batch = aios / ".staging" / name
    batch.mkdir(parents=True, exist_ok=True)
    ops = []
    for tmp_name, dest, payload in ops_spec:
        tmp = batch / tmp_name
        data = payload if payload is not None else PAYLOAD
        if payload is not None:
            tmp.write_bytes(payload)
        ops.append({"tmp": str(tmp), "dest": str(dest), "digest": hashlib.sha256(data).hexdigest()})
    body = hashlib.sha256(m.canonical_json({"batch_id": name, "ops": ops}).encode()).hexdigest()
    j = {"format": fmt, "batch_id": name, "ops": ops, "body_digest": body}
    (batch / "journal.v2.json").write_text(m.canonical_json(j))
    return batch


def state(aios):
    return json.loads(Path(aios, ".l5", "state.json").read_text())


def quarantine_ids(aios, prefix=None):
    q = Path(aios, ".quarantine")
    if not q.is_dir():
        return []
    names = sorted(os.listdir(q))
    return [n for n in names if prefix is None or n.startswith(prefix + "~")]


def assert_untracked_quarantined(aios, name):
    """A planted staging entry is quarantined as evidence and never executed."""
    with pytest.raises(m.LedgerBlockedError, match="untracked staging entries quarantined"):
        m.recover_pending(str(aios))
    qids = quarantine_ids(aios, name)
    assert len(qids) == 1, qids
    assert qids[0] in m.unresolved_quarantine(str(aios))
    assert not os.path.lexists(Path(aios, ".staging", name))
    meta = json.loads(Path(aios, ".quarantine", qids[0], "QUARANTINE.json").read_text())
    assert meta["classification"] == "UNTRACKED_STAGING_ENTRY" and meta["staging_entry"] == name
    with pytest.raises(m.LedgerBlockedError):   # stays blocked until operator resolution
        m.recover_pending(str(aios))
    return qids[0]


def inflight(aios, payloads, monkeypatch, fail_at=1):
    """Commit ``payloads`` and crash (EIO) before install number ``fail_at``.

    Returns the batch directory Path. Protected state is left APPLYING.
    """
    real = m._apply_op
    calls = {"n": 0}

    def crash(*a, **k):
        calls["n"] += 1
        if calls["n"] >= fail_at:
            raise OSError(5, "injected crash before install")
        return real(*a, **k)

    with monkeypatch.context() as mp:
        mp.setattr(m, "_apply_op", crash)
        with pytest.raises(m.RecoveryIncompleteError):
            m.commit_batch(str(aios), payloads)
    st = state(aios)
    assert st["phase"] == "APPLYING", st
    return Path(aios, ".staging", st["txn"]["batch_name"])


def staged_files(batch):
    return sorted(p for p in Path(batch).iterdir() if p.name.endswith(".tmp") and p.name != "journal.v3.json.tmp")


def journal(batch):
    return json.loads(Path(batch, "journal.v3.json").read_text())


def assert_txn_quarantined(aios, classification=None):
    with pytest.raises(m.LedgerBlockedError, match="quarantined") as exc:
        m.recover_pending(str(aios))
    if classification:
        assert classification in str(exc.value)
    st = state(aios)
    assert st["phase"] == "QUARANTINED", st
    qid = st["txn"]["quarantine_id"]
    assert qid in m.unresolved_quarantine(str(aios))
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    return qid


def resolve(aios, qid):
    """Operator resolution: the service uid writes a protected record."""
    p = Path(aios, ".quarantine", qid, "RESOLVED.json")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b'{"resolved_by":"operator"}')
    os.close(fd)


def tree(root):
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
