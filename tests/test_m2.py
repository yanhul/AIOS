"""M2 test suite: authority / verification foundation.

Every test inspects actual persisted state under a temp ``.aios`` tree
(files on disk), never mock return values. RX50-style sources are
synthetic fixtures inside temp dirs; the real repository is never touched.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import reconcile as rcn  # noqa: E402
from core.contradictions import detect_cross_file_contradictions  # noqa: E402
from core.mutation import TransitionError, apply_mutations  # noqa: E402
from core.snapshot import create_snapshot  # noqa: E402
from core.verification import (  # noqa: E402
    OUTCOME_UNSUPPORTED,
    OUTCOME_VERIFIED,
    VerificationError,
    apply_verification,
)

ACTOR = "test:m2"
VERIFIER_A = "verifier:a"
VERIFIER_B = "verifier:b"


def make_entity(etype="EVIDENCE", eid="EV-01", status="VERIFIED", **over):
    ent = {
        "entity_type": etype,
        "entity_id": eid,
        "statement": "supply voltage",
        "status": status,
        "source_file": "evidence/EVIDENCE_REGISTER.md",
        "source_line": 13,
        "source_text": "| EV-01 | supply voltage | 5 V | datasheet | VERIFIED |",
        "classification": etype,
        "imported_at": "2026-08-23T00:00:00Z",
        "snapshot_id": "SNAP-T1",
    }
    ent.update(over)
    return ent


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aios_m2_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.aios = os.path.join(self.tmp, ".aios")

    # -- persisted-state helpers ------------------------------------------
    @staticmethod
    def _load(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _write(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)

    def commit(self, ents, notice=None):
        return apply_mutations(
            self.aios, ents, ACTOR,
            notice_factory=(lambda n: notice) if notice else None)

    def entity_files(self, dirname):
        d = os.path.join(self.aios, dirname)
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def event_files(self):
        return self.entity_files("events")

    def verification_records(self):
        out = {}
        d = os.path.join(self.aios, "verifications")
        for fn in self.entity_files("verifications"):
            rec = self._load(os.path.join(d, fn))
            out[rec["verification_id"]] = rec
        return out

    def seed_evidence_and_decision(self):
        self.commit([
            make_entity(),
            make_entity(eid="EV-02", statement="off leakage",
                        source_text="| EV-02 | off leakage | 100 nA | d | VERIFIED |"),
            make_entity(etype="DECISION", eid="D-01", status="LOCKED",
                        statement="Use 50 channels",
                        source_file="decisions/DECISION_REGISTER.md",
                        source_text="| D-01 | Use 50 channels | LOCKED | owner |"),
        ])

    def seed_source_tree(self):
        src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(src, "decisions"))
        os.makedirs(os.path.join(src, "evidence"))
        with open(os.path.join(src, "decisions", "DECISION_REGISTER.md"),
                  "w", encoding="utf-8") as fh:
            fh.write("| ID | Statement | Status | Basis |\n|---|---|---|---|\n"
                     "| D-01 | Use 50 channels | LOCKED | owner |\n")
        with open(os.path.join(src, "evidence", "EVIDENCE_REGISTER.md"),
                  "w", encoding="utf-8") as fh:
            fh.write("| ID | Fact | Value | Source | Status |\n"
                     "|---|---|---|---|---|\n"
                     "| EV-01 | supply | 5 V | datasheet | VERIFIED |\n")
        return src

    @staticmethod
    def tree_bytes(root):
        snap = {}
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                with open(p, "rb") as fh:
                    snap[os.path.relpath(p, root)] = fh.read()
        return snap

    def findings(self, rep, prefix):
        return [f for f in rep["findings"] if f["check"].startswith(prefix)]

    def imported_event_for(self, entity_id):
        edir = os.path.join(self.aios, "events")
        for fn in os.listdir(edir):
            obj = self._load(os.path.join(edir, fn))
            if (obj.get("action") == "entity.imported"
                    and obj.get("entity_id") == entity_id):
                return fn, obj
        return None, None


# ---------------------------------------------------------------------------
# Phase 1 — snapshot semantics
# ---------------------------------------------------------------------------

class TestSnapshotSemantics(Base):
    def test_1_uncommitted_snapshot_is_not_committed(self):
        sdir = os.path.join(self.aios, "snapshots")
        sid, _ = create_snapshot(sdir, inventory=[], entities=[],
                                 contradictions=[], unresolved=[],
                                 metadata={}, snapshot_id="SNAP-OBS1")
        status, _ = rcn.snapshot_status(self.aios, sid)
        self.assertEqual(status, "OBSERVED")
        meta = self._load(os.path.join(sdir, sid, "meta.json"))
        self.assertEqual(meta["status"], "OBSERVED")

    def test_1b_committed_after_successful_pipeline_notice(self):
        sid, _ = create_snapshot(os.path.join(self.aios, "snapshots"),
                                 inventory=[], entities=[], contradictions=[],
                                 unresolved=[], metadata={},
                                 snapshot_id="SNAP-C1")
        self.commit([make_entity()],
                    notice={"type": "snapshot.created", "project_id": "T",
                            "snapshot_id": sid, "entities_written": 1})
        status, detail = rcn.snapshot_status(self.aios, sid)
        self.assertEqual(status, "COMMITTED")
        self.assertTrue(str(detail).endswith(".json"))

    def test_2_rejected_mutation_leaves_no_committed_state(self):
        sid, _ = create_snapshot(os.path.join(self.aios, "snapshots"),
                                 inventory=[], entities=[], contradictions=[],
                                 unresolved=[], metadata={},
                                 snapshot_id="SNAP-R1")
        with self.assertRaises(Exception):
            self.commit([make_entity(eid="BAD ID")],
                        notice={"type": "snapshot.created",
                                "snapshot_id": sid})
        self.assertEqual(rcn.snapshot_status(self.aios, sid)[0], "OBSERVED")
        self.assertEqual(self.entity_files("decisions"), [])
        evt_like = [f for f in self.event_files() if f.startswith("EVT-")]
        self.assertEqual(evt_like, [],
                         "rejected batch must leave no audit events")


# ---------------------------------------------------------------------------
# Phase 2 — reconciliation A/B/C/D/F/G + E
# ---------------------------------------------------------------------------

class TestReconciliation(Base):
    def setUp(self):
        super().setUp()
        self.seed_evidence_and_decision()

    def test_clean_store_is_valid(self):
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "VALID", rep["findings"])

    def test_3_entity_without_event_detected(self):
        fn, _ = self.imported_event_for("EV-01")
        self.assertIsNotNone(fn)
        os.unlink(os.path.join(self.aios, "events", fn))
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "INCONSISTENT")
        self.assertTrue(self.findings(rep, "A.entity_without_event"))

    def test_4_event_without_entity_detected(self):
        os.unlink(os.path.join(self.aios, "decisions", "D-01.json"))
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "INCONSISTENT")
        self.assertTrue(self.findings(rep, "B.event_without_entity"))

    def test_5_modified_event_detected_as_corrupted(self):
        edir = os.path.join(self.aios, "events")
        fn, obj = self.imported_event_for("EV-01")
        path = os.path.join(edir, fn)
        obj["status"] = "TAMPERED"          # content changed...
        self._write(path, obj)              # ...stale event_id -> digest break
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "CORRUPTED")
        self.assertTrue(self.findings(rep, "D.event_digest"))

    def test_6_modified_entity_detected_as_pairing_mismatch(self):
        path = os.path.join(self.aios, "evidence", "EV-01.json")
        ent = self._load(path)
        ent["statement"] = "tampered statement"
        self._write(path, ent)
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "INCONSISTENT")
        self.assertTrue(self.findings(rep, "C.pairing_mismatch"))

    def test_12_contradiction_remains_unresolved(self):
        src = os.path.join(self.tmp, "rx")
        os.makedirs(os.path.join(src, "decisions"))
        os.makedirs(os.path.join(src, "evidence"))
        with open(os.path.join(src, "decisions", "DECISION_REGISTER.md"),
                  "w", encoding="utf-8") as fh:
            fh.write("| ID | Statement | Status | Basis |\n|---|---|---|---|\n"
                     "| D-77 | a | LOCKED | x |\n")
        with open(os.path.join(src, "evidence", "EVIDENCE_REGISTER.md"),
                  "w", encoding="utf-8") as fh:
            fh.write("| ID | Fact | Value | Source | Status |\n"
                     "|---|---|---|---|---|\n"
                     "| D-77 | a | b | c | OPEN |\n")
        con = detect_cross_file_contradictions(src)
        self.assertEqual(len(con), 1)
        self.assertEqual(con[0]["status"], "unresolved")

    def test_14_corrupt_transaction_state_detected(self):
        stg = os.path.join(self.aios, ".staging", "batch-garbage")
        os.makedirs(stg)
        with open(os.path.join(stg, "journal.json"), "w") as fh:
            fh.write("{not json")
        orphan = os.path.join(self.aios, ".staging", "batch-orphan")
        os.makedirs(orphan)
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "CORRUPTED")
        self.assertTrue(self.findings(rep, "F.corrupt_journal"))
        self.assertTrue(self.findings(rep, "F.orphan_staging"))

    def test_E_committed_snapshot_missing_entity_flagged(self):
        sid = "SNAP-E1"
        create_snapshot(os.path.join(self.aios, "snapshots"), inventory=[],
                        entities=[{"entity_type": "DECISION",
                                   "entity_id": "D-99",
                                   "snapshot_id": sid}],
                        contradictions=[], unresolved=[], metadata={},
                        snapshot_id=sid)
        self.commit([], notice={"type": "snapshot.created",
                                "project_id": "T", "snapshot_id": sid})
        self.assertEqual(rcn.snapshot_status(self.aios, sid)[0], "COMMITTED")
        rep = rcn.reconcile(self.aios)
        self.assertTrue(self.findings(rep, "E.committed_snapshot_missing_entity"))

    def test_observed_snapshot_makes_no_claims(self):
        sid = "SNAP-OBS9"
        create_snapshot(os.path.join(self.aios, "snapshots"), inventory=[],
                        entities=[{"entity_type": "DECISION",
                                   "entity_id": "D-99",
                                   "snapshot_id": sid}],
                        contradictions=[], unresolved=[], metadata={},
                        snapshot_id=sid)
        rep = rcn.reconcile(self.aios)
        self.assertFalse(self.findings(rep, "E.committed_snapshot_missing_entity"))


# ---------------------------------------------------------------------------
# Phases 3–6 — verification, evidence, authority, transitions
# ---------------------------------------------------------------------------

class TestVerification(Base):
    def setUp(self):
        super().setUp()
        self.seed_evidence_and_decision()

    def verification_events(self):
        out = []
        edir = os.path.join(self.aios, "events")
        for fn in os.listdir(edir):
            obj = self._load(os.path.join(edir, fn))
            if obj.get("action") == "verification.recorded":
                out.append(obj)
        return out

    def test_15_valid_verification_succeeds(self):
        res = apply_verification(self.aios, "DECISION", "D-01",
                                 [["EVIDENCE", "EV-01"]], VERIFIER_A)
        self.assertEqual(res["outcome"], OUTCOME_VERIFIED)
        recs = self.verification_records()
        self.assertEqual(len(recs), 1)
        rec = list(recs.values())[0]
        self.assertEqual(rec["authority"], "AIOS_VERIFICATION")
        self.assertEqual(rec["resolved_evidence_ids"], ["EV-01"])
        evs = self.verification_events()
        self.assertEqual([e["verification_id"] for e in evs],
                         [rec["verification_id"]])
        self.assertEqual(rcn.reconcile(self.aios)["overall"], "VALID")

    def test_16_exact_replay_is_idempotent(self):
        args = ("DECISION", "D-01", [["EVIDENCE", "EV-01"]])
        r1 = apply_verification(self.aios, *args, verifier=VERIFIER_A)
        events_after_first = len(self.event_files())
        r2 = apply_verification(self.aios, *args, verifier=VERIFIER_A)
        self.assertFalse(r1["replayed"])
        self.assertTrue(r2["replayed"])
        self.assertEqual(len(self.verification_records()), 1)
        self.assertEqual(len(self.event_files()), events_after_first,
                         "replay must not add audit events")

    def test_17_different_verifier_creates_distinct_append_only_record(self):
        args = ("DECISION", "D-01", [["EVIDENCE", "EV-01"]])
        ra = apply_verification(self.aios, *args, verifier=VERIFIER_A)
        rb = apply_verification(self.aios, *args, verifier=VERIFIER_B)
        self.assertNotEqual(ra["verification_id"], rb["verification_id"])
        recs = self.verification_records()
        self.assertEqual(len(recs), 2)
        self.assertEqual({r["verifier"] for r in recs.values()},
                         {VERIFIER_A, VERIFIER_B})
        ra2 = apply_verification(self.aios, *args, verifier=VERIFIER_A)
        self.assertTrue(ra2["replayed"])

    def test_7_dangling_evidence_reference_yields_unsupported(self):
        res = apply_verification(self.aios, "DECISION", "D-01",
                                 [["EVIDENCE", "EV-999"]], VERIFIER_A)
        self.assertEqual(res["outcome"], OUTCOME_UNSUPPORTED)
        rec = list(self.verification_records().values())[0]
        self.assertEqual(rec["unresolved_refs"], [["EVIDENCE", "EV-999"]])

    def test_8_verified_without_evidence_is_impossible(self):
        res = apply_verification(self.aios, "DECISION", "D-01", [],
                                 VERIFIER_A)
        self.assertEqual(res["outcome"], OUTCOME_UNSUPPORTED)
        for bad in ("EV-01", ["EV-01"], [["FOO", "X"]],
                    [["EVIDENCE", "X"]], [["EVIDENCE", 1]]):
            with self.assertRaises(VerificationError):
                apply_verification(self.aios, "DECISION", "D-01", bad,
                                   VERIFIER_A)
        # The []-refs attempt IS persisted (append-only audit of attempts);
    # malformed shapes are rejected before persistence. Nothing VERIFIED.
        recs = self.verification_records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(list(recs.values())[0]["outcome"],
                         OUTCOME_UNSUPPORTED)

    def test_9_imported_verified_text_is_not_aios_verification(self):
        path = os.path.join(self.aios, "evidence", "EV-01.json")
        before = open(path, "rb").read()
        res = apply_verification(self.aios, "EVIDENCE", "EV-01", [],
                                 VERIFIER_A)
        self.assertEqual(res["outcome"], OUTCOME_UNSUPPORTED,
                         "subject's imported 'VERIFIED' text must not count "
                         "as evidence")
        self.assertEqual(open(path, "rb").read(), before)
        ent = self._load(path)
        self.assertNotIn("aios_verification",
                         {k.lower() for k in ent})

    def test_10_verification_event_is_paired_and_auditable(self):
        res = apply_verification(self.aios, "DECISION", "D-01",
                                 [["EVIDENCE", "EV-01"],
                                  ["EVIDENCE", "EV-02"]], VERIFIER_A)
        evs = [e for e in self.verification_events()
               if e["verification_id"] == res["verification_id"]]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["kind"], "mutation")
        self.assertEqual(evs[0]["actor"], VERIFIER_A)
        self.assertEqual(evs[0]["outcome"], "VERIFIED")

    def test_13_invalid_verification_transition_blocked(self):
        args = ("DECISION", "D-01", [["EVIDENCE", "EV-01"]])
        first = apply_verification(self.aios, *args, verifier=VERIFIER_A)
        vdir = os.path.join(self.aios, "verifications")
        (fname,) = os.listdir(vdir)
        path = os.path.join(vdir, fname)
        rec = self._load(path)
        rec["outcome"] = (OUTCOME_UNSUPPORTED
                          if rec["outcome"] == OUTCOME_VERIFIED
                          else OUTCOME_VERIFIED)
        self._write(path, rec)
        with self.assertRaises(TransitionError):
            apply_verification(self.aios, *args, verifier=VERIFIER_A)
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "CORRUPTED")
        self.assertTrue(self.findings(rep, "D.corrupt_verification"))
        self.assertNotEqual(first["outcome"], rec["outcome"])

    def test_missing_actor_rejected(self):
        with self.assertRaises(Exception):
            apply_verification(self.aios, "DECISION", "D-01",
                               [["EVIDENCE", "EV-01"]], "")
        self.assertEqual(self.verification_records(), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
