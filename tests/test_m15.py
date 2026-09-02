"""M1.5 test suite: writer-enforcement boundary (core.mutation).

Covers requirements A–S of the M1.5 spec: entity contracts, transition
legality, actor identity, deterministic event IDs, idempotent replay,
atomicity under deterministic failure injection, snapshot immutability,
and RX50 read-only preservation.

The invariant auditor below deliberately re-implements pairing logic
instead of importing production helpers, so the tests do not verify the
code with the same code.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import mutation  # noqa: E402
from core.mutation import (  # noqa: E402
    ActorError,
    ContractError,
    StateConflictError,
    TransitionError,
    apply_mutations,
    event_identity,
    recover_pending,
)
from core.snapshot import SnapshotExistsError, create_snapshot  # noqa: E402

ACTOR = "test:m15"

# Independent copy of the layout mapping (do not import production one).
TYPE_DIR = {
    "REQUIREMENT": "requirements",
    "DECISION": "decisions",
    "EVIDENCE": "evidence",
    "ISSUE": "issues",
    "GATE": "issues",
    "CONTRADICTION": "issues",
}


def make_entity(etype="DECISION", eid="D-99", status="LOCKED", **over):
    ent = {
        "entity_type": etype,
        "entity_id": eid,
        "statement": "Use 50 channels",
        "status": status,
        "source_file": "decisions/DECISION_REGISTER.md",
        "source_line": 13,
        "source_text": "| D-99 | Use 50 channels | LOCKED | owner |",
        "classification": etype,
        "imported_at": "2026-08-23T00:00:00Z",
        "snapshot_id": "SNAP-TEST0001",
    }
    ent.update(over)
    return ent


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aios_m15_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.aios = os.path.join(self.tmp, ".aios")

    # -- independent invariant auditor -------------------------------------
    @staticmethod
    def _load_json(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def collect_state(self, aios=None):
        aios = aios or self.aios
        ents, evs = {}, {}
        for dirname in sorted(set(TYPE_DIR.values())):
            d = os.path.join(aios, dirname)
            if not os.path.isdir(d):
                continue
            for fn in os.listdir(d):
                if fn.endswith(".json"):
                    j = self._load_json(os.path.join(d, fn))
                    ents[(j["entity_type"], j["entity_id"])] = j
        edir = os.path.join(aios, "events")
        if os.path.isdir(edir):
            for fn in os.listdir(edir):
                j = self._load_json(os.path.join(edir, fn))
                if j.get("kind") == "mutation":
                    evs[(j["entity_type"], j["entity_id"])] = j
        return ents, evs

    def assert_paired_invariant(self, expected_keys, aios=None):
        """Every entity <-> exactly one mutation event, fields consistent."""
        ents, evs = self.collect_state(aios)
        self.assertEqual(set(ents), set(expected_keys))
        self.assertEqual(set(ents), set(evs), "entity/event pairing violated")
        for key, ent in ents.items():
            ev = evs[key]
            self.assertEqual(ev["status"], ent["status"])
            self.assertEqual(ev["snapshot_id"], ent["snapshot_id"])
            self.assertEqual(ev["actor"], ACTOR)
            logical = {k: v for k, v in ev.items()
                       if k not in ("timestamp_utc", "event_id")}
            self.assertEqual(ev["event_id"], event_identity(logical))

    def entity_path(self, ent, aios=None):
        aios = aios or self.aios
        return os.path.join(aios, TYPE_DIR[ent["entity_type"]],
                            ent["entity_id"] + ".json")

    def event_files(self, aios=None):
        aios = aios or self.aios
        d = os.path.join(aios, "events")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def pending_batches(self, aios=None):
        stg = os.path.join(aios or self.aios, ".staging")
        if not os.path.isdir(stg):
            return []
        return [d for d in os.listdir(stg) if d.startswith("batch-")]


# ---------------------------------------------------------------------------
# A/B/C/D/R. entity contracts
# ---------------------------------------------------------------------------

class TestContracts(Base):
    def test_A_valid_entity_accepted(self):
        res = apply_mutations(self.aios, [make_entity()], ACTOR)
        self.assertEqual(res["applied"], [["DECISION", "D-99"]])
        self.assertTrue(os.path.isfile(self.entity_path(make_entity())))
        self.assert_paired_invariant({("DECISION", "D-99")})

    def test_B_missing_required_field_rejected(self):
        ent = make_entity()
        del ent["source_line"]
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [ent], ACTOR)
        self.assertEqual(self.collect_state()[0], {})

    def test_B2_unexpected_field_rejected(self):
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [make_entity(extra_field=1)], ACTOR)

    def test_C_unknown_entity_type_rejected(self):
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [make_entity(etype="SPECULATION")],
                            ACTOR)

    def test_R_whole_batch_aborts_on_unknown_type(self):
        good = make_entity(eid="D-01")
        bad = make_entity(etype="WISH", eid="W-01")
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [good, bad], ACTOR)
        self.assertEqual(self.collect_state()[0], {},
                         "silent drop must not become partial write")
        self.assertFalse(os.path.exists(os.path.join(self.aios, ".staging")))

    def test_bad_entity_id_format_rejected(self):
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [make_entity(etype="EVIDENCE",
                                                    eid="D-99")], ACTOR)

    def test_classification_mismatch_rejected(self):
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [make_entity(classification="ISSUE")],
                            ACTOR)

    def test_bad_imported_at_rejected(self):
        with self.assertRaises(ContractError):
            apply_mutations(self.aios,
                            [make_entity(imported_at="yesterday")], ACTOR)

    def test_bad_source_line_rejected(self):
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [make_entity(source_line=0)], ACTOR)
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [make_entity(source_line="13")], ACTOR)

    def test_D_invalid_status_rejected(self):
        for bad in ("", "   ", None, 5, "A|B", "line1\nline2", "x" * 600):
            with self.assertRaises((ContractError, TypeError)):
                apply_mutations(self.aios, [make_entity(status=bad)], ACTOR)
        self.assertEqual(self.collect_state()[0], {})


# ---------------------------------------------------------------------------
# E/F. transition legality / K,L. idempotency / tamper detection
# ---------------------------------------------------------------------------

class TestTransitions(Base):
    def test_F_creation_supported(self):
        apply_mutations(self.aios, [make_entity()], ACTOR)
        self.assert_paired_invariant({("DECISION", "D-99")})

    def test_E_status_change_rejected_as_undefined(self):
        apply_mutations(self.aios, [make_entity(status="LOCKED")], ACTOR)
        with self.assertRaises(TransitionError):
            apply_mutations(self.aios, [make_entity(status="OPEN")], ACTOR)
        self.assert_paired_invariant({("DECISION", "D-99")})

    def test_E2_field_change_rejected_as_undefined(self):
        apply_mutations(self.aios, [make_entity(statement="v1")], ACTOR)
        with self.assertRaises(TransitionError):
            apply_mutations(self.aios, [make_entity(statement="v2")], ACTOR)

    def test_K_identical_replay_is_idempotent(self):
        ent = make_entity()
        apply_mutations(self.aios, [ent], ACTOR)
        events_before = self.event_files()
        mtime_before = os.path.getmtime(self.entity_path(ent))
        res = apply_mutations(self.aios, [dict(ent)], "test:m15-again")
        self.assertEqual(res["replayed"], [["DECISION", "D-99"]])
        self.assertEqual(res["applied"], [])
        self.assertEqual(self.event_files(), events_before,
                         "replay must not duplicate events")
        self.assertEqual(os.path.getmtime(self.entity_path(ent)),
                         mtime_before, "replay must not rewrite the entity")

    def test_L_different_mutation_gets_distinct_event(self):
        apply_mutations(self.aios, [make_entity(eid="D-01")], ACTOR)
        apply_mutations(self.aios, [make_entity(eid="D-02")], ACTOR)
        self.assertEqual(len(self.event_files()), 2)
        self.assert_paired_invariant({("DECISION", "D-01"),
                                      ("DECISION", "D-02")})

    def test_tampered_event_detected_on_replay(self):
        ent = make_entity()
        apply_mutations(self.aios, [ent], ACTOR)
        os.unlink(os.path.join(self.aios, "events", self.event_files()[0]))
        with self.assertRaises(StateConflictError):
            apply_mutations(self.aios, [dict(ent)], ACTOR)


# ---------------------------------------------------------------------------
# G/H. actor identity / I/J. deterministic event identity
# ---------------------------------------------------------------------------

class TestActorAndIdentity(Base):
    def test_G_missing_actor_rejected(self):
        for bad in (None, "", "   "):
            with self.assertRaises(ActorError):
                apply_mutations(self.aios, [make_entity()], bad)
        self.assertEqual(self.collect_state()[0], {})

    def test_H_actor_recorded_in_event(self):
        apply_mutations(self.aios, [make_entity()], "agent:explorer#7")
        _, evs = self.collect_state()
        self.assertEqual(evs[("DECISION", "D-99")]["actor"],
                         "agent:explorer#7")

    def test_I_same_logical_event_same_identity(self):
        ev = {"kind": "mutation", "action": "entity.imported", "actor": ACTOR,
              "entity_type": "DECISION", "entity_id": "D-99",
              "status": "LOCKED", "statement": "s",
              "source_file": "f.md", "source_line": 1,
              "snapshot_id": "SNAP-X"}
        e1 = event_identity(ev)
        e2 = event_identity({"timestamp_utc": "2099-01-01T00:00:00Z", **ev})
        self.assertEqual(e1, e2, "timestamp must not affect identity")
        self.assertEqual(len(e1), 64, "full SHA-256 digest width required")

    def test_J_different_values_different_identity(self):
        base = {"kind": "mutation", "action": "entity.imported",
                "actor": ACTOR, "entity_type": "DECISION",
                "entity_id": "D-99", "status": "LOCKED"}
        self.assertNotEqual(event_identity(base),
                            event_identity({**base, "status": "OPEN"}))
        self.assertNotEqual(event_identity(base),
                            event_identity({**base, "actor": "other"}))

    def test_event_names_are_full_hex_sha256(self):
        apply_mutations(self.aios, [make_entity()], ACTOR)
        digest = self.event_files()[0].rsplit("-", 1)[1].split(".")[0]
        self.assertEqual(len(digest), 64)
        int(digest, 16)


# ---------------------------------------------------------------------------
# M/N. atomicity with deterministic failure injection at the commit boundary
# ---------------------------------------------------------------------------

class TestAtomicity(Base):
    @staticmethod
    def _flaky_replace(fail_at):
        calls = {"n": 0}

        def fake(src, dst):
            calls["n"] += 1
            if calls["n"] == fail_at:
                raise RuntimeError(f"injected failure at replace #{fail_at}")
            return os.replace(src, dst)
        return fake

    def test_MN_interrupted_commit_recovers_with_pairing_intact(self):
        ents = [make_entity(eid="D-01"), make_entity(eid="D-02")]
        total_ops = len(ents) * 2  # entity renames + event renames
        for fail_at in range(1, total_ops + 1):
            aios = os.path.join(self.tmp, f"case{fail_at}", ".aios")
            with self.assertRaises(RuntimeError):
                with mock.patch.object(mutation, "_replace",
                                       self._flaky_replace(fail_at)):
                    apply_mutations(aios, [dict(e) for e in ents], ACTOR)
            # interrupted state must be journal-marked pending, never silent
            self.assertEqual(len(self.pending_batches(aios)), 1,
                             f"crash at #{fail_at}: journal must mark pending")
            # roll-forward completes the commit; invariant restored
            recover_pending(aios)
            self.assert_paired_invariant(
                {("DECISION", "D-01"), ("DECISION", "D-02")}, aios)
            # post-recovery replay: fully idempotent, no new files
            res = apply_mutations(aios, [dict(e) for e in ents], ACTOR)
            self.assertEqual(res["applied"], [])
            self.assertEqual(len(res["replayed"]), 2)
            self.assertEqual(self.pending_batches(aios), [])

    def test_failure_before_staging_leaves_disk_untouched(self):
        good = make_entity(eid="D-01")
        bad = make_entity(eid="BAD ID")  # contract failure aborts whole batch
        with self.assertRaises(ContractError):
            apply_mutations(self.aios, [good, bad], ACTOR)
        self.assertEqual(self.collect_state()[0], {})
        self.assertEqual(self.event_files(), [])
        self.assertFalse(os.path.exists(os.path.join(self.aios, ".staging")))

    def test_orphan_staging_without_journal_is_swept(self):
        orphan = os.path.join(self.aios, ".staging", "batch-deadbeef")
        os.makedirs(orphan)
        with open(os.path.join(orphan, "stray.tmp"), "w") as fh:
            fh.write("junk")
        apply_mutations(self.aios, [make_entity()], ACTOR)
        self.assertFalse(os.path.exists(orphan),
                         "pre-journal crash leftovers must be discarded")
        self.assert_paired_invariant({("DECISION", "D-99")})


# ---------------------------------------------------------------------------
# O/P/Q. preserved guarantees + notice-event compatibility
# ---------------------------------------------------------------------------

class TestPreservedBehavior(Base):
    def test_O_snapshot_immutability_intact(self):
        root = os.path.join(self.aios, "snapshots")
        create_snapshot(root, inventory=[], entities=[], contradictions=[],
                        unresolved=[], metadata={}, snapshot_id="SNAP-FIXED")
        with self.assertRaises(SnapshotExistsError):
            create_snapshot(root, inventory=[], entities=[], contradictions=[],
                            unresolved=[], metadata={},
                            snapshot_id="SNAP-FIXED")

    def test_notice_and_mutation_events_coexist(self):
        res = apply_mutations(self.aios, [make_entity()], ACTOR,
                              notice_factory=lambda n: {
                                  "type": "snapshot.created",
                                  "project_id": "RX50",
                                  "snapshot_id": "SNAP-X",
                                  "entities_written": n,
                              })
        self.assertTrue(res["notice_file"])
        notices = [self._load_json(os.path.join(self.aios, "events", f))
                   for f in self.event_files()]
        self.assertEqual(sorted(n["kind"] for n in notices),
                         ["mutation", "notice"])
        notice = [n for n in notices if n["kind"] == "notice"][0]
        self.assertEqual(notice["entities_written"], 1)
        self.assertIn("actor", notice)

    def test_notice_only_mutation_writes_notice(self):
        res = apply_mutations(self.aios, [], ACTOR,
                              notice_factory=lambda n: {
                                  "type": "noop", "entities_written": n})
        self.assertEqual(res["applied"], [])
        self.assertEqual(len(self.event_files()), 1)


class TestCliPathResolution(Base):
    def test_project_path_resolves_to_repo_projects_dir(self):
        # Regression: _project_path previously resolved to <repo>/cli/projects
        # (single dirname), making every CLI command exit "project not found".
        from cli import aios as cli
        expected = os.path.join(ROOT, "projects", "RX50")
        self.assertEqual(
            os.path.normcase(os.path.abspath(cli._project_path("RX50"))),
            os.path.normcase(os.path.abspath(expected)))


if __name__ == "__main__":
    unittest.main(verbosity=2)

