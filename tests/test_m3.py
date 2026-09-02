"""M3 test suite: minimal source-divergence detection.

All tests operate on synthetic fixtures inside temp dirs and inspect
actual persisted state. The real RX50 tree is never touched here; its
integrity is verified externally (git status) as part of the milestone
checklist.
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
from core.importer import import_entities  # noqa: E402
from core.mutation import TransitionError, apply_mutations  # noqa: E402

ACTOR = "test:m3"


def write_register(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("| ID | Statement | Status | Basis |\n|---|---|---|---|\n")
        for row in rows:
            fh.write(row + "\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aios_m3_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.aios = os.path.join(self.tmp, ".aios")
        self.src = os.path.join(self.tmp, "src")
        self.dec_path = os.path.join(
            self.src, "decisions", "DECISION_REGISTER.md")
        write_register(self.dec_path, [
            "| D-01 | Use 50 channels | LOCKED | owner |",
            "| D-02 | Gate G4 must measure | LOCKED | EV-01 |",
        ])

    @staticmethod
    def _load(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def seed_store_from_source(self):
        ents = import_entities(self.src, snapshot_id="SNAP-M3")
        apply_mutations(self.aios, ents, ACTOR)
        return ents

    def findings(self, rep, prefix):
        return [f for f in rep["findings"] if f["check"].startswith(prefix)]

    def divs(self, rep):
        return sorted(f["check"] + "|" + f["detail"]
                      for f in rep["findings"]
                      if f["check"].startswith("H.source_divergence"))

    def aios_bytes(self):
        snap = {}
        for dirpath, _, filenames in os.walk(self.aios):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                with open(p, "rb") as fh:
                    snap[os.path.relpath(p, self.aios)] = fh.read()
        return snap


class TestNoSourceRoot(Base):
    def test_M3_01_no_source_root_preserves_behavior(self):
        ents = import_entities(self.src, snapshot_id="SNAP-M3")
        apply_mutations(self.aios, ents, ACTOR)
        rep = rcn.reconcile(self.aios)
        self.assertEqual(rep["overall"], "VALID", rep["findings"])
        self.assertEqual(self.divs(rep), [])
        rep2 = rcn.reconcile(self.aios, source_root=None)
        self.assertEqual(rep2, rep)


class TestSourceDivergence(Base):
    def setUp(self):
        super().setUp()
        self.seed_store_from_source()

    def test_M3_02_identical_source_store_has_no_divergence(self):
        rep = rcn.reconcile(self.aios, source_root=self.src)
        self.assertEqual(self.divs(rep), [], rep["findings"])
        self.assertEqual(rep["overall"], "VALID")

    def test_M3_03_source_only_entity_is_added(self):
        write_register(self.dec_path, [
            "| D-01 | Use 50 channels | LOCKED | owner |",
            "| D-02 | Gate G4 must measure | LOCKED | EV-01 |",
            "| D-03 | New owner decision | OWNER-APPROVED | memo |",
        ])
        rep = rcn.reconcile(self.aios, source_root=self.src)
        hits = [f for f in self.findings(rep, "H.source_divergence.added")
                if "DECISION D-03" in f["detail"]]
        self.assertEqual(len(hits), 1)
        self.assertIn("kind=added", hits[0]["detail"])
        self.assertIn("store=absent", hits[0]["detail"])

    def test_M3_04_store_only_entity_is_missing(self):
        write_register(self.dec_path, [
            "| D-01 | Use 50 channels | LOCKED | owner |",
        ])
        rep = rcn.reconcile(self.aios, source_root=self.src)
        hits = self.findings(rep, "H.source_divergence.missing")
        self.assertTrue(hits)
        self.assertTrue(all("DECISION D-02" in f["detail"] for f in hits))
        self.assertIn("kind=missing", hits[0]["detail"])
        self.assertIn("source=absent", hits[0]["detail"])

    def test_M3_05_changed_content_is_changed(self):
        write_register(self.dec_path, [
            "| D-01 | Use 50 channels | OPEN superseded | owner |",
            "| D-02 | Gate G4 must measure | LOCKED | EV-01 |",
        ])
        rep = rcn.reconcile(self.aios, source_root=self.src)
        hits = [f for f in self.findings(rep, "H.source_divergence.changed")
                if "DECISION D-01" in f["detail"]]
        self.assertEqual(len(hits), 1)
        det = hits[0]["detail"]
        self.assertIn("kind=changed", det)
        self.assertIn("source_digest=", det)
        self.assertIn("store_digest=", det)

    def test_M3_06_formatting_noise_is_not_divergence(self):
        with open(self.dec_path, "w", encoding="utf-8") as fh:
            fh.write("\n# reviewer scratchpad: reflowed table below\n\n")
            fh.write("| ID | Statement      | Status | Basis     |\n")
            fh.write("| --- | ------------- | ------ | --------- |\n")
            fh.write("| D-01   | Use 50 channels | LOCKED | owner |\n")
            fh.write("| D-02   | Gate G4 must measure | LOCKED | EV-01 |\n")
            fh.write("\ntrailing prose with no table markers\n")
        rep = rcn.reconcile(self.aios, source_root=self.src)
        self.assertEqual(self.divs(rep), [], rep["findings"])
        self.assertEqual(rep["overall"], "VALID")

    def test_M3_07_zero_writes_during_divergence_check(self):
        before = self.aios_bytes()
        write_register(self.dec_path, ["| D-01 | changed | OPEN | x |"])
        rcn.reconcile(self.aios, source_root=self.src)
        self.assertEqual(self.aios_bytes(), before,
                         "divergence detection must not write anything")

    def test_M3_08_refresh_does_not_overwrite_store(self):
        dpath = os.path.join(self.aios, "decisions", "D-01.json")
        committed = open(dpath, "rb").read()
        write_register(self.dec_path, [
            "| D-01 | silently different | OPEN | x |",
            "| D-02 | Gate G4 must measure | LOCKED | EV-01 |",
        ])
        rep = rcn.reconcile(self.aios, source_root=self.src)
        self.assertTrue(self.findings(rep, "H.source_divergence.changed"))
        self.assertEqual(open(dpath, "rb").read(), committed,
                         "detection must never refresh persisted entities")

    def test_M3_09_provenance_changing_reimport_still_rejected(self):
        ents = import_entities(self.src, snapshot_id="SNAP-M3")
        rederived = [dict(e, snapshot_id="SNAP-M3-NEW") for e in ents]
        with self.assertRaises(TransitionError):
            apply_mutations(self.aios, rederived, ACTOR)
        rep = rcn.reconcile(self.aios, source_root=self.src)
        self.assertEqual(self.divs(rep), [])

    def test_M3_11_findings_are_deterministic(self):
        write_register(self.dec_path, [
            "| D-01 | Use 50 channels | OPEN superseded | owner |",
            "| D-02 | Gate G4 must measure | LOCKED | EV-01 |",
        ])
        r1 = rcn.reconcile(self.aios, source_root=self.src)
        r2 = rcn.reconcile(self.aios, source_root=self.src)
        self.assertEqual(r1, r2)

    def test_M3_13_conflicting_source_variants_flagged_not_guessed(self):
        plan = os.path.join(
            self.src, "RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md")
        closure = os.path.join(
            self.src, "RX50_G1_G2_REQUIREMENT_CLOSURE.md")
        with open(plan, "w", encoding="utf-8") as fh:
            fh.write("| # | REQUIREMENT FIELD | STATUS NOW | "
                     "REQUIRED OWNER INPUT |\n|---|---|---|---|\n"
                     "| R-01 | max channels | HOLD / TBD | explicit number |\n")
        with open(closure, "w", encoding="utf-8") as fh:
            fh.write("| # | REQUIREMENT FIELD | STATUS NOW |\n"
                     "|---|---|---|\n"
                     "| R-01 | max channels variant | OPEN |\n")
        rep = rcn.reconcile(self.aios, source_root=self.src)
        amb = self.findings(rep, "H.source_divergence.ambiguous")
        self.assertEqual(len(amb), 1)
        self.assertIn("R-01", amb[0]["detail"])
        self.assertFalse(self.findings(rep, "H.source_divergence.added"))

    def test_existing_checks_still_fire_alongside_source_root(self):
        os.unlink(os.path.join(self.aios, "decisions", "D-01.json"))
        rep = rcn.reconcile(self.aios, source_root=self.src)
        self.assertTrue(self.findings(rep, "B.event_without_entity"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
