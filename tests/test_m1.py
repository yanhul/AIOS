"""M1 test suite for AIOS read-only inspector + importer + snapshot.

Uses synthetic fixtures in a temp directory — the real RX50 repository is
NEVER touched by these tests.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import classifier as clf  # noqa: E402
from core.classifier import UNKNOWN  # noqa: E402
from core.contradictions import detect_cross_file_contradictions  # noqa: E402
from core.importer import (  # noqa: E402
    import_contradictions,
    import_decisions,
    import_entities,
    import_evidence,
    import_gates,
    import_issues,
    import_requirements,
)
from core.inspector import inspect_repository  # noqa: E402
from core.project import (  # noqa: E402
    ProjectError,
    load_mini_yaml,
    resolve_source_path,
)
from core.snapshot import SnapshotExistsError, create_snapshot  # noqa: E402


class BaseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aios_m1_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, rel, content):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path


def make_rx50_like_fixture(root):
    """Create a small synthetic RX50-like repository."""
    os.makedirs(root, exist_ok=True)
    files = {
        "AGENTS.md": "# Rules\nNever invent numbers.\n",
        "README.md": "# RX50\nA test project.\n",
        "decisions/DECISION_REGISTER.md": (
            "# DECISION REGISTER\n"
            "| ID | Statement | Status | Basis |\n"
            "|---|---|---|---|\n"
            "| D-01 | Use 50 channels | OWNER-APPROVED | owner 2026-08-15 |\n"
            "| D-02 | Gate G4 must measure | LOCKED | evidence EV-01 |\n"
        ),
        "evidence/EVIDENCE_REGISTER.md": (
            "# EVIDENCE REGISTER\n"
            "| ID | Fact | Value | Source | Status |\n"
            "|---|---|---|---|---|\n"
            "| EV-01 | supply voltage | 5 V | datasheet | VERIFIED |\n"
            "| EV-02 | off leakage | 100 nA | datasheet | VERIFIED |\n"
        ),
        "open_issues/OPEN_ISSUES.md": (
            "# OPEN ISSUES\n"
            "| ID | Issue | Status | Gate | Note |\n"
            "|---|---|---|---|---|\n"
            "| OI-01 | load envelope unknown | HOLD / TBD | G1 | owner evidence |\n"
        ),
        "harness/state/CONTRADICTION_REGISTER.md": (
            "# CONTRADICTION REGISTER\n"
            "| ID | Conflict | Severity | Evidence | Status |\n"
            "|---|---|---|---|---|\n"
            "| C-01 | A vs B | MEDIUM | datasheet wins | OPEN |\n"
        ),
        "RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md": (
            "# G1 ELICITATION PLAN\n"
            "| # | REQUIREMENT FIELD | STATUS NOW | REQUIRED OWNER INPUT |\n"
            "|---|---|---|---|\n"
            "| R-01 | max simultaneous channels | HOLD / TBD | explicit number |\n"
        ),
        "harness/state/project_state.md": (
            "# PROJECT STATE\n"
            "| Gate | Subject | Status |\n"
            "|---|---|---|\n"
            "| G1 | Load envelope | HOLD |\n"
            "| G4 | Continuity | MEASUREMENT PENDING |\n"
        ),
        "reports/unstructured_note.txt": "Some random text with no markers.\n",
        "notes/oddfile.md": "no strong category keywords anywhere here\n",
    }
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    return root


class TestProjectYaml(BaseFixture):
    def test_load_mini_yaml(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = os.path.join(d, "project.yaml")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(
                "# comment\n"
                "- project_id: RX50\n"
                "- name: RX50\n"
                "- source:\n"
                "    type: existing_repository\n"
                "    path: C:\\tmp\\rx50\n"
            )
        meta = load_mini_yaml(p)
        self.assertEqual(meta["project_id"], "RX50")
        self.assertEqual(meta["source"]["type"], "existing_repository")
        self.assertEqual(meta["source"]["path"], "C:\\tmp\\rx50")

    def test_missing_file_raises(self):
        with self.assertRaises(ProjectError):
            load_mini_yaml(os.path.join(self.tmp, "nope.yaml"))


class TestSourcePathResolution(BaseFixture):
    def test_existing_dir_ok(self):
        resolved = resolve_source_path(self.tmp)
        self.assertEqual(os.path.abspath(self.tmp), resolved)

    def test_missing_path_raises(self):
        with self.assertRaises(ProjectError):
            resolve_source_path(os.path.join(self.tmp, "does_not_exist"))

    def test_file_not_dir_raises(self):
        f = os.path.join(self.tmp, "afile.txt")
        with open(f, "w") as fh:
            fh.write("x")
        with self.assertRaises(ProjectError):
            resolve_source_path(f)


class TestClassifier(unittest.TestCase):
    def test_known_files(self):
        cases = [
            ("AGENTS.md", "AGENTS.md", "INSTRUCTION"),
            ("README.md", "README.md", "INSTRUCTION"),
            ("decisions/DECISION_REGISTER.md", "DECISION_REGISTER.md", "DECISION"),
            ("evidence/EVIDENCE_REGISTER.md", "EVIDENCE_REGISTER.md", "EVIDENCE"),
            ("open_issues/OPEN_ISSUES.md", "OPEN_ISSUES.md", "ISSUE"),
            ("RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md", "x.md", "REQUIREMENT"),
            ("RX50_G4_OWNER_DECISION_SHEET.md", "x.md", "DECISION"),
            ("RX50_SCHEMATIC_RELEASE_GATE.md", "x.md", "GATE"),
        ]
        for rel, fname, expected in cases:
            cat, conf, _ = clf.classify_file(rel, fname, "")
            self.assertEqual(cat, expected, msg=f"{rel}: got {cat}")

    def test_ambiguous_classification_is_unknown(self):
        cat, conf, _ = clf.classify_file("misc/random.md", "random.md", "unrelated words")
        self.assertEqual(cat, UNKNOWN)

    def test_content_based_fallback(self):
        cat, _, _ = clf.classify_file("docs/x.md", "x.md", "open issue OI-05 severity high")
        self.assertEqual(cat, "ISSUE")


class TestInspector(BaseFixture):
    def test_inventory_fields(self):
        root = os.path.join(self.tmp, "rx")
        make_rx50_like_fixture(root)
        arts = inspect_repository(root)
        self.assertGreaterEqual(len(arts), 8)
        a = arts[0]
        for key in ("source_path", "relative_path", "file_type", "size_bytes",
                    "mtime_utc", "sha256", "category"):
            self.assertIn(key, a.to_dict())
        self.assertTrue(a.to_dict()["sha256"])

    def test_skips_git(self):
        root = os.path.join(self.tmp, "rx")
        make_rx50_like_fixture(root)
        os.makedirs(os.path.join(root, ".git"))
        with open(os.path.join(root, ".git", "config"), "w") as fh:
            fh.write("[core]\n")
        arts = inspect_repository(root)
        rels = [a.relative_path for a in arts]
        self.assertFalse(any(".git" in r for r in rels))


class TestImporterProvenance(BaseFixture):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "rx")
        make_rx50_like_fixture(self.root)

    def _rel(self, rel):
        return os.path.join(self.root, *rel.split("/"))

    def test_decisions_provenance(self):
        ents = import_decisions(self._rel("decisions/DECISION_REGISTER.md"),
                                "decisions/DECISION_REGISTER.md", "SNAP-X")
        self.assertEqual(len(ents), 2)
        d1 = ents[0]
        self.assertEqual(d1["entity_id"], "D-01")
        self.assertEqual(d1["source_file"], "decisions/DECISION_REGISTER.md")
        self.assertGreater(d1["source_line"], 0)
        self.assertIn("50 channels", d1["statement"])
        self.assertEqual(d1["snapshot_id"], "SNAP-X")

    def test_evidence_import(self):
        ents = import_evidence(self._rel("evidence/EVIDENCE_REGISTER.md"),
                               "evidence/EVIDENCE_REGISTER.md", "SNAP-X")
        self.assertEqual(len(ents), 2)
        self.assertEqual(ents[0]["status"], "VERIFIED")

    def test_issues_import(self):
        ents = import_issues(self._rel("open_issues/OPEN_ISSUES.md"),
                             "open_issues/OPEN_ISSUES.md", "SNAP-X")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0]["entity_id"], "OI-01")
        self.assertEqual(ents[0]["status"], "HOLD / TBD")

    def test_contradictions_import(self):
        ents = import_contradictions(self._rel("harness/state/CONTRADICTION_REGISTER.md"),
                                     "harness/state/CONTRADICTION_REGISTER.md", "SNAP-X")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0]["entity_id"], "C-01")
        self.assertEqual(ents[0]["status"], "OPEN")

    def test_requirements_import(self):
        ents = import_requirements(self._rel("RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md"),
                                   "RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md", "SNAP-X")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0]["entity_id"], "R-01")

    def test_gates_import(self):
        ents = import_gates(self._rel("harness/state/project_state.md"),
                            "harness/state/project_state.md", "SNAP-X")
        self.assertEqual(len(ents), 2)
        self.assertEqual(ents[0]["entity_id"], "G1")

    def test_import_entities_aggregates(self):
        ents = import_entities(self.root, "SNAP-Y")
        types = {e["entity_type"] for e in ents}
        self.assertTrue({"DECISION", "EVIDENCE", "ISSUE", "CONTRADICTION",
                         "REQUIREMENT", "GATE"}.issubset(types))
        for e in ents:
            self.assertTrue(e["source_file"])
            self.assertTrue(e["source_line"])
            self.assertTrue(e["statement"])
            self.assertTrue(e["source_text"])


class TestContradictionDetection(BaseFixture):
    def test_cross_file_contradiction_detected(self):
        root = os.path.join(self.tmp, "rx")
        os.makedirs(os.path.join(root, "decisions"))
        with open(os.path.join(root, "decisions", "DECISION_REGISTER.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("| ID | Statement | Status | Basis |\n"
                     "|---|---|---|---|\n"
                     "| D-99 | something | LOCKED | a |\n")
        os.makedirs(os.path.join(root, "evidence"))
        with open(os.path.join(root, "evidence", "EVIDENCE_REGISTER.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("| ID | Fact | Value | Source | Status |\n"
                     "|---|---|---|---|---|\n"
                     "| D-99 | something | x | y | OWNER-APPROVED |\n")
        os.makedirs(os.path.join(root, "harness", "state"))
        with open(os.path.join(root, "harness", "state", "CONTRADICTION_REGISTER.md"),
                  "w", encoding="utf-8") as fh:
            fh.write("| ID | Conflict | Severity | Evidence | Status |\n"
                     "|---|---|---|---|---|\n")
        con = detect_cross_file_contradictions(root)
        self.assertEqual(len(con), 1)
        self.assertEqual(con[0]["status"], "unresolved")
        self.assertEqual(con[0]["entity_id"], "D-99")
        self.assertNotEqual(con[0]["source_a"]["file"], con[0]["source_b"]["file"])


class TestSnapshot(BaseFixture):
    def test_create_snapshot(self):
        root = os.path.join(self.tmp, "aios", "projects", "RX50", ".aios", "snapshots")
        os.makedirs(root)
        sid, path = create_snapshot(
            root,
            inventory=[{"x": 1}],
            entities=[{"id": "E1"}],
            contradictions=[],
            unresolved=[],
            metadata={"project_id": "RX50"},
            snapshot_id="SNAP-TEST0001",
        )
        self.assertTrue(os.path.isdir(path))
        self.assertTrue(os.path.isfile(os.path.join(path, "meta.json")))
        self.assertTrue(os.path.isfile(os.path.join(path, "inventory.json")))
        with open(os.path.join(path, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertTrue(meta["immutable"])

    def test_existing_snapshot_not_overwritten(self):
        root = os.path.join(self.tmp, "snaps")
        os.makedirs(root)
        create_snapshot(root, inventory=[], entities=[], contradictions=[],
                        unresolved=[], metadata={}, snapshot_id="SNAP-FIXED")
        with self.assertRaises(SnapshotExistsError):
            create_snapshot(root, inventory=[], entities=[], contradictions=[],
                            unresolved=[], metadata={}, snapshot_id="SNAP-FIXED")


class TestReadOnlyBehavior(BaseFixture):
    def test_inspector_and_import_never_modify_source(self):
        root = os.path.join(self.tmp, "rx")
        make_rx50_like_fixture(root)
        before = {}
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                with open(p, "rb") as fh:
                    before[os.path.relpath(p, root)] = fh.read()

        inspect_repository(root)
        import_entities(root, "SNAP-RO")

        after = {}
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                with open(p, "rb") as fh:
                    after[os.path.relpath(p, root)] = fh.read()
        self.assertEqual(before, after)
        self.assertEqual(set(before), set(after))


if __name__ == "__main__":
    unittest.main(verbosity=2)
