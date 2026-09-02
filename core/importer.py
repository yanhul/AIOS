"""Read-only importers that convert RX50 artifacts into AIOS entities.

Each importer reads a source file and emits entity records with strict
provenance (source file, line, verbatim text, classification). Nothing is
invented: statements are preserved verbatim; statuses come only from the
source. Importers never write to the source repository.
"""

import datetime
import os
import re
from typing import Dict, List, Tuple

ENTITY_TYPES = {
    "REQUIREMENT",
    "DECISION",
    "ASSUMPTION",
    "EVIDENCE",
    "ISSUE",
    "GATE",
    "CONTRADICTION",
}


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def _table_rows(lines: List[str]):
    """Yield (line_number, [cells]) for every markdown table row in a file."""
    for i, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            yield i + 1, cells


def _id_row(lines, pattern, header_scan=3):
    """Yield (line_no, cells) for rows whose first cell matches `pattern`."""
    rx = re.compile(pattern)
    for line_no, cells in _table_rows(lines):
        if cells and rx.fullmatch(cells[0]):
            yield line_no, cells


def _make_entity(
    entity_type: str,
    entity_id: str,
    source_file: str,
    source_line: int,
    source_text: str,
    status: str,
    statement: str,
    snapshot_id: str,
) -> dict:
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "statement": statement,
        "status": status,
        "source_file": source_file,
        "source_line": source_line,
        "source_text": source_text,
        "classification": entity_type,
        "imported_at": _now_utc(),
        "snapshot_id": snapshot_id,
    }


def import_decisions(path: str, rel: str, snapshot_id: str) -> List[dict]:
    """DECISION_REGISTER.md: | ID | Statement | Status | Basis |"""
    lines = _read(path)
    out = []
    for line_no, cells in _id_row(lines, r"D-\d+"):
        if len(cells) < 3:
            continue
        statement = " | ".join(cells[1:2]).strip()
        status = cells[2] if len(cells) > 2 else ""
        basis = " | ".join(cells[3:]) if len(cells) > 3 else ""
        text = " | ".join(cells)
        out.append(
            _make_entity(
                "DECISION", cells[0], rel, line_no, text, status,
                statement + (" — " + basis if basis else ""), snapshot_id,
            )
        )
    return out


def import_evidence(path: str, rel: str, snapshot_id: str) -> List[dict]:
    """EVIDENCE_REGISTER.md: | ID | Fact | Value | Source | Status | (varies)"""
    lines = _read(path)
    out = []
    for line_no, cells in _id_row(lines, r"EV-\d+"):
        if len(cells) < 3:
            continue
        statement = " | ".join(cells[1:2]).strip()
        # Status is the last cell (5-col) or the 3rd (4-col Level-4 table).
        status = cells[-1] if len(cells) >= 4 else ""
        text = " | ".join(cells)
        out.append(
            _make_entity("EVIDENCE", cells[0], rel, line_no, text, status,
                         statement, snapshot_id)
        )
    return out


def import_issues(path: str, rel: str, snapshot_id: str) -> List[dict]:
    """OPEN_ISSUES.md: | ID | Issue | Status | Gate | Note |"""
    lines = _read(path)
    out = []
    for line_no, cells in _id_row(lines, r"OI-\d+"):
        if len(cells) < 3:
            continue
        statement = " | ".join(cells[1:2]).strip()
        status = cells[2] if len(cells) > 2 else ""
        gate = cells[3] if len(cells) > 3 else ""
        note = " | ".join(cells[4:]) if len(cells) > 4 else ""
        note_suffix = f" | gate={gate}" if gate else ""
        note_suffix += f" | note={note}" if note else ""
        text = " | ".join(cells)
        out.append(
            _make_entity("ISSUE", cells[0], rel, line_no, text, status,
                         statement + note_suffix, snapshot_id)
        )
    return out


def import_contradictions(path: str, rel: str, snapshot_id: str) -> List[dict]:
    """CONTRADICTION_REGISTER.md: | ID | Conflict | Severity | Evidence | Status |"""
    lines = _read(path)
    out = []
    for line_no, cells in _id_row(lines, r"C-\d+"):
        if len(cells) < 2:
            continue
        statement = " | ".join(cells[1:2]).strip()
        status = cells[-1] if len(cells) >= 2 else ""
        text = " | ".join(cells)
        out.append(
            _make_entity("CONTRADICTION", cells[0], rel, line_no, text, status,
                         statement, snapshot_id)
        )
    return out


def import_requirements(path: str, rel: str, snapshot_id: str) -> List[dict]:
    """Requirement sources: | R-xx | requirement | ... | status |"""
    lines = _read(path)
    out = []
    for line_no, cells in _id_row(lines, r"R-\d+"):
        if len(cells) < 2:
            continue
        statement = " | ".join(cells[1:2]).strip()
        status = cells[-1] if len(cells) >= 3 else ""
        text = " | ".join(cells)
        out.append(
            _make_entity("REQUIREMENT", cells[0], rel, line_no, text, status,
                         statement, snapshot_id)
        )
    return out


def import_gates(path: str, rel: str, snapshot_id: str) -> List[dict]:
    """project_state.md gate map: | Gxx | Subject | Status |"""
    lines = _read(path)
    out = []
    for line_no, cells in _id_row(lines, r"G\d+"):
        if len(cells) < 2:
            continue
        statement = " | ".join(cells[1:2]).strip()
        status = cells[2] if len(cells) > 2 else ""
        text = " | ".join(cells)
        out.append(
            _make_entity("GATE", cells[0], rel, line_no, text, status,
                         statement, snapshot_id)
        )
    return out


# Map: relative filename -> (importer, entity_type)
_REGISTER_IMPORTERS: Dict[str, Tuple] = {
    "decisions/DECISION_REGISTER.md": (import_decisions, "DECISION"),
    "evidence/EVIDENCE_REGISTER.md": (import_evidence, "EVIDENCE"),
    "open_issues/OPEN_ISSUES.md": (import_issues, "ISSUE"),
    "harness/state/CONTRADICTION_REGISTER.md": (import_contradictions, "CONTRADICTION"),
    "RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md": (import_requirements, "REQUIREMENT"),
    "RX50_G1_G2_REQUIREMENT_CLOSURE.md": (import_requirements, "REQUIREMENT"),
    "harness/state/project_state.md": (import_gates, "GATE"),
}


def import_entities(source_root: str, snapshot_id: str) -> List[dict]:
    """Import entities from every known structured register.

    Returns a flat list of entity records. Pure read of the source tree.
    """
    entities: List[dict] = []
    for rel, (fn, _etype) in _REGISTER_IMPORTERS.items():
        path = os.path.join(source_root, *rel.split("/"))
        if os.path.isfile(path):
            try:
                entities.extend(fn(path, rel, snapshot_id))
            except OSError:
                continue
    return entities
