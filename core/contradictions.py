"""Contradiction detection across RX50 artifacts.

Cross-file contradictions are detected mechanically: if two source artifacts
assign a different STATUS to the same entity ID, a contradiction record is
produced. AIOS NEVER resolves the conflict — it records both sides and marks
the record unresolved. The RX50 evidence hierarchy is respected (reported,
not silently resolved).
"""

import os
from typing import Dict, List

_STATUS_RE = None  # set lazily


def _load_statuses_by_id(paths_to_rel) -> Dict[str, List[dict]]:
    """Scan each source file for entity ID + status cells."""
    import re

    from .importer import _table_rows, _read

    status_re = re.compile(r"^(D|EV|OI|C|R|G)(-?\d+|-\d+)\b")
    result: Dict[str, List[dict]] = {}
    for path, rel in paths_to_rel.items():
        if not os.path.isfile(path):
            continue
        try:
            lines = _read(path)
        except OSError:
            continue
        for line_no, cells in _table_rows(lines):
            if not cells:
                continue
            m = status_re.match(cells[0])
            if not m:
                continue
            entity_id = cells[0]
            status = cells[-1] if len(cells) >= 2 else ""
            result.setdefault(entity_id, []).append(
                {"file": rel, "line": line_no, "status": status, "text": " | ".join(cells)}
            )
    return result


def _norm(status: str) -> str:
    return status.strip().upper()


def detect_cross_file_contradictions(source_root: str) -> List[dict]:
    """Detect same-ID entities with differing status across files.

    Returns contradiction records, each with source A, source B, the two
    conflicting statuses, location, and status=unresolved.
    """
    import re

    from .importer import import_entities  # noqa: F401 (ensure package importable)

    # Candidate structured files only — mirrors the importer's register set.
    import os as _os

    rels = [
        "decisions/DECISION_REGISTER.md",
        "evidence/EVIDENCE_REGISTER.md",
        "open_issues/OPEN_ISSUES.md",
        "harness/state/CONTRADICTION_REGISTER.md",
        "RX50_G1_REQUIREMENTS_ELICITATION_PLAN.md",
        "RX50_G1_G2_REQUIREMENT_CLOSURE.md",
    ]
    paths = {
        os.path.join(source_root, *r.split("/")): r
        for r in rels
        if os.path.isfile(os.path.join(source_root, *r.split("/")))
    }
    by_id = _load_statuses_by_id(paths)

    contradictions = []
    for entity_id, occurrences in sorted(by_id.items()):
        seen = {}
        for occ in occurrences:
            key = _norm(occ["status"])
            if key not in seen:
                seen[key] = occ
        if len(seen) > 1:
            first, second = list(seen.values())[:2]
            contradictions.append(
                {
                    "entity_id": entity_id,
                    "source_a": {"file": first["file"], "line": first["line"],
                                 "status": first["status"]},
                    "source_b": {"file": second["file"], "line": second["line"],
                                 "status": second["status"]},
                    "detected_location": f"{first['file']}:{first['line']} vs "
                                         f"{second['file']}:{second['line']}",
                    "status": "unresolved",
                    "note": "differing status text across RX50 artifacts; AIOS does not resolve",
                }
            )
    return contradictions
