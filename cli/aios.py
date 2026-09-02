"""AIOS CLI.

Provides:
    aios inspect RX50      — read-only summary of the referenced repository
    aios snapshot RX50     — create an immutable AIOS state snapshot

Stdlib only. Never writes to RX50.
"""

import argparse
import os
import sys

from core.classifier import UNKNOWN
from core.contradictions import detect_cross_file_contradictions
from core.importer import import_entities
from core.inspector import inspect_repository
from core.project import load_project
from core.snapshot import create_snapshot
from core import state as state_layout
from core.mutation import apply_mutations


def _counts(entities):
    counts = {}
    for e in entities:
        counts[e["entity_type"]] = counts.get(e["entity_type"], 0) + 1
    return counts


def _project_path(project_id: str) -> str:
    # aios.py lives in <AIOS>/cli/, so the repository root is one level up.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "projects", project_id)


def run_inspect(project_id: str, ai_project_dir: str) -> dict:
    """Read-only inspection + import; returns a summary dict. Writes nothing."""
    project = load_project(ai_project_dir)
    source_root = project["source_path"]
    artifacts = inspect_repository(source_root)
    entities = import_entities(source_root, snapshot_id="inspect-only")
    contradictions = detect_cross_file_contradictions(source_root)
    unresolved = [a for a in artifacts if a.category == UNKNOWN]
    return {
        "project": project,
        "artifacts": artifacts,
        "entities": entities,
        "contradictions": contradictions,
        "unresolved": unresolved,
        "counts": _counts(entities),
    }


def run_snapshot(project_id: str, ai_project_dir: str, snapshot_id: str = None) -> dict:
    """Full M1/M1.5 pipeline: inspect, import, commit via the mutation boundary."""
    project = load_project(ai_project_dir)
    source_root = project["source_path"]
    aios_dir = os.path.join(ai_project_dir, ".aios")
    state_layout.ensure_state_dirs(aios_dir)

    artifacts = inspect_repository(source_root)
    entities = import_entities(source_root, snapshot_id=snapshot_id or "pending")
    contradictions = detect_cross_file_contradictions(source_root)
    unresolved = [a.to_dict() for a in artifacts if a.category == UNKNOWN]

    snap_id, snap_path = create_snapshot(
        os.path.join(aios_dir, "snapshots"),
        inventory=[a.to_dict() for a in artifacts],
        entities=entities,
        contradictions=contradictions,
        unresolved=unresolved,
        metadata={
            "project_id": project_id,
            "source_path": source_root,
            "importer": "aios M1 stdlib",
        },
        snapshot_id=snapshot_id,
    )

    # Commit imported entities + their audit events through the single
    # authoritative mutation boundary (M1.5). Snapshot creation above is a
    # separate, already-immutable authority.
    for ent in entities:
        ent["snapshot_id"] = snap_id

    def _notice(entities_applied):
        return {
            "type": "snapshot.created",
            "project_id": project_id,
            "snapshot_id": snap_id,
            "entities_written": entities_applied,
            "source_path": source_root,
        }

    mutation = apply_mutations(
        aios_dir,
        entities,
        actor=f"cli:snapshot:{project_id}",
        notice_factory=_notice,
    )
    written = len(mutation["applied"]) + len(mutation["replayed"])
    return {
        "project": project,
        "artifacts": artifacts,
        "entities": entities,
        "contradictions": contradictions,
        "snapshot_id": snap_id,
        "snapshot_path": snap_path,
        "mutation": mutation,
        "counts": _counts(entities),
    }


def _print_summary(result: dict) -> None:
    project = result["project"]
    counts = result.get("counts", {})
    artifacts = result["artifacts"]
    print(f"PROJECT: {os.path.basename(project['project_dir'])}")
    print("Source:")
    print(f"    {project['source_path']}")
    print()
    print("Artifacts discovered:")
    print(f"    {len(artifacts)}")
    print()
    for label, key in [
        ("Requirements", "REQUIREMENT"),
        ("Decisions", "DECISION"),
        ("Assumptions", "ASSUMPTION"),
        ("Evidence", "EVIDENCE"),
        ("Issues", "ISSUE"),
        ("Contradictions", "CONTRADICTION"),
        ("Gates", "GATE"),
    ]:
        print(f"{label}:")
        print(f"    {counts.get(key, 0)}")
    print()
    reports = len([a for a in artifacts if a.category == "REPORT"])
    print("Reports:")
    print(f"    {reports}")
    print()
    print("Contradictions (cross-file detected):")
    print(f"    {len(result.get('contradictions', []))}")
    print()
    print("Snapshot:")
    if result.get("snapshot_id"):
        print(f"    {result['snapshot_id']} -> {result['snapshot_path']}")
    else:
        print(f"    (inspect-only; run 'aios snapshot' to persist)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aios", description="AI Operating System CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="read-only inspection summary")
    p_inspect.add_argument("project", help="project id, e.g. RX50")

    p_snap = sub.add_parser("snapshot", help="create immutable state snapshot")
    p_snap.add_argument("project", help="project id, e.g. RX50")
    p_snap.add_argument("--id", dest="snapshot_id", default=None,
                        help="explicit snapshot id (default: auto UTC id)")

    args = parser.parse_args(argv)
    project_dir = _project_path(args.project)
    if not os.path.isdir(project_dir):
        print(f"ERROR: project not found: {args.project}", file=sys.stderr)
        return 2

    try:
        if args.command == "inspect":
            result = run_inspect(args.project, project_dir)
            _print_summary(result)
        elif args.command == "snapshot":
            result = run_snapshot(args.project, project_dir, args.snapshot_id)
            _print_summary(result)
    except Exception as exc:  # surface clean CLI errors
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
