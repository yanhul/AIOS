#!/usr/bin/env python3
"""Trusted staging step for the isolated repair test job.

Runs before any proposed code executes. Writes the validated proposal files
into the base checkout and fails closed unless the resulting tree matches the
apply record produced by the trusted AIOS apply job byte-for-byte.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from core.repository_patch_adapter import _atomic_write, _safe_repo_path
from scripts.ci_repair_common import (
    APPLY_RECORD_KIND, changed_paths, expected_paths, git, load_proposals,
    proposals_digest, tree_digests,
)


def main() -> int:
    base = os.environ["AIOS_REPAIR_SHA"]
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    attempt = int(os.environ["AIOS_REPAIR_ATTEMPT"])
    paths = [Path(x) for x in os.environ["AIOS_REPAIR_PROPOSALS"].split(",") if x]
    record = json.loads(Path(os.environ["AIOS_REPAIR_APPLY_RECORD"]).read_text(encoding="utf-8"))
    proposals = load_proposals(paths, base)
    if git("rev-parse", "HEAD") != base or changed_paths():
        raise SystemExit("BLOCKED: test checkout is not the clean repair base")
    digest = proposals_digest(proposals)
    if (record.get("schema") != 3 or record.get("kind") != APPLY_RECORD_KIND
            or record.get("run_id") != run_id or record.get("base_sha") != base
            or record.get("attempt") != attempt or int(proposals[-1]["attempt"]) != attempt
            or record.get("proposals_digest") != digest):
        raise SystemExit("BLOCKED: apply record is not bound to these proposals")

    root = Path(".").resolve()
    for proposal in proposals:
        for item in proposal["files"]:
            target = _safe_repo_path(root, item["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(target, item["content"])

    expected = expected_paths(proposals)
    if changed_paths() != expected:
        raise SystemExit("BLOCKED: staged test tree scope differs from proposals")
    if tree_digests(root, expected) != record.get("files"):
        raise SystemExit("BLOCKED: staged test tree differs from trusted apply record")
    print(json.dumps({"attempt": attempt, "staged": sorted(expected)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
