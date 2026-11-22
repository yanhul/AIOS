#!/usr/bin/env python3
"""Trusted apply step: apply cumulative proposals through AIOS, never run them.

Writes an apply record binding the proposals digest to the resulting file
digests. Tests run later in a separate job without secrets or write tokens.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from core.agent_repair_worker import AgentRepairWorker, ProposedFile
from scripts.ci_repair_common import (
    APPLY_RECORD_KIND, changed_paths, expected_paths, git, issue_repair_authority,
    load_proposals, proposals_digest, tree_digests,
)


def main() -> int:
    base = os.environ["AIOS_REPAIR_SHA"]
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    attempt = int(os.environ["AIOS_REPAIR_ATTEMPT"])
    out = Path(os.environ["AIOS_REPAIR_APPLY_RECORD"])
    paths = [Path(x) for x in os.environ["AIOS_REPAIR_PROPOSALS"].split(",") if x]
    if not paths:
        raise SystemExit("no repair proposals")
    proposals = load_proposals(paths, base)
    if int(proposals[-1]["attempt"]) != attempt:
        raise SystemExit("BLOCKED: proposals do not end at the requested attempt")
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("repair proposal base SHA does not match checkout")
    digest = proposals_digest(proposals)

    with tempfile.TemporaryDirectory(prefix="aios-repair-authority-") as td:
        aios = Path(td) / "aios"
        aios.mkdir()
        contract_id, permit_id = issue_repair_authority(
            aios, actor="ci-repair-worker",
            task_id=f"ci-repair-{run_id}-attempt-{attempt}", input_digest=digest)
        worker = AgentRepairWorker(
            Path("."), object(), aios_dir=aios,
            contract_id=contract_id, permit_id=permit_id, actor="ci-repair-worker",
        )
        applied = []
        owned = frozenset()
        for proposal in proposals:
            files = tuple(ProposedFile(x["path"], x["content"]) for x in proposal["files"])
            result = worker.apply_via_aios(
                base_sha=base, files=files,
                logical_operation_id=f"ci-repair:{run_id}:attempt:{proposal['attempt']}",
                allowed_dirty_paths=owned,
            )
            applied.append({"attempt": proposal["attempt"], "result": dict(result)})
            owned = frozenset(set(owned) | {x.path for x in files})

    expected = expected_paths(proposals)
    actual = changed_paths()
    if actual != expected:
        raise SystemExit(f"mutation scope mismatch: actual={sorted(actual)} expected={sorted(expected)}")
    record = {
        "schema": 3, "kind": APPLY_RECORD_KIND, "run_id": run_id, "base_sha": base,
        "attempt": attempt, "attempts": [int(p["attempt"]) for p in proposals],
        "proposals_digest": digest, "files": tree_digests(Path("."), expected),
        "applied": applied,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"attempt": attempt, "proposals_digest": digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
