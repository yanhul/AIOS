#!/usr/bin/env python3
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
    pass_attempt = int(os.environ["AIOS_REPAIR_PASS_ATTEMPT"])
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("stale repair publish base")

    proposal_dir = Path(os.environ.get("AIOS_REPAIR_PROPOSALS_DIR", "proposals"))
    proposals = load_proposals(
        [proposal_dir / f"repair-proposal-{n}.json" for n in range(1, pass_attempt + 1)], base)
    if not proposals or int(proposals[-1]["attempt"]) != pass_attempt:
        raise SystemExit("missing cumulative proposals for PASS attempt")
    digest = proposals_digest(proposals)
    apply_dir = Path(os.environ.get("AIOS_REPAIR_APPLY_DIR", "apply"))
    record = json.loads((apply_dir / f"repair-apply-{pass_attempt}.json").read_text(encoding="utf-8"))
    if (record.get("kind") != APPLY_RECORD_KIND or record.get("run_id") != run_id
            or record.get("base_sha") != base or record.get("attempt") != pass_attempt
            or record.get("proposals_digest") != digest):
        raise SystemExit("BLOCKED: PASS attempt apply record is not bound to these proposals")

    expected = expected_paths(proposals)

    with tempfile.TemporaryDirectory(prefix="aios-repair-authority-") as td:
        aios = Path(td) / "aios"
        aios.mkdir()
        contract_id, permit_id = issue_repair_authority(
            aios, actor="ci-repair-publisher",
            task_id=f"ci-repair-publish-{run_id}", input_digest=digest)
        worker = AgentRepairWorker(
            Path("."), object(), aios_dir=aios,
            contract_id=contract_id, permit_id=permit_id, actor="ci-repair-publisher",
        )
        owned = frozenset()
        for proposal in proposals:
            files = tuple(ProposedFile(x["path"], x["content"]) for x in proposal["files"])
            worker.apply_via_aios(
                base_sha=base,
                files=files,
                logical_operation_id=f"ci-repair-publish:{run_id}:attempt:{proposal['attempt']}",
                allowed_dirty_paths=owned,
            )
            owned = frozenset(set(owned) | {x.path for x in files})

    actual = changed_paths()
    if actual != expected:
        raise SystemExit(f"mutation scope mismatch: actual={sorted(actual)} expected={sorted(expected)}")
    if tree_digests(Path("."), expected) != record.get("files"):
        raise SystemExit("BLOCKED: publish tree differs from the tree that passed isolated tests")

    source_branch = os.environ.get("AIOS_REPAIR_SOURCE_BRANCH", "main")
    marker = git("show", "-s", "--format=%B", base)
    previous_cycle = 0
    for line in marker.splitlines():
        if line.startswith("AIOS-REPAIR-CYCLE:"):
            try:
                previous_cycle = int(line.split(":", 1)[1].strip())
            except ValueError:
                raise SystemExit("invalid AIOS-REPAIR-CYCLE marker")
    cycle = previous_cycle + 1
    if cycle > 3:
        raise SystemExit("repair campaign exhausted: maximum 3 full-CI repair cycles")
    if source_branch == "main":
        branch = f"aios/autorepair/{run_id}"
    elif source_branch.startswith("aios/autorepair/"):
        branch = source_branch
    else:
        raise SystemExit(f"unauthorized repair source branch: {source_branch!r}")
    git("config", "user.name", "AIOS Repair Worker")
    git("config", "user.email", "aios-repair-worker@users.noreply.github.com")
    git("switch", "-c", branch)
    git("add", "--", *sorted(expected))
    git("commit", "-m", f"fix: autonomous repair for CI run {run_id}", "-m", f"AIOS-REPAIR-CYCLE: {cycle}")
    print(branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
