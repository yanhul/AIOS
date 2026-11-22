#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from core.agent_repair_worker import AgentRepairWorker, ProposedFile
from core.effect_authority import ProviderKeyring
from ci_repair_provenance import candidate_branch
from core.repair_reconcile import reconcile_repair


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], text=True, capture_output=True, check=True)
    return p.stdout.strip()


def atomic_write(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.repair-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, target)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def main() -> int:
    base = os.environ["AIOS_REPAIR_SHA"]
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    repository = os.environ["GITHUB_REPOSITORY"]
    pass_attempt = int(os.environ["AIOS_REPAIR_PASS_ATTEMPT"])
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("stale repair publish base")
    if git("status", "--porcelain"):
        raise SystemExit("publish checkout must be clean before verified patch materialization")

    result_path = Path(os.environ["AIOS_REPAIR_RESULT_FILE"])
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("schema") != 3 or result.get("status") != "REPAIR_E2E_PASS":
        raise SystemExit("selected result is not a reconciled AIOS repair E2E result")
    if (result.get("run_id") != run_id or result.get("base_sha") != base
            or result.get("repository") != repository):
        raise SystemExit("repair result repository/run/base binding mismatch")
    if max(result.get("attempts", [0])) != pass_attempt:
        raise SystemExit("selected repair result does not match PASS attempt")

    proposal_dir = Path(os.environ.get("AIOS_REPAIR_PROPOSALS_DIR", "proposals"))
    proposal_files = sorted(proposal_dir.glob("repair-proposal-*.json"))
    proposals = []
    for path in proposal_files:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if (obj.get("schema") == 2 and obj.get("run_id") == run_id
                and obj.get("repository") == repository and obj.get("base_sha") == base and int(obj.get("attempt", 0)) <= pass_attempt):
            proposals.append(obj)
    proposals.sort(key=lambda x: int(x["attempt"]))
    if [int(p["attempt"]) for p in proposals] != list(range(1, pass_attempt + 1)):
        raise SystemExit("missing contiguous cumulative proposals for selected PASS attempt")

    provider_keyring = ProviderKeyring.from_env()
    if provider_keyring is None:
        raise SystemExit("trusted AIOS_PROVIDER_KEYRING is required for publish reconciliation")
    authority_dir = Path(os.environ["AIOS_REPAIR_AUTHORITY_DIR"])
    reconciliation = reconcile_repair(
        authority_dir, contract_id=result["contract_id"], permit_id=result["permit_id"],
        actor="ci-repair-worker", repository=repository, run_id=run_id, base_sha=base,
        effects=result["effects"], proposals=proposals, test=result["test"],
        provider_keyring=provider_keyring,
    )
    if reconciliation != result.get("reconciliation"):
        raise SystemExit("persisted authority/effect state no longer matches the repair result reconciliation")

    worker = AgentRepairWorker(Path("."), object())
    expected = set()
    for proposal in proposals:
        files = tuple(ProposedFile(x["path"], x["content"]) for x in proposal["files"])
        for item in files:
            target = worker._safe_path(item.path)
            atomic_write(target, item.content)
            expected.add(item.path)

    actual = set(git("diff", "--name-only").splitlines())
    if actual != expected:
        raise SystemExit(f"verified patch materialization mismatch: actual={sorted(actual)} expected={sorted(expected)}")

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
    if source_branch != "main" and not source_branch.startswith("aios/autorepair/"):
        raise SystemExit(f"unauthorized repair source branch: {source_branch!r}")
    branch = candidate_branch(run_id, os.environ.get("GITHUB_RUN_ID", ""))
    git("config", "user.name", "AIOS Repair Worker")
    git("config", "user.email", "aios-repair-worker@users.noreply.github.com")
    git("switch", "-c", branch)
    git("add", "--", *sorted(expected))
    git("commit", "-m", f"fix: autonomous repair for CI run {run_id}", "-m",
        f"AIOS-REPAIR-CYCLE: {cycle}\nAIOS-Repair-Run: {os.environ.get('GITHUB_RUN_ID', 'local')}")
    print(json.dumps({"status": "PUBLISHED_CANDIDATE", "branch": branch,
                      "reconciliation": reconciliation["status"], "paths": sorted(expected)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
