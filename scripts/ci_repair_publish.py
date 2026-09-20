#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from core.agent_repair_worker import AgentRepairWorker, ProposedFile
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.policy_registry import persist_policy


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], text=True, capture_output=True, check=True)
    return p.stdout.strip()


def authority(root: Path, actor: str, run_id: int):
    registry = CapabilityRegistry()
    registry.register(Capability("repo_patch", "1", "AIOS", "external_effect",
                                 inputs=("patch",), outputs=("observation",), status="ACTIVE"))
    registry.persist(root, actor=actor)
    policy_digest = persist_policy(root, {
        "policy_type": "GOVERNING_POLICY", "task": "ci-repair",
        "allowed_effects": ["external_effect"],
    })
    contract = {
        "contract_type": CONTRACT_TYPE, "task_id": f"ci-repair-publish-{run_id}",
        "scope": "repository", "actor": actor, "capabilities": ["repo_patch@1"],
        "input_digest": "sha256:ci-failure", "allowed_effects": ["external_effect"],
        "evidence_required": ["OBSERVED"], "max_attempts": 2,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": policy_digest,
    }
    stored = persist_contract(root, contract)
    permit = persist_permit(root, stored, issuer="ci-repair-authority")
    return stored["contract_id"], permit["permit_id"]


def main() -> int:
    base = os.environ["AIOS_REPAIR_SHA"]
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    pass_attempt = int(os.environ["AIOS_REPAIR_PASS_ATTEMPT"])
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("stale repair publish base")

    proposal_files = sorted(Path(".").glob("repair-proposal-*.json"))
    proposals = []
    for path in proposal_files:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if obj["base_sha"] == base and int(obj["attempt"]) <= pass_attempt:
            proposals.append(obj)
    proposals.sort(key=lambda x: int(x["attempt"]))
    if not proposals or int(proposals[-1]["attempt"]) != pass_attempt:
        raise SystemExit("missing cumulative proposals for PASS attempt")

    expected = set()
    for proposal in proposals:
        expected.update(x["path"] for x in proposal["files"])

    with tempfile.TemporaryDirectory(prefix="aios-repair-authority-") as td:
        aios = Path(td) / "aios"
        aios.mkdir()
        contract_id, permit_id = authority(aios, "ci-repair-publisher", run_id)
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

    actual = set(git("diff", "--name-only").splitlines())
    if actual != expected:
        raise SystemExit(f"mutation scope mismatch: actual={sorted(actual)} expected={sorted(expected)}")

    branch = f"aios/autorepair/{run_id}"
    git("config", "user.name", "AIOS Repair Worker")
    git("config", "user.email", "aios-repair-worker@users.noreply.github.com")
    git("switch", "-c", branch)
    git("add", "--", *sorted(expected))
    git("commit", "-m", f"fix: autonomous repair for CI run {run_id}")
    print(branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
