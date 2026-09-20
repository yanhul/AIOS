#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
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


def main() -> int:
    proposal = json.loads(Path("repair-proposal.json").read_text(encoding="utf-8"))
    base = proposal["base_sha"]
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("stale repair publish base")

    with tempfile.TemporaryDirectory(prefix="aios-repair-authority-") as td:
        aios = Path(td) / "aios"
        aios.mkdir()
        registry = CapabilityRegistry()
        registry.register(Capability(
            "repo_patch", "1", "AIOS", "external_effect",
            inputs=("patch",), outputs=("observation",), status="ACTIVE",
        ))
        registry.persist(aios, actor="ci-repair-publisher")
        policy_digest = persist_policy(aios, {
            "policy_type": "GOVERNING_POLICY",
            "task": "ci-repair",
            "allowed_effects": ["external_effect"],
        })
        contract = {
            "contract_type": CONTRACT_TYPE,
            "task_id": f"ci-repair-publish-{proposal['run_id']}",
            "scope": "repository",
            "actor": "ci-repair-publisher",
            "capabilities": ["repo_patch@1"],
            "input_digest": "sha256:ci-failure",
            "allowed_effects": ["external_effect"],
            "evidence_required": ["OBSERVED"],
            "max_attempts": 2,
            "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
            "policy_digest": policy_digest,
        }
        stored = persist_contract(aios, contract)
        permit = persist_permit(aios, stored, issuer="ci-repair-authority")
        worker = AgentRepairWorker(
            Path("."),
            object(),
            aios_dir=aios,
            contract_id=stored["contract_id"],
            permit_id=permit["permit_id"],
            actor="ci-repair-publisher",
        )
        files = tuple(ProposedFile(x["path"], x["content"]) for x in proposal["files"])
        worker.apply_via_aios(
            base_sha=base,
            files=files,
            logical_operation_id=f"ci-repair-publish:{proposal['run_id']}",
        )

    expected = sorted(x["path"] for x in proposal["files"])
    actual = sorted(git("diff", "--name-only").splitlines())
    if actual != expected:
        raise SystemExit(f"mutation scope mismatch: actual={actual} expected={expected}")

    branch = f"aios/autorepair/{proposal['run_id']}"
    git("config", "user.name", "AIOS Repair Worker")
    git("config", "user.email", "aios-repair-worker@users.noreply.github.com")
    git("switch", "-c", branch)
    git("add", "--", *expected)
    git("commit", "-m", f"fix: autonomous repair for CI run {proposal['run_id']}")
    print(branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
