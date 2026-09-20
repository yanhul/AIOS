#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile

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
        "contract_type": CONTRACT_TYPE, "task_id": f"ci-repair-{actor}-{run_id}",
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
    paths = [Path(x) for x in os.environ["AIOS_REPAIR_PROPOSALS"].split(",") if x]
    proposals = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    if not proposals:
        raise SystemExit("no repair proposals")
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("repair proposal base SHA does not match checkout")
    for p in proposals:
        if p["base_sha"] != base:
            raise SystemExit("cumulative repair proposal has stale base SHA")

    with tempfile.TemporaryDirectory(prefix="aios-repair-authority-") as td:
        aios = Path(td) / "aios"
        aios.mkdir()
        contract_id, permit_id = authority(aios, "ci-repair-worker", run_id)
        worker = AgentRepairWorker(
            Path("."), object(),
            allowed_test_commands=(("python", "-m", "pytest", "-q"),),
            timeout_seconds=900, aios_dir=aios,
            contract_id=contract_id, permit_id=permit_id, actor="ci-repair-worker",
        )
        applied = []
        owned = frozenset()
        for idx, proposal in enumerate(proposals, 1):
            files = tuple(ProposedFile(x["path"], x["content"]) for x in proposal["files"])
            result = worker.apply_via_aios(
                base_sha=base, files=files,
                logical_operation_id=f"ci-repair:{run_id}:attempt:{proposal['attempt']}",
                allowed_dirty_paths=owned,
            )
            applied.append({"attempt": proposal["attempt"], "result": dict(result)})
            owned = frozenset(set(owned) | {x.path for x in files})
        tested = worker.test()

    result = {
        "schema": 2, "run_id": run_id, "base_sha": base,
        "attempts": [p["attempt"] for p in proposals],
        "applied": applied,
        "test": {
            "status": tested.status,
            "evidence_refs": list(tested.evidence_refs),
            "details": dict(tested.details),
        },
    }
    Path("repair-result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": tested.status, "attempts": result["attempts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
