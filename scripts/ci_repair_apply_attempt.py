#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import stat

from core.agent_repair_worker import AgentRepairWorker, ProposedFile
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.policy_registry import persist_policy
from scripts.ci_repair_test_hygiene import restore_test_generated_artifacts


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], text=True, capture_output=True, check=True)
    return p.stdout.strip()


def content_sha256(paths) -> str:
    # Include newly-created files too; git diff alone omits untracked paths.
    digest = hashlib.sha256()
    for raw in sorted(set(paths)):
        path = Path(raw)
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"BLOCKED: repair source path is not a regular file: {raw}")
        data = path.read_bytes()
        mode = stat.S_IMODE(path.stat().st_mode)
        name = raw.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def authority(root: Path, actor: str, run_id: int):
    """Do not mint local authority for a privileged repository mutation.

    The separately governed aios-authority-store currently declares itself
    NOT READY / NOT VERIFIED and has no provisioned issuer. Until a verified
    external contract/permit/attestation bundle is integrated, repair must
    stop here rather than self-promote repo_patch@1 or self-issue a permit.
    """
    raise SystemExit(
        "BLOCKED: external AIOS authority issuer/store is not provisioned; "
        "ephemeral self-issued capability, policy, contract, and permit are forbidden"
    )


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
            timeout_seconds=1800, aios_dir=aios,
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
    restored_test_artifacts = restore_test_generated_artifacts(git)
    tested_content_sha256 = content_sha256(x["path"] for proposal in proposals for x in proposal["files"])

    result = {
        "schema": 3, "run_id": run_id, "base_sha": base,
        "content_sha256": tested_content_sha256,
        "restored_test_generated_artifacts": list(restored_test_artifacts),
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
