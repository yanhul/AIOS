#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

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


def verify_pass_artifact(obj: dict, *, run_id: int, base_sha: str, pass_attempt: int) -> str:
    if obj.get("schema") != 3 or obj.get("run_id") != run_id or obj.get("base_sha") != base_sha:
        raise SystemExit("BLOCKED: repair result artifact is not bound to this run/base")
    if type(pass_attempt) is not int or pass_attempt not in (1, 2, 3):
        raise SystemExit("BLOCKED: selected repair attempt is outside the allowed range")
    attempts = obj.get("attempts")
    if (not isinstance(attempts, list) or
            any(type(x) is not int for x in attempts) or
            attempts != list(range(1, pass_attempt + 1))):
        raise SystemExit("BLOCKED: repair result artifact attempt sequence does not match selected attempt")
    test = obj.get("test")
    if not isinstance(test, dict) or test.get("status") != "PASS":
        raise SystemExit("BLOCKED: repair result artifact does not report PASS")
    evidence = test.get("evidence_refs")
    if (not isinstance(evidence, list) or not evidence or
            any(not isinstance(x, str) or not x.strip() for x in evidence)):
        raise SystemExit("BLOCKED: repair result artifact has no valid test evidence references")
    digest = obj.get("content_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise SystemExit("BLOCKED: repair result artifact has invalid content_sha256")
    return digest


def require_matching_source_digest(expected: str, actual: str) -> None:
    if actual != expected:
        raise SystemExit("BLOCKED: publish source tree differs from tested content_sha256")


def require_exact_publish_scope(expected, *, unstaged, staged, untracked) -> None:
    expected = set(expected)
    unstaged, staged, untracked = set(unstaged), set(staged), set(untracked)
    if unstaged or untracked or staged != expected:
        raise SystemExit(
            "BLOCKED: publish index/worktree scope mismatch; "
            f"unstaged={sorted(unstaged)} staged={sorted(staged)} "
            f"untracked={sorted(untracked)} expected={sorted(expected)}"
        )


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
    pass_attempt = int(os.environ["AIOS_REPAIR_PASS_ATTEMPT"])
    result_path = Path(os.environ["AIOS_REPAIR_RESULT_PATH"])
    result_obj = json.loads(result_path.read_text(encoding="utf-8"))
    expected_digest = verify_pass_artifact(
        result_obj, run_id=run_id, base_sha=base, pass_attempt=pass_attempt,
    )
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("stale repair publish base")

    proposal_dir = Path(os.environ.get("AIOS_REPAIR_PROPOSALS_DIR", "proposals"))
    proposal_files = sorted(proposal_dir.glob("repair-proposal-*.json"))
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
            Path("."), object(),
            allowed_test_commands=(("python", "-m", "pytest", "-q"),),
            timeout_seconds=1800, aios_dir=aios,
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

    # Recreate the source patch, bind it to the PASS digest, then retest at publish.
    before_retest = content_sha256(expected)
    require_matching_source_digest(expected_digest, before_retest)
    retest = worker.test()
    restored_test_artifacts = restore_test_generated_artifacts(git)
    print(json.dumps({"restored_test_generated_artifacts": list(restored_test_artifacts)}))
    if retest.status != "PASS":
        raise SystemExit(f"BLOCKED: publish-boundary re-test did not PASS: {retest.status}")
    after_retest = content_sha256(expected)
    require_matching_source_digest(expected_digest, after_retest)

    initial_staged = set(git("diff", "--cached", "--name-only").splitlines())
    if initial_staged:
        raise SystemExit(f"BLOCKED: pre-existing staged paths: {sorted(initial_staged)}")
    unstaged = set(git("diff", "--name-only").splitlines())
    untracked = set(git("ls-files", "--others", "--exclude-standard").splitlines())
    if unstaged | untracked != expected:
        raise SystemExit(f"BLOCKED: mutation scope mismatch: actual={sorted(unstaged | untracked)} expected={sorted(expected)}")

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
    require_exact_publish_scope(
        expected,
        unstaged=git("diff", "--name-only").splitlines(),
        staged=git("diff", "--cached", "--name-only").splitlines(),
        untracked=git("ls-files", "--others", "--exclude-standard").splitlines(),
    )
    git("commit", "-m", f"fix: autonomous repair for CI run {run_id}", "-m", f"AIOS-REPAIR-CYCLE: {cycle}")
    print(branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
