"""Trusted helpers shared by the autonomous CI repair workflow jobs.

These run only from the trusted ``main`` checkout. Proposed code is never
imported here; it is only written to disk as validated text.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from core.authority import AUTHORITY_ATTESTATION_SECRET_ENV, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.policy_registry import persist_policy
from core.try_repair_provider import TryRepairProviderError, validate_proposal

APPLY_RECORD_KIND = "AIOS_CI_REPAIR_APPLY"


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], text=True, capture_output=True, check=True)
    return p.stdout.strip()


def changed_paths() -> set[str]:
    tracked = git("diff", "--name-only").splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    return {p for p in (*tracked, *untracked) if p}


def load_proposals(paths, base_sha: str) -> list[dict]:
    proposals = []
    for path in paths:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
        try:
            proposal = validate_proposal(obj)
        except TryRepairProviderError as exc:
            raise SystemExit(f"BLOCKED: invalid repair proposal {path}: {exc}") from exc
        if proposal.get("status") == "HOLD":
            raise SystemExit(f"BLOCKED: repair proposal {path} is a HOLD")
        if proposal.get("base_sha") != base_sha:
            raise SystemExit("BLOCKED: cumulative repair proposal has stale base SHA")
        if not all(isinstance(f.get("content"), str) for f in proposal["files"]):
            raise SystemExit(f"BLOCKED: repair proposal {path} has non-text content")
        proposals.append(proposal)
    proposals.sort(key=lambda p: int(p["attempt"]))
    if [int(p["attempt"]) for p in proposals] != list(range(1, len(proposals) + 1)):
        raise SystemExit("BLOCKED: repair proposals are not a contiguous cumulative sequence")
    return proposals


def proposals_digest(proposals) -> str:
    material = [
        {"attempt": int(p["attempt"]), "base_sha": p["base_sha"],
         "files": [{"path": f["path"], "content": f["content"]} for f in p["files"]]}
        for p in proposals
    ]
    raw = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def expected_paths(proposals) -> set[str]:
    return {f["path"] for p in proposals for f in p["files"]}


def tree_digests(root: Path, paths) -> dict[str, str]:
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in sorted(paths)}


def issue_repair_authority(root: Path, *, actor: str, task_id: str, input_digest: str):
    """Issue an attested permit bound to the exact proposals being applied.

    Only trusted jobs that never execute proposed code receive the secret.
    """
    secret = os.environ.get(AUTHORITY_ATTESTATION_SECRET_ENV)
    if not secret or len(secret) < 16:
        raise SystemExit(f"BLOCKED: {AUTHORITY_ATTESTATION_SECRET_ENV} is not configured for this trusted job")
    registry = CapabilityRegistry()
    registry.register(Capability("repo_patch", "1", "AIOS", "external_effect",
                                 inputs=("patch",), outputs=("observation",), status="ACTIVE"))
    registry.persist(root, actor=actor)
    policy_digest = persist_policy(root, {
        "policy_type": "GOVERNING_POLICY", "task": "ci-repair",
        "allowed_effects": ["external_effect"],
    })
    contract = {
        "contract_type": CONTRACT_TYPE, "task_id": task_id,
        "scope": "repository", "actor": actor, "capabilities": ["repo_patch@1"],
        "input_digest": input_digest, "allowed_effects": ["external_effect"],
        "evidence_required": ["OBSERVED"], "max_attempts": 2,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": policy_digest,
    }
    stored = persist_contract(root, contract)
    permit = persist_permit(root, stored, issuer="ci-repair-authority")
    return stored["contract_id"], permit["permit_id"]
