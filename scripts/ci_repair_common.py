"""Trusted helpers shared by the autonomous CI repair workflow jobs.

These run only from the trusted ``main`` checkout. Proposed code is never
imported here; it is only written to disk as validated text.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from core.authority import AUTHORITY_ATTESTATION_SECRET_ENV, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.policy_registry import persist_policy
from core.try_repair_provider import TryRepairProviderError, validate_proposal

APPLY_RECORD_KIND = "AIOS_CI_REPAIR_APPLY"
_EFFECT_STATE_DIRS = {"authority", "capabilities", "effects", "policies"}


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


@contextmanager
def repair_state_dir():
    """AIOS state for one job; kept at AIOS_REPAIR_STATE_DIR so it can be uploaded as evidence."""
    keep = os.environ.get("AIOS_REPAIR_STATE_DIR")
    if keep:
        path = Path(keep)
        path.mkdir(parents=True, exist_ok=False)
        yield path
        return
    with tempfile.TemporaryDirectory(prefix="aios-repair-authority-") as td:
        path = Path(td) / "aios"
        path.mkdir()
        yield path


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


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def verify_repair_chain(aios_dir: Path, *, contract_id: str, permit_id: str,
                        input_digest: str, proposals, results) -> dict:
    """Re-verify permit/attestation, effect receipts and AIOS state after applying.

    Fails closed (SystemExit) unless every link holds; returns the evidence report.
    """
    from core.authority import authorize, load_attestation, load_contract
    from core.reconcile import reconcile
    from core.repository_patch_adapter import _sha256_patch
    from core.agent_repair_worker import ProposedFile

    aios = str(aios_dir)
    failures = []
    authorize(aios, contract_id, permit_id)
    contract = load_contract(aios, contract_id)
    attestation = load_attestation(aios, permit_id)
    if contract.get("input_digest") != input_digest:
        failures.append("contract input_digest is not the proposals digest")

    effects = []
    for proposal, result in zip(proposals, results, strict=True):
        effect_id = result.get("effect_id", "")
        obs = (result.get("provider_observation") or {}).get("observation") or {}
        files = tuple(ProposedFile(f["path"], f["content"]) for f in proposal["files"])
        expected_changed = sorted(({"path": f.path, "content_sha256": _sha256_text(f.content)} for f in files),
                                  key=lambda x: x["path"])
        stored_path = Path(aios) / "effects" / f"{effect_id}.json"
        stored = json.loads(stored_path.read_text(encoding="utf-8")) if stored_path.is_file() else {}
        events = sorted(p.name for p in (Path(aios) / "events").glob(f"*{effect_id}*.json"))
        checks = {
            "state_observed_success": result.get("state") == "OBSERVED_SUCCESS",
            "bound_to_permit": result.get("contract_id") == contract_id and result.get("permit_id") == permit_id,
            "receipt_authenticated": isinstance((result.get("provider_observation") or {}).get("provider_authentication"), dict),
            "patch_digest_matches_proposal": obs.get("patch_digest") == _sha256_patch(files),
            "changed_files_match_proposal": sorted(obs.get("changed") or [], key=lambda x: x["path"]) == expected_changed,
            "persisted_effect_matches_result": stored.get("state") == result.get("state") == "OBSERVED_SUCCESS",
            "lifecycle_events_present": len(events) == 3 and any(e.endswith("-OBSERVED_SUCCESS.json") for e in events),
        }
        if result.get("state") != "OBSERVED_SUCCESS":
            failures.append(f"attempt {proposal['attempt']}: effect state {result.get('state')}: "
                            f"{result.get('unknown_reason', '')[:200]}")
        failures += [f"attempt {proposal['attempt']}: {name}" for name, ok in checks.items() if not ok]
        effects.append({"attempt": proposal["attempt"], "effect_id": effect_id, "state": result.get("state"),
                        "patch_digest": obs.get("patch_digest"),
                        "receipt_id": ((result.get("provider_observation") or {}).get("provider_authentication") or {}).get("receipt_id"),
                        "events": events, "checks": checks})

    swept = reconcile(aios)
    # reconcile() models the mutation store only (entities/events/snapshots); authority,
    # capability, policy and effect state plus effect lifecycle events are verified above.
    unmodeled = [f for f in swept["findings"]
                 if (f["check"] == "D.event_digest" and "(effect-" in f["detail"])
                 or (f["check"] == "G.unexpected_entry"
                     and f["detail"].rsplit(": ", 1)[-1] in _EFFECT_STATE_DIRS)]
    other = [f for f in swept["findings"] if f not in unmodeled]
    if other:
        failures.append(f"reconcile findings: {other[:5]}")
    report = {
        "contract_id": contract_id, "permit_id": permit_id, "input_digest": input_digest,
        "permit_issuer": attestation.get("issuer"), "authorize": "VERIFIED",
        "effects": effects,
        "reconcile": {"overall": swept["overall"], "not_modeled_by_reconcile": unmodeled, "other_findings": other},
        "failures": failures,
    }
    if failures:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        raise SystemExit("BLOCKED: repair chain verification failed: " + "; ".join(failures[:5]))
    return report
