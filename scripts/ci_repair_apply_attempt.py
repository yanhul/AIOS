#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from core.agent_repair_worker import AgentRepairWorker, ProposedFile
from core.authority import authorize, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.effect_authority import ProviderKeyring
from core.policy_registry import persist_policy
from core.provider_authority import ProviderReceiptSigner


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], text=True, capture_output=True, check=True)
    return p.stdout.strip()


def authority(root: Path, actor: str, run_id: int, base_sha: str, repository: str):
    registry = CapabilityRegistry()
    registry.register(Capability("repo_patch", "1", "AIOS", "external_effect",
                                 inputs=("patch",), outputs=("observation",), status="ACTIVE"))
    registry.persist(root, actor=actor)
    policy_digest = persist_policy(root, {
        "policy_type": "GOVERNING_POLICY", "task": "ci-repair",
        "allowed_effects": ["external_effect"],
    })
    input_digest = "sha256:" + hashlib.sha256(f"ci-failure:{repository}:{run_id}:{base_sha}".encode()).hexdigest()
    contract = {
        "contract_type": CONTRACT_TYPE, "task_id": f"ci-repair-{actor}-{run_id}",
        "scope": "repository", "actor": actor, "capabilities": ["repo_patch@1"],
        "input_digest": input_digest, "allowed_effects": ["external_effect"],
        "evidence_required": ["OBSERVED"], "max_attempts": 3,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": policy_digest,
    }
    stored = persist_contract(root, contract)
    # No authority private key exists in GitHub Actions. The permit is recorded
    # unattested; execution stays BLOCKED until the external authority signer
    # attests it (scripts/aios_authority_signer.py, separate service account).
    permit = persist_permit(root, stored, issuer="ci-repair-authority")
    try:
        authorize(str(root), stored["contract_id"], permit["permit_id"])
    except Exception as exc:
        raise SystemExit("BLOCKED: repair permit requires an attestation from the external AIOS "
                         f"authority signer ({permit['permit_id']}): {exc}") from None
    return stored["contract_id"], permit["permit_id"]


def main() -> int:
    base = os.environ["AIOS_REPAIR_SHA"]
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    repository = os.environ["GITHUB_REPOSITORY"]
    paths = [Path(x) for x in os.environ["AIOS_REPAIR_PROPOSALS"].split(",") if x]
    proposals = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    if not proposals:
        raise SystemExit("no repair proposals")
    if git("rev-parse", "HEAD") != base:
        raise SystemExit("repair proposal base SHA does not match checkout")
    for expected_attempt, proposal in enumerate(proposals, 1):
        if (proposal.get("schema") != 2 or proposal.get("base_sha") != base
                or proposal.get("run_id") != run_id or proposal.get("repository") != repository):
            raise SystemExit("repair proposal schema/run/base binding mismatch")
        if int(proposal.get("attempt", -1)) != expected_attempt:
            raise SystemExit("repair proposals must be contiguous attempts starting at 1")
        if not isinstance(proposal.get("files"), list) or not proposal["files"]:
            raise SystemExit("repair proposal contains no files")

    authority_dir = Path(os.environ["AIOS_REPAIR_AUTHORITY_DIR"]).resolve()
    authority_dir.mkdir(parents=True, exist_ok=True)
    if any(authority_dir.iterdir()):
        raise SystemExit("AIOS_REPAIR_AUTHORITY_DIR must be empty at the start of an apply job")
    if not os.environ.get("AIOS_AUTHORITY_TRUSTED_KEYS"):
        raise SystemExit("AIOS_AUTHORITY_TRUSTED_KEYS (public Ed25519 keyring) is required")
    signing_spec = json.loads(os.environ.get("AIOS_PROVIDER_SIGNING_KEYS", "{}"))
    verifier_spec = json.loads(os.environ.get("AIOS_PROVIDER_KEYRING", "{}"))
    signing_secret = signing_spec.get("repo_patch") if isinstance(signing_spec, dict) else None
    verifier_entry = verifier_spec.get("repo_patch") if isinstance(verifier_spec, dict) else None
    if not isinstance(signing_secret, str) or len(signing_secret) < 16:
        raise SystemExit("AIOS_PROVIDER_SIGNING_KEYS must contain a repo_patch secret")
    if not isinstance(verifier_entry, dict) or verifier_entry.get("secret") != signing_secret:
        raise SystemExit("AIOS_PROVIDER_KEYRING repo_patch trust anchor must match the provider signer")
    signer = ProviderReceiptSigner.from_env("repo_patch")
    provider_keyring = ProviderKeyring.from_env()
    if signer is None or provider_keyring is None:
        raise SystemExit("both AIOS_PROVIDER_SIGNING_KEYS and AIOS_PROVIDER_KEYRING must trust repo_patch")
    provider_keyring.secret_for("repo_patch", "provider.receipt.sign")

    actor = "ci-repair-worker"
    contract_id, permit_id = authority(authority_dir, actor, run_id, base, repository)
    worker = AgentRepairWorker(
        Path("."), object(),
        allowed_test_commands=(("python", "-m", "pytest", "-q"),),
        timeout_seconds=900, aios_dir=authority_dir,
        contract_id=contract_id, permit_id=permit_id, actor=actor,
        provider_keyring=provider_keyring,
    )
    applied = []
    effects = []
    owned = frozenset()
    for proposal in proposals:
        files = tuple(ProposedFile(x["path"], x["content"]) for x in proposal["files"])
        result = worker.apply_via_aios(
            base_sha=base, files=files,
            logical_operation_id=f"ci-repair:{run_id}:attempt:{proposal['attempt']}",
            allowed_dirty_paths=owned,
        )
        if result.get("state") != "OBSERVED_SUCCESS":
            raise SystemExit(f"AIOS effect did not reach OBSERVED_SUCCESS: {result.get('state')} {result.get('unknown_reason', '')}")
        effect_id = result.get("effect_id")
        if not isinstance(effect_id, str) or not effect_id:
            raise SystemExit("AIOS result is missing effect_id")
        applied.append({"attempt": proposal["attempt"], "result": dict(result)})
        effects.append({"attempt": proposal["attempt"], "effect_id": effect_id})
        owned = frozenset(set(owned) | {x.path for x in files})

    apply_result = {
        "schema": 1, "status": "PATCH_APPLIED_RECEIPTS_ACCEPTED", "run_id": run_id,
        "repository": repository, "base_sha": base,
        "contract_id": contract_id, "permit_id": permit_id,
        "attempts": [p["attempt"] for p in proposals], "effects": effects,
        "applied": applied,
    }
    Path("repair-apply-result.json").write_text(
        json.dumps(apply_result, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({"status": apply_result["status"], "effects": len(effects),
                      "authority_store": str(authority_dir)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
