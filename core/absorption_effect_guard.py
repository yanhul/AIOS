"""Effect-level Ed25519 permit enforcement with a separate writer-job receipt.

The ledger write is performed only in the dedicated writer job. Production
verifies the receipt from that job and never receives the writer credential.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping
from core.absorption_authority import verify_absorption_permit, AbsorptionAuthorizationError
from core.mutation import canonical_json


def _verify_replay_receipt(*, permit: Mapping[str, Any], target_apply_run_id: str) -> bool:
    path = os.environ.get("AIOS_REPLAY_RECEIPT_PATH", "")
    if not path:
        raise AbsorptionAuthorizationError("writer replay receipt missing; DENY")
    try:
        receipt = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise AbsorptionAuthorizationError("writer replay receipt unreadable; DENY") from exc
    permit_id = hashlib.sha256(canonical_json(dict(permit)).encode("utf-8")).hexdigest()
    expected = {
        "schema_version": 2,
        "permit_id": permit_id,
        "target_apply_run_id": target_apply_run_id,
        "continuation_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "ledger_repository": "yanhul/AIOS-replay-ledger",
        "ledger_branch": "main",
        "writer_job": "verify-merged-ledger",
        "consumed": True,
    }
    if not isinstance(receipt, Mapping) or any(receipt.get(k) != v for k, v in expected.items()):
        raise AbsorptionAuthorizationError("writer replay receipt binding mismatch; DENY")
    if (isinstance(receipt.get("ledger_pr_number"), bool) or
            not isinstance(receipt.get("ledger_pr_number"), int) or receipt["ledger_pr_number"] < 1 or
            not isinstance(receipt.get("ledger_merge_commit_sha"), str) or
            len(receipt["ledger_merge_commit_sha"]) != 40 or
            not isinstance(receipt.get("ledger_entry_digest"), str) or
            len(receipt["ledger_entry_digest"]) != 64 or
            not isinstance(receipt.get("verified_at"), int)):
        raise AbsorptionAuthorizationError("post-merge ledger proof fields missing or malformed; DENY")
    return True


def authorize_absorption_effect(*, permit: Mapping[str, Any], permit_keyring: Mapping[str, Any],
                                policy: Mapping[str, Any], repository: str, target_branch: str,
                                run_id: str, source_commit_sha: str,
                                artifact_digests: Mapping[str, str], target_apply_run_id: str, effect: str,
                                now: int | None = None) -> bool:
    """Verify permit scope and require proof from the isolated writer job."""
    if not isinstance(effect, str) or not effect.strip():
        raise AbsorptionAuthorizationError("effect identity missing; DENY")
    continuation_run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not continuation_run_id:
        raise AbsorptionAuthorizationError("current continuation workflow run identity missing; DENY")
    verify_absorption_permit(
        permit=permit, permit_keyring=permit_keyring, policy=policy,
        repository=repository, target_branch=target_branch, run_id=run_id,
        source_commit_sha=source_commit_sha, artifact_digests=artifact_digests,
        target_apply_run_id=target_apply_run_id, now=now,
    )
    allowed = policy.get("decision", {}).get("allowed_effects")
    if not isinstance(allowed, list) or effect not in allowed:
        raise AbsorptionAuthorizationError(f"effect {effect!r} is not authorized by policy; DENY")
    _verify_replay_receipt(permit=permit, target_apply_run_id=target_apply_run_id)
    return True
