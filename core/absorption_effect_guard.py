"""Effect-level Ed25519 permit enforcement for absorption materialization."""
from __future__ import annotations
from typing import Any, Mapping
from core.absorption_authority import verify_absorption_permit, AbsorptionAuthorizationError


def authorize_absorption_effect(*, permit: Mapping[str, Any], permit_keyring: Mapping[str, Any],
                                policy: Mapping[str, Any], repository: str, target_branch: str,
                                run_id: str, source_commit_sha: str,
                                artifact_digests: Mapping[str, str], effect: str,
                                now: int | None = None) -> bool:
    """Verify exact permit scope and deny any effect not explicitly authorized by policy."""
    if not isinstance(effect, str) or not effect.strip():
        raise AbsorptionAuthorizationError("effect identity missing; DENY")
    verify_absorption_permit(
        permit=permit, permit_keyring=permit_keyring, policy=policy,
        repository=repository, target_branch=target_branch, run_id=run_id,
        source_commit_sha=source_commit_sha, artifact_digests=artifact_digests, now=now,
    )
    allowed = policy.get("decision", {}).get("allowed_effects")
    if not isinstance(allowed, list) or effect not in allowed:
        raise AbsorptionAuthorizationError(f"effect {effect!r} is not authorized by policy; DENY")
    return True
