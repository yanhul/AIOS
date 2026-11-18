"""Effect-level Ed25519 permit enforcement for absorption materialization.

A valid signature is not one-time authorization. Until a durable, atomic
permit-consumption backend is configured, this guard deliberately DENIES every
materialization effect. Do not replace this fail-closed boundary with a
process-local set, temporary file, or caller-supplied boolean.
"""
from __future__ import annotations
from typing import Any, Mapping
from core.absorption_authority import verify_absorption_permit, AbsorptionAuthorizationError
from core.absorption_replay_store import consume_permit_once, ReplayStoreError


def authorize_absorption_effect(*, permit: Mapping[str, Any], permit_keyring: Mapping[str, Any],
                                policy: Mapping[str, Any], repository: str, target_branch: str,
                                run_id: str, source_commit_sha: str,
                                artifact_digests: Mapping[str, str], target_apply_run_id: str, effect: str,
                                now: int | None = None) -> bool:
    """Verify scope, then fail closed because atomic replay protection is unavailable."""
    if not isinstance(effect, str) or not effect.strip():
        raise AbsorptionAuthorizationError("effect identity missing; DENY")
    verify_absorption_permit(
        permit=permit, permit_keyring=permit_keyring, policy=policy,
        repository=repository, target_branch=target_branch, run_id=run_id,
        source_commit_sha=source_commit_sha, artifact_digests=artifact_digests,
        target_apply_run_id=target_apply_run_id, now=now,
    )
    allowed = policy.get("decision", {}).get("allowed_effects")
    if not isinstance(allowed, list) or effect not in allowed:
        raise AbsorptionAuthorizationError(f"effect {effect!r} is not authorized by policy; DENY")
    try:
        consume_permit_once(permit=permit, repository=repository, now=now)
    except ReplayStoreError as exc:
        raise AbsorptionAuthorizationError(str(exc)) from exc
    return True
