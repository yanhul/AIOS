"""Content-addressed governing-policy registry.

Policy digests are authority references only when the corresponding immutable
policy artifact exists in the local authority store and hashes to that digest.
A caller cannot self-authorize an arbitrary policy digest.
"""
import hashlib
import os

from .mutation import canonical_json, commit_batch, recover_pending

POLICIES_DIR = "policies"
POLICY_TYPE = "GOVERNING_POLICY"


def policy_digest(policy):
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")
    return "sha256:" + hashlib.sha256(canonical_json(policy).encode("utf-8")).hexdigest()


def persist_policy(aios_dir, policy):
    """Persist an immutable policy artifact and return its content digest."""
    if not isinstance(policy, dict) or policy.get("policy_type") != POLICY_TYPE:
        raise ValueError("policy must be a governing policy artifact")
    digest = policy_digest(policy)
    recover_pending(aios_dir)
    path = os.path.join(aios_dir, POLICIES_DIR, digest + ".json")
    record = dict(policy)
    record["policy_digest"] = digest
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = __import__("json").load(fh)
        if canonical_json(existing) != canonical_json(record):
            raise ValueError("existing policy identity has different content")
        return digest
    commit_batch(aios_dir, [(os.path.join(POLICIES_DIR, digest + ".json"), record)])
    return digest


def resolve_policy(aios_dir, digest):
    """Resolve and re-hash an immutable policy artifact; fail closed."""
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("policy digest must be a sha256 content digest")
    path = os.path.join(aios_dir, POLICIES_DIR, digest + ".json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            policy = __import__("json").load(fh)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ValueError("governing policy artifact not found") from exc
    if policy.get("policy_digest") != digest:
        raise ValueError("stored governing policy digest mismatch")
    content = dict(policy)
    content.pop("policy_digest", None)
    if policy_digest(content) != digest:
        raise ValueError("governing policy content hash mismatch")
    return policy


__all__ = ["POLICY_TYPE", "policy_digest", "persist_policy", "resolve_policy"]
