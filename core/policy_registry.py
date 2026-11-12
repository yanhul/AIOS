"""Content-addressed governing-policy registry.

Policy digests are authority references only when the corresponding immutable
policy artifact exists in the local authority store and hashes to that digest.
A caller cannot self-authorize an arbitrary policy digest.
"""
import hashlib
import os

from .mutation import _committed_state, canonical_json, commit_batch, read_state_json, recover_pending

POLICIES_DIR = "policies"
POLICY_TYPE = "GOVERNING_POLICY"


def _policy_filename(digest):
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("policy digest must be a sha256 content digest")
    return "sha256-" + digest.split(":", 1)[1] + ".json"


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
    record = dict(policy)
    record["policy_digest"] = digest
    if _committed_state(aios_dir, os.path.join(POLICIES_DIR, _policy_filename(digest))):
        existing = read_state_json(aios_dir, os.path.join(POLICIES_DIR, _policy_filename(digest)))
        if canonical_json(existing) != canonical_json(record):
            raise ValueError("existing policy identity has different content")
        return digest
    commit_batch(aios_dir, [(os.path.join(POLICIES_DIR, _policy_filename(digest)), record)])
    return digest


def resolve_policy(aios_dir, digest):
    """Resolve and re-hash an immutable policy artifact; fail closed."""
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("policy digest must be a sha256 content digest")
    path = f"{POLICIES_DIR}/{_policy_filename(digest)}"
    legacy_path = f"{POLICIES_DIR}/{digest}.json"
    policy = None
    for candidate in (path, legacy_path):
        # Unsafe entries (symlink / special / untrusted dir) raise
        # StateConflictError: never followed, never treated as "not found".
        try:
            policy = read_state_json(aios_dir, candidate)
            break
        except FileNotFoundError:
            continue
        except ValueError:  # invalid JSON / encoding: try legacy, else fail
            continue
    if policy is None:
        raise ValueError("governing policy artifact not found")
    if policy.get("policy_digest") != digest:
        raise ValueError("stored governing policy digest mismatch")
    content = dict(policy)
    content.pop("policy_digest", None)
    if policy_digest(content) != digest:
        raise ValueError("governing policy content hash mismatch")
    return policy


__all__ = ["POLICY_TYPE", "policy_digest", "persist_policy", "resolve_policy"]
