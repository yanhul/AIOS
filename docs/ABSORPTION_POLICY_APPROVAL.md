# Absorption policy approval and enforcement

The initial artifact at `policies/absorption-default-deny.v1.json` is a **draft**, not an active authorization. Its `allowed_effects` list is empty. The non-effect operations listed there do not authorize writes or production effects.

## Activation protocol

1. Canonicalize the complete policy using `core.mutation.canonical_json`.
2. Persist it with `core.policy_registry.persist_policy`; record the returned `sha256:` digest.
3. An authorized human reviews the exact digest and the full policy contents.
4. Record a separate approval attestation that binds the exact policy digest, repository, target branch, allowed effects, and expiry. The approver identity must be resolved against an explicit governance allowlist; a GitHub workflow success, commit author, PR author, or signer identity is not approval by itself.
5. The isolated Ed25519 signer independently resolves and re-hashes the policy, validates the approval attestation and approver authorization, checks expiry/revocation, and revalidates the workflow run, source commit, and artifact digests. Any missing, stale, ambiguous, or invalid input is DENY.
6. Only after these checks may the signer sign a permit. The runtime receives only the public key and must verify the signature and exact scope immediately before each effect.

## Non-negotiable defaults

- No source, policy, contract, or capability-registry mutation.
- No permit issuance or production execution under this draft.
- No automatic promotion or materialization.
- No candidate-controlled code execution.
- Missing approval, unknown approver, expired approval, key mismatch, or unavailable revocation state means DENY.

## Scope of this change

This document and policy artifact establish a reviewable default-deny proposal. They do not claim that the current workflow enforces this approval protocol. The signer, verifier, runtime authorization, and approval lookup must be implemented and tested before the policy can become active.
