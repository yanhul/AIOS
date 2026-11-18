# Absorption signer / verifier contract

## Trust separation

- Governance approval is a separate Ed25519 signature over the exact policy digest, repository, target branch, allowed effects, approver identity, and expiry.
- The governance public-key allowlist is verifier/signer input. Unknown, revoked, malformed, or unavailable trust state is DENY.
- The permit signer uses a different Ed25519 private key. Its private key must be available only to a protected GitHub Actions Environment signer job. No executor, verifier, apply, runtime, or candidate-controlled step receives it.
- Runtime and verifier jobs receive public keys only.
- The signer must run trusted, pinned code and must not checkout or execute candidate-controlled scripts. It independently fetches/validates the policy, approval, run metadata, commit, and immutable artifact digests before signing.

## Implemented library boundary

`core.absorption_authority` implements:
- policy digest and default-deny/approved-state checks;
- human approval attestation creation and verification;
- allowlisted/revocation-aware Ed25519 key verification;
- repository/run/commit/artifact lineage checks;
- Ed25519 permit signing and public-key-only permit verification.

The signing function accepts data structures only; it has no subprocess, network, filesystem, or candidate-code execution path.

## Deliberate activation block

The checked-in policy remains `DRAFT_UNAPPROVED`, with `allowed_effects: []`. It cannot pass the approval or permit-signing preconditions. No approval key, signer private key, production secret, or production workflow is created by this change.

## Integration still required before activation

The existing absorption workflow still has legacy HMAC secret distribution and direct apply flow. This library does not silently replace that workflow. Before activation, split it into unprivileged research/verification jobs and a protected signer job, pass only immutable artifact IDs/digests, then require public-key verification plus `core.authority.authorize` / permit checks at the apply boundary. Reduce workflow permissions to job-level minimums and remove signing secrets from all non-signer jobs.
