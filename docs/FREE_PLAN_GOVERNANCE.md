# GitHub Free governance boundary

**Status: GOVERNANCE CONTROL GAP — production retry and promotion remain BLOCKED.**

This document records the actual security boundary when private supporting repositories are hosted on GitHub Free. It is a limitation record and operational policy, not a substitute for repository-enforced branch protection.

## Confirmed platform constraint

The owner observed GitHub's UI warning that rulesets on a private repository are not enforced unless the repository is in a GitHub Team organization account. Therefore, for private `AIOS-effect-state`, do not claim that a configured ruleset is active or that PR review/CODEOWNERS are enforced by GitHub.

A workflow check, CODEOWNERS file, PR template, signed commit, or a successful CI run does **not** provide equivalent protection against a repository owner/admin who can change the workflow, policy, or branch configuration.

The same limitation must be checked independently for each private repository. Do not infer enforcement from the existence of a ruleset configuration.

## Required state labels

- `CI_VERIFIED`: the named workflow ran successfully for the exact commit SHA.
- `CRYPTOGRAPHICALLY_VERIFIED`: an independent verifier checked the signature, digest, issuer identity, revocation state, and exact source binding against a separately pinned public key.
- `REPOSITORY_GOVERNANCE_ENFORCED`: GitHub confirms that required reviews/status checks/rulesets are actively enforced for the exact repository and ref.
- `PRODUCTION_E2E_VERIFIED`: live source publication, attestation, issuer, provider reconciliation, one-shot retry, receipt persistence, and restart/readback were exercised and independently evidenced.

These states are separate. Never derive one from another.

## Free-plan fail-closed operating policy

1. Keep private state and authority-store repositories private. Do not make them public to obtain free rulesets.
2. Treat private-repository ruleset enforcement as `UNKNOWN/UNAVAILABLE` until the repository settings UI/API positively demonstrates enforcement. Record the exact repository, ref, observed plan, date, and evidence.
3. Do not grant the executing agent write access to the authoritative state-source repository or the authority-store signing material.
4. Do not dispatch the attestor or retry issuer against production data while independent approval and repository governance are unavailable.
5. Keep production retry, automatic retry dispatch, and promotion disabled. A local unit/integration test or CI success cannot override this gate.
6. Require a separate operator to inspect the exact source commit, raw snapshot digest, attestation commit and first-parent relation, issuer identity/key fingerprint, authorization expiry, and final readback. Store the review record outside the repository being reviewed.
7. Pin public keys through an independently administered deployment configuration. Never trust a public-key candidate emitted by the same signing workflow.
8. Any missing, stale, conflicting, unreviewed, or unprovable input produces `BLOCKED`; do not retry by changing state or bypassing a failed gate.

## Evidence required to change status

A status change requires all of:
- Repository/ref-specific evidence that governance is actively enforced, or a documented independent control outside the repository owner/admin trust domain.
- Independent verification of the state-attestor and retry-issuer public-key fingerprints.
- Exact immutable source and attestation commit readback, including the required first-parent binding.
- Provider-authenticated `NOT_APPLIED` for the exact current `UNKNOWN` effect.
- One-shot retry, receipt persistence, replay rejection, and restart recovery evidence.
- A reviewer who did not create the issuer authorization.

Until then the authoritative state is:

```text
BRANCH_PROTECTION_UNAVAILABLE
ENVIRONMENT_APPROVAL_ENFORCEMENT_UNVERIFIED
PRODUCTION_RETRY_BLOCKED
PROMOTION_BLOCKED
```

## Residual risk

Under this fallback, a repository owner/admin can still alter repository workflows and documentation. External signatures and independently held keys protect authenticity of signed records, but they do not by themselves guarantee repository availability, branch immutability, or enforcement of human review. This residual risk is accepted only for development and audit preparation, not production authority or autonomous retry.
