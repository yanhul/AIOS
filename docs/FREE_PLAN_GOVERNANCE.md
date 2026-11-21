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

## Decision: owner-reviewed pilot (approved)

Use a **manual owner-reviewed pilot** to unblock integration work without purchasing GitHub Team. This is an explicit, limited trust assumption—not equivalent to branch protection.

Pilot rules:
1. The repository owner manually initiates the test workflow and reviews the exact PR/commit before any test artifact is accepted.
2. Pilot data must be synthetic. Use ephemeral Ed25519 keypairs generated inside the test process; never use production keys, real effect records, production tokens, or live provider credentials.
3. The pilot may exercise the complete software path: UNKNOWN fixture → signed snapshot attestation → retry authorization → AIOS import → provider-authenticated NOT_APPLIED test proof → one-shot retry → receipt persistence → restart/readback → replay rejection.
4. The test must assert exact source SHA, attestation parent binding, trust-key separation, signature verification, CAS/single-use consumption, and durable receipt.
5. Owner review is recorded as an operator action in the PR/release evidence. Because GitHub does not enforce it on this private Free repository, label it `MANUAL_OWNER_REVIEWED`, never `REPOSITORY_GOVERNANCE_ENFORCED`.
6. Pilot success is `PILOT_E2E_VERIFIED` only. It does not authorize production issuance, retry, promotion, or merge to an authoritative branch.

Exit criteria: all pilot assertions pass on one pinned commit and the test artifact/logs are retained. Production remains blocked until independent governance, production key custody, and live provider E2E are separately proven.
