# PR #140 — Ed25519 signer / permit integration gate

## Status

**BLOCKED — design and implementation must remain fail-closed.** This branch is intentionally based on the current PR #139 head. It does not activate a policy, issue a permit, access production secrets, or authorize materialization.

## Source facts reviewed at PR #139 head

- `.github/workflows/aios-research-absorb.yml` currently has one `scan-and-intake` job with `environment: production` at job scope. The job runs research, verification, runtime proof, promotion, and apply in the same job.
- That workflow passes `AIOS_PRODUCTION_EVIDENCE_SIGNING_SECRET` to verifier, runtime proof, promotion, and apply. This is incompatible with the intended isolated Ed25519 signer boundary.
- `research/absorption_verifier.py`, `research/absorption_runtime_proof.py`, and `research/absorption_promotion.py` still create or verify HMAC attestations using `AIOS_EVIDENCE_SIGNING_SECRET`.
- `research/absorption_apply.py::absorb` does not accept or verify an Ed25519 permit. It verifies legacy HMAC attestations and content digests, then creates the absorption outcome.
- `core/absorption_authority.py` supplies Ed25519 approval/permit primitives and checks approval plus repository/run/commit/artifact lineage. It is not yet called by the workflow or apply boundary.
- `policies/absorption-default-deny.v1.json` is `DRAFT_UNAPPROVED`, with `allowed_effects: []`; this state must remain a hard DENY.

## Required implementation sequence

1. Split the workflow into an unprivileged research/verification job, a protected signer job, and a public-key-only apply job. The signer job must be the only job with access to the new permit private-key secret. Do not pass any signing secret to verifier, runtime, promotion, or apply.
2. Replace HMAC artifact/evidence attestations with content-addressed artifacts whose exact digests are independently checked by the signer. The signer must validate trusted workflow/run metadata and must not execute candidate-controlled code.
3. Add an explicit governance approval record and governance public-key allowlist. The permit signer public key must also be pinned in a verifier keyring. Missing, empty, revoked, or unavailable keyrings mean DENY.
4. Make `absorption_apply.absorb` require and verify a permit before it can produce any absorbed record. Bind policy digest, repository, target branch, run ID, source commit SHA, exact artifact digest map, and permitted effect. Verify immediately before each effect.
5. Add adversarial tests for missing/forged/expired approvals, revoked and unknown keys, replayed run IDs, wrong commit, modified/missing/extra artifacts, wrong effect, and absent permit.
6. Ensure CI runs for PRs targeting `security/absorption-policy-ed25519-tests`, then run the full suite and inspect the resulting run logs on the exact PR #140 head.

## Merge / activation gates

- Keep PR #138, #139, and this PR in Draft until the above implementation and tests are complete.
- Do not merge this PR as an implementation-complete change while any legacy HMAC secret remains exposed outside the signer.
- Do not create or modify production secrets, key material, GitHub Environment protection, or approval records as part of this PR.
- Do not change the current policy from `DRAFT_UNAPPROVED` or populate `allowed_effects`.
- CI success alone is not evidence that the production signer boundary is enforced.
