# PR #140 — Ed25519 signer / permit integration gate

## Status

**DRAFT / BLOCKED — partial implementation added, end-to-end integration not complete.** This branch is based on PR #139. The signer workflow and apply-time Ed25519 guard are present, but no policy is activated, no permit is issued, and no production secret is accessed or changed.

## Source facts reviewed at PR #139 head

- `.github/workflows/aios-research-absorb.yml` currently has one `scan-and-intake` job with `environment: production` at job scope. The job runs research, verification, runtime proof, promotion, and apply in the same job.
- That workflow passes `AIOS_PRODUCTION_EVIDENCE_SIGNING_SECRET` to verifier, runtime proof, promotion, and apply. This is incompatible with the intended isolated Ed25519 signer boundary.
- `research/absorption_verifier.py`, `research/absorption_runtime_proof.py`, and `research/absorption_promotion.py` still create or verify HMAC attestations using `AIOS_EVIDENCE_SIGNING_SECRET`.
- `research/absorption_apply.py` now calls an Ed25519 effect guard before each candidate materialization. It still retains legacy HMAC checks, so it is not yet public-key-only.
- `core/absorption_authority.py` supplies Ed25519 approval/permit primitives. The new `core/absorption_effect_guard.py` wires permit verification into the apply loop. The separate signer workflow is not yet sequenced before apply in the existing research workflow.
- `policies/absorption-default-deny.v1.json` is `DRAFT_UNAPPROVED`, with `allowed_effects: []`; this state must remain a hard DENY.

## Required implementation sequence

1. Split the workflow into an unprivileged research/verification job, a protected signer job, and a public-key-only apply job. The signer job must be the only job with access to the new permit private-key secret. Do not pass any signing secret to verifier, runtime, promotion, or apply.
2. Replace HMAC artifact/evidence attestations with content-addressed artifacts whose exact digests are independently checked by the signer. The signer must validate trusted workflow/run metadata and must not execute candidate-controlled code.
3. Add an explicit governance approval record and governance public-key allowlist. The permit signer public key must also be pinned in a verifier keyring. Missing, empty, revoked, or unavailable keyrings mean DENY.
4. Complete the apply integration: remove legacy HMAC requirements from apply and its upstream gates, bind the signer output to the exact same source run and artifacts, and ensure the apply job consumes the signer artifact before any effect. The current guard checks the permit immediately before each candidate effect, but the workflow does not yet connect signer output to apply.
5. Expand adversarial tests for forged/expired approvals, revoked and unknown keys, replayed run IDs, wrong commit, modified/missing/extra artifacts, and wrong effect. Current tests cover missing permit denial, empty default-deny policy/keyrings, and signer workflow secret scoping; this is not the full adversarial corpus.
6. Ensure CI runs for PRs targeting `security/absorption-policy-ed25519-tests`, then run the full suite and inspect the resulting run logs on the exact PR #140 head.

## Merge / activation gates

- Keep PR #138, #139, and this PR in Draft until the above implementation and tests are complete.
- Do not merge this PR as an implementation-complete change while any legacy HMAC secret remains exposed outside the signer.
- Do not create or modify production secrets, key material, GitHub Environment protection, or approval records as part of this PR.
- Do not change the current policy from `DRAFT_UNAPPROVED` or populate `allowed_effects`.
- CI success alone is not evidence that the production signer boundary is enforced.
