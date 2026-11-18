# PR #140 — Ed25519 signer / permit integration gate

## Status

**DRAFT / BLOCKED — no end-to-end authorization path is established.** Current reviewed head before this documentation correction: `5d0c37116b15f75e574d5d787356a8f17f21a3d3`. The policy remains `DRAFT_UNAPPROVED` with `allowed_effects: []`. This is intentional and must remain DENY.

## A — Artifact producer/consumer contract: NOT CONNECTED

- `.github/workflows/aios-research-absorb.yml` runs read-only research intake and publishes `aios-absorption-research-${{ github.run_id }}`.
- `research/absorption_signer.py` expects `input/approval.json` and four separate files: executor, verification, runtime-proof, and promotion.
- The research workflow does not produce that approved four-artifact bundle or an approval record. The signer therefore cannot complete with the current producer output.
- Do not fabricate approval or synthesize missing verification/runtime/promotion records merely to make signer pass.

## B — Authentication migration: INCOMPLETE

- `core/artifact_attestation.py` still defines HMAC-SHA256 artifact attestations.
- `core/evidence.py` and `core/evidence_gate.py` still use HMAC-SHA256 for evidence attestations and promotion authorization.
- `research/absorption_verifier.py`, `research/absorption_runtime_proof.py`, `research/absorption_promotion.py`, and `research/absorption_apply.py` still depend on those HMAC paths.
- Ed25519 approval/permit primitives in `core/absorption_authority.py` do not by themselves replace those legacy evidence trust decisions.
- Research workflow isolation removed production signing secrets from the research job; it did not complete the Python-side HMAC-to-public-key migration.

## C — Permit scope and effect enforcement: INCOMPLETE

- Current permit binds policy digest, repository, target branch, source run, source commit, and artifact digests.
- It does **not** bind a distinct target apply-run ID.
- No durable atomic one-time nonce-consumption/replay ledger is implemented. Signature verification alone does not prevent reuse of a valid permit.
- `core/absorption_effect_guard.py` now verifies signature/scope/effect and then **unconditionally DENIES** because no durable atomic one-time consumption backend exists. This is an intentional safety interlock, not replay protection.
- `tests/test_absorption_apply.py` uses an autouse fixture to replace the real effect authorization call with an always-allow stub for its data-lineage tests. One dedicated test restores the real function to check missing-permit denial. This does not establish replay, wrong-effect, or successful end-to-end enforcement coverage.
- There is no durable one-time permit-consumption implementation. The added test asserts denial when that backend is absent; it does not claim replay protection is implemented.

## Safe hardening applied on PR #140

- Effect guard now fails closed after cryptographic/scope checks because atomic replay-safe consumption is not implemented. No process-local nonce cache or fake ledger was introduced.
- Signer workflow now performs a no-secret preflight before the private-key step: it requires the separate approval file, all four expected artifacts, an approved policy with non-empty effects, and non-empty governance/permit keyrings. The current draft policy and current research artifact bundle intentionally fail this gate, so the private-key step is not reached.
- Added tests asserting the effect guard denies without the durable consumption backend and that signer preflight precedes any private-key exposure.

## Test status

- CI run **44253161295** on head `5d0c37116b15f75e574d5d787356a8f17f21a3d3` completed successfully: `full-suite`, `minimind-key-isolation`, and `minimind-capability-readiness (non-production)`.
- This is a code/test-suite pass only. It does not prove A, B, or C are complete, and it does not establish production authorization.
- Required additional adversarial tests: missing/invalid approval, draft policy, unknown/revoked key, expired permit, wrong repository/run/commit/apply-run, altered/missing/extra artifact, wrong effect, replay, concurrent consumption, and missing audit receipt.

## Safe next implementation gates

1. Define one versioned artifact manifest produced by research, including exact artifact names, run ID, repository, source commit, sizes, and SHA-256 digests. Signer must validate exact expected contents and reject missing/extra artifacts.
2. Replace HMAC authorization dependencies with public-key verification or content-addressed integrity plus separately authenticated provenance. Do not treat a bare digest as an authenticated issuer.
3. Add target apply-run binding and a durable atomic one-time permit-consumption service. If that service is unavailable, effect authorization must remain DENY; an ephemeral runner-local file is not a cross-run replay defense.
4. Enforce the guard in the actual apply entrypoint and test direct invocation, wrong effect, replay, and concurrent consumption without stubbing the guard.
5. Run CI against the exact final head and inspect all job results.

## Merge / activation gates

- Keep PR #140 Draft and unmerged until A, B, C, and their adversarial tests are implemented.
- Keep the policy draft and empty-effect list unchanged until a separate authorized governance decision.
- Do not create governance approvals or production private keys, and do not modify production secrets or Environment settings.
- Do not claim production readiness from CI success alone.
