# PR #140 — absorption signer, apply binding, and replay enforcement

## Current implementation status

**Code path implemented in PR branch; activation remains blocked by missing governance authority material.** The implementation now includes a four-artifact producer, signer-side semantic validation, a distinct target apply-run binding, an apply workflow, and a durable replay ledger using GitHub Contents API compare-and-swap. It is not yet CI-verified at the current head and has not been run end-to-end on `main`.

## A — Producer/consumer artifact contract

Implemented in the PR branch:

- `.github/workflows/aios-research-absorb.yml` now runs the executor, independent verifier, runtime proof, and promotion steps and publishes the four JSON artifacts in one source-run artifact.
- `research/absorption_signer.py` rejects missing/extra artifact names, wrong source-run IDs, non-PASS stages, invalid verification/runtime/promotion digests, failed runtime probes, promotion holds, mismatched candidate sets, and unsafe external-code flags before loading the permit private key.
- The signer uses a separately reviewed `policies/absorption-approval.json` governance approval record; research output is not treated as approval.
- `.github/workflows/aios-absorption-apply.yml` downloads the immutable source-run artifact and validates the exact four-file contract.

Still required for activation: the separately signed approval file must exist and bind the exact approved policy digest. It must not be fabricated from research output.

## B — HMAC removal from absorption authorization

Implemented for the absorption decision path:

- `research/absorption_verifier.py` now emits content-addressed evidence records without using HMAC as issuer authentication.
- `research/absorption_runtime_proof.py` emits a content digest; the signer later authenticates the exact artifact bytes through the Ed25519 permit.
- `research/absorption_promotion.py` validates evidence-record digests and levels, runtime proof digest, and same-run lineage without using HMAC as the promotion authority.
- `research/absorption_apply.py` revalidates evidence and artifact digests and requires the Ed25519 permit before the effect. It no longer uses the legacy HMAC evidence gate for this absorption path.
- Generic HMAC utilities and `core/evidence_gate.py` remain for other existing AIOS workflows; they are not being silently removed globally.

Trust boundary: content digests provide integrity, not issuer identity. The signed Ed25519 permit is the authorization over the exact artifact manifest and scope.

## C — Target apply-run binding and durable replay prevention

Implemented in the PR branch:

- Permit signature includes `target_apply_run_id`, distinct from the source research `run_id`.
- Signer validates that the target ID is an active `.github/workflows/aios-absorption-apply.yml` workflow run, from the same repository, on `main`, with the same source/signer commit SHA.
- Apply workflow starts first, dispatches the signer with its own `GITHUB_RUN_ID`, waits for the permit artifact, and checks that the permit targets that exact run.
- `core/absorption_replay_store.py` writes a durable permit-consumption ledger on branch `aios-absorption-replay-ledger`. Updates require the current blob SHA; concurrent compare-and-swap conflicts fail closed. A consumed permit ID is rejected on subsequent use.
- The effect guard consumes one permit once for the complete apply batch, not once per candidate.
- The replay ledger branch has been created. The apply workflow requests `contents:write` only for its job and passes its GitHub token to the replay store.

Tests added for first consumption, duplicate replay rejection, missing write credentials, and compare-and-swap conflict denial. The concurrency test is a mocked API conflict test, not a live parallel GitHub race test.

## Governance activation blockers — deliberately not manufactured

Current checked-in governance state was inspected:

- `policies/absorption-default-deny.v1.json`: `DRAFT_UNAPPROVED`; `allowed_effects: []`.
- `policies/absorption-governance-keyring.json`: empty object.
- `policies/absorption-permit-keyring.json`: empty object.
- `policies/absorption-approval.json`: not present.

Until an authorized governance owner provisions distinct governance and permit public keys, their corresponding private keys in the appropriate protected secret boundary, and a signed approval bound to the exact approved policy digest, the signer must stop before private-key use and the apply workflow must not materialize anything.

No production secret, Environment setting, approval, private key, or permit was created or changed in this work.

## Verification and merge gate

- CI run `44258376538` failed on the test that had not yet been updated for the required `target_apply_run_id` parameter. The failure was identified from the job log and the test was corrected in a later commit.
- CI run `44259554737` is the latest PR validation run currently observed. At last inspection, the full test suite was still running; the two MiniMind jobs had passed. Do not report this run as fully passed until the full-suite conclusion is available.
- The exact current head must have all CI jobs pass.
- Before converting PR #140 to Ready or merging, review the complete diff and validate the workflow YAML plus the source→signer→apply sequence in a non-production test policy/key setup.
- Keep production policy default DENY until a separate authorized governance approval. Do not treat CI success as production authorization.
