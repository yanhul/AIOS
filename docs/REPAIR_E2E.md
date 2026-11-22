# AIOS autonomous repair E2E trust chain

The autonomous repair workflow is fail-closed. A deploy or provider health check is not a repair result.

## Required GitHub Actions configuration

Configure these repository settings before dispatching the repair workflow:

- `TRY_REPAIR_PROVIDER_URL` (repository secret): base URL of the deployed TRY repair worker.
- `TRY_REPAIR_PROVIDER_TOKEN` (repository secret): Bearer token accepted by that worker. This is distinct from Gemini credentials.

The workflow maps these existing names to its internal `TRY_REPAIR_WORKER_URL` and `TRY_PROVIDER_TOKEN` environment variables. Do not create duplicate secrets under the old internal names.

## Required GitHub Actions secrets

Configure these repository secrets before dispatching the repair workflow:

- `AIOS_AUTHORITY_ATTESTATION_SECRET`: random deployment-held secret, at least 16 characters. It authenticates the issuer attestation bound to the execution contract and permit.
- `AIOS_PROVIDER_SIGNING_KEYS`: JSON object containing the `repo_patch` HMAC signer key, for example `{"repo_patch":"<deployment-key>"}`.
- `AIOS_PROVIDER_KEYRING`: verifier keyring JSON containing `repo_patch` with the same HMAC key and the `provider.receipt.sign` scope, for example `{"repo_patch":{"secret":"<deployment-key>","scopes":["provider.receipt.sign"]}}`.

The provider signer and verifier entries must match because the current `repo_patch` receipt contract uses HMAC-SHA256. Keep the key only in GitHub Secrets; never commit it or place it in artifacts. The apply script checks the signer/verifier match before it mutates the checkout.

## Execution stages

1. The trusted AIOS client stamps the provider proposal with repository, failed CI run ID, base SHA and attempt.
2. The apply step creates the policy, capability registry, contract, permit and permit attestation in a persistent per-job authority store. It authorizes the permit before mutation.
3. The `repo_patch` adapter applies the exact proposal through `runtime.execute()`. The apply step stops unless the persisted effect reaches `OBSERVED_SUCCESS` with a provider-authenticated receipt.
4. Trusted pytest runs in a separate GitHub Actions step. That step receives no authority attestation, provider signing/verifier, TRY, SCM or deployment secrets. The patch adapter also rejects `tests/`, `test/`, test modules, pytest configuration, `conftest.py`, and Python startup hooks, so a proposal cannot rewrite the test suite or its discovery configuration.
5. The reconciliation step verifies the persisted contract/permit/attestation, effect state, receipt signature and bindings, AIOS-minted evidence, proposal file hashes, test command/result digest and repository/run/base lineage.
6. The authority store is uploaded as a run-scoped artifact. Publish downloads the authority artifact and selected result, repeats reconciliation, then materializes the already-verified proposal and creates a candidate commit/PR. It does not invoke the provider or create a second effect.

## Status semantics

- `PATCH_APPLIED_RECEIPTS_ACCEPTED`: apply stage only; not a repair PASS.
- `REPAIR_ATTEMPT_TEST_FAIL`: patch receipt accepted but trusted tests failed; eligible for another bounded proposal attempt, not publishable.
- `REPAIR_E2E_PASS`: receipt/effect, trusted tests and reconciliation all passed for the same repository, run, base SHA and proposal set.
- `PUBLISHED_CANDIDATE`: verified patch was materialized as a candidate commit/PR. This does not mean the PR's full CI passed, it was merged, or production was deployed.

Missing or invalid authority, receipt, test or reconciliation evidence blocks publication. An ambiguous external effect remains `UNKNOWN`; it is never upgraded from a provider claim or test PASS alone.

## Candidate signature and provenance gate

A `PUBLISHED_CANDIDATE` commit is built locally in `publish` and is **not** pushed there.

1. `publish` writes `candidate-provenance.json` (repository, failed run, base SHA, repair run/attempt,
   workflow SHA, candidate commit/tree/parent, per-file SHA-256, patch digest, test digest,
   contract/permit/receipt IDs, reconciliation digest) and a git bundle of the commit, then signs the
   statement with a GitHub artifact attestation (Sigstore, `actions/attest-build-provenance`).
2. `verify-candidate` (read-only token) runs `gh attestation verify --signer-workflow
   .../ci-autonomous-repair.yml --deny-self-hosted-runners` and `scripts/ci_repair_provenance.py verify`.
   It blocks unless the signer is this workflow, at this workflow SHA, in this run, on a GitHub-hosted
   runner, and the bundled commit is a single-parent child of the failed base whose content equals the
   cumulative proposal files, touches no protected paths, and matches the reconciled patch digest.
3. Only then `submit-candidate` pushes to `aios/autorepair/*` and, for failures on `main`, opens a
   **draft** PR. Nothing is merged or pushed to `main` automatically.

Reviewers can re-check a candidate with
`gh attestation verify candidate-provenance.json --repo <owner>/<repo> --signer-workflow <owner>/<repo>/.github/workflows/ci-autonomous-repair.yml`
using the `aios-repair-candidate-<run>` artifact.
