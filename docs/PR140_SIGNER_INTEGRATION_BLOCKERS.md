# PR #140 — isolated signer and two-phase replay-ledger PR writer

## Status

**Draft / BLOCKED / not merged.** The implementation now has two separate workflow phases. No live ledger write, human merge, receipt issuance, or production apply has been performed. CI for the latest head is pending at the time of this update.

## Phase 1 — propose ledger consumption

Workflow: `.github/workflows/aios-absorption-apply.yml`

1. Validate the trusted source research run and bind the signer permit to this stage-one workflow run.
2. Signer remains isolated in the `absorption-signer` Environment.
3. The `consume-permit` job runs in `absorption-ledger-writer`, mints a narrowly scoped GitHub App token for only `yanhul/AIOS-replay-ledger`, and requests Contents: write + Pull requests: write.
4. Read the current `main` SHA and ledger; reject malformed schema or duplicate permit.
5. Create a unique branch `aios-absorption-<stage1-run-id>` from that exact SHA, commit the candidate ledger entry to the branch, and open a PR targeting `main`.
6. Publish only a PR reference artifact. **No replay receipt is issued in phase 1.**

## Phase 2 — verify after human merge

Workflow: `.github/workflows/aios-absorption-finalize.yml`

Inputs: original source run ID, successful stage-one run ID, and ledger PR number.

1. Require source and stage-one runs to be successful, from their expected workflows, on `main`, and on the same source SHA.
2. Download the exact signed permit from the stage-one run.
3. Use a read-only App token to inspect the specified PR and ledger.
4. Require the PR to be merged into `main`, have the expected unique branch, contain the exact permit/target/stage-one markers, and change only the ledger file.
5. Re-read the ledger from `main`; require the exact permit ID and target stage-one run ID in the consumed map.
6. Only after those checks, issue a receipt binding the permit, target stage-one run, continuation run, PR number, merge commit SHA, and ledger-entry digest.
7. The separate `production` job downloads the original source evidence, permit, and same-run receipt and re-runs the apply-time Ed25519 and receipt checks.

The effect guard now distinguishes the permit's stage-one target run from the later post-merge continuation run. The receipt must bind both.

## Security boundaries and remaining blockers

- The App token is minted only in the writer/verification Environment. Production has no App ID/private key or ledger write credential.
- Phase 1 writes only to a uniquely named branch; it does not write to ledger `main`.
- Phase 2 does not issue a receipt unless the PR is merged and the exact ledger entry is observed on `main`.
- GitHub Free does not provide server-enforced branch protection for this private ledger. The PR is a human review boundary, not tamper-proof append-only storage. An administrator or sufficiently privileged credential can still bypass it.
- App preflight attempt 4 passed token minting and GET access. It did not test branch creation, PR creation, merge verification, or receipt issuance.
- No live writer PR, live post-merge verification, live CAS/race test, or signer→writer→finalizer→apply E2E has been executed.
- Environment secret presence is user-confirmed; secret values are not read.
- Policy remains `DRAFT_UNAPPROVED`, default `DENY`, `allowed_effects: []`; governance and permit keyrings remain empty. The production effect must remain denied.
- Keep this PR Draft and unmerged. Do not create governance/permit keys or run production to bypass these blockers.
