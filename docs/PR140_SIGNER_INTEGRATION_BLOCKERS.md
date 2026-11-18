# PR #140 — isolated absorption replay-ledger writer

## Status

**Draft / DENY / not merged.** The workflow and code have been changed on this PR branch to isolate replay-ledger writes. CI on commit `7e9b764223253a9ffe45801496527aa449d7980f` passed all three jobs (`826 passed, 16 skipped` in `full-suite`). The follow-up documentation-only integrity-boundary update is being rechecked. No live apply, signer, or ledger write has been executed.

## Job separation implemented

1. `prepare`: validates the source run, dispatches the protected signer, and publishes the permit artifact for this workflow run.
2. `consume-permit`: runs only in Environment `absorption-ledger-writer`; creates a GitHub App installation token scoped to repository `yanhul/AIOS-replay-ledger` with Contents write; consumes the permit once using Contents API blob-SHA CAS; publishes a receipt only after the CAS write succeeds.
3. `apply`: runs only in Environment `production`; receives the permit and receipt artifacts, verifies the receipt binding and Ed25519 permit, and has no App private key or replay-ledger token.

The App action is pinned to verified commit `64ab729a6294000f5aa4a4bc0b73d1f32bc45510` (tag v3.3.0). The replay store no longer falls back to `GITHUB_TOKEN`; it requires `AIOS_REPLAY_LEDGER_TOKEN`. Target is fixed in workflow configuration to `yanhul/AIOS-replay-ledger`, branch `main`, path `.aios/absorption-consumed-permits.json`.

## Receipt and failure behavior

- The writer job must successfully complete the Contents API CAS before it can upload the receipt.
- Receipt binds permit digest, exact apply workflow run ID, ledger repository/branch, and writer job ID.
- The production guard rejects missing, unreadable, or mismatched receipts.
- A consumed permit is not automatically retried if downstream production fails; this is fail-closed and requires a fresh apply run/permit.
- The receipt is a same-workflow artifact from the required writer job; production does not receive the App token or private key.

## Remaining blockers

- The target repository `yanhul/AIOS-replay-ledger` is private and its default branch is `main`. The connected GitHub API returned `403: Upgrade to GitHub Pro or make this repository public to enable this feature` for repository rulesets; branch-protection reads also returned `403 Resource not accessible by integration`. Therefore protection of `main` is **UNKNOWN / NOT VERIFIED**. Do not describe the ledger as append-only or tamper-proof. Contents API blob-SHA CAS prevents two writers using the same stale SHA from both succeeding, but it does not prevent a credential holder or administrator from later rewriting/deleting history. Do not make the repository public or change its plan/privacy as a workaround.
- No live writer-token creation, CAS write, signer→writer→production non-production run, or parallel CAS race has been executed. The existing tests simulate a CAS conflict; they are not a live GitHub concurrency test.
- Environment secret presence is user-confirmed only; secret values were not exposed or independently read.
- Policy remains default `DENY`, `allowed_effects: []`; governance and permit keyrings remain empty. No approval or production authorization is being created.

## Verification required

Run PR CI on the latest head and inspect all jobs. CI passing is code/test evidence only. Before any non-production end-to-end run, verify the App installation is restricted to only `yanhul/AIOS-replay-ledger`, the Environment contains only the intended App ID/private-key secrets, and the separate repository's branch protection. Keep this PR Draft and unmerged until those checks and non-production E2E pass.
