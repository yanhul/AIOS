# PR #140 — absorption signer, apply binding, and replay enforcement

## Current status

**Draft / not approved for production / not merged.** The code path is implemented on this PR branch, but production activation remains deliberately blocked by the checked-in default-deny policy and missing governance authority material.

The repository owner reports that the dedicated `absorption-signer` Environment has been created/configured. This is user-confirmed, not independently verified through the connected GitHub API. The signer workflow targets that Environment; the apply workflow separately targets `production`.

## A — Producer/consumer artifact contract

- The research workflow produces executor, independent-verification, runtime-proof, and promotion JSON artifacts.
- The signer validates the exact artifact set, source-run identity, PASS states, digests, candidate-set equality, runtime probes, promotion decisions, and external-code restrictions before loading the permit private key.
- The signer verifies a separately authenticated governance approval. Research output is not approval.
- The signer private-key secret is referenced only in the signer workflow's signing step; the apply workflow does not reference it.
- Permit artifacts are now named with both source run ID and target apply run ID. The apply workflow looks up that exact pair, preventing an old artifact for the same source run from shadowing the current apply run during retries or concurrent runs.

## B — Authorization and trust boundaries

- Absorption authorization uses Ed25519 permits over the policy, repository, target branch, source run, source commit, artifact digests, and exact target apply run.
- Content digests provide integrity, not issuer identity.
- Generic HMAC utilities remain for unrelated AIOS evidence flows; they are not the authorization mechanism for this absorption path.
- The policy's signer key location now matches the workflow's dedicated `absorption-signer` Environment.

## C — Target apply-run binding and replay prevention

- The apply workflow starts first and dispatches the signer with its own workflow run ID.
- The signer verifies the target is an active apply workflow run in the same repository, on `main`, and on the same code revision as the source and signer.
- The permit is bound to that exact target apply run.
- The replay store records permit consumption on `aios-absorption-replay-ledger` using GitHub Contents API updates with the current blob SHA. Duplicate permit IDs and write conflicts fail closed.
- One permit is consumed once for the apply batch, not once per candidate.
- Tests cover duplicate replay rejection and a mocked compare-and-swap conflict. This is not evidence of a live parallel GitHub race.

## Governance state — activation blocked

The checked-in state remains:

- `policies/absorption-default-deny.v1.json`: `DRAFT_UNAPPROVED`.
- `decision.default`: `DENY`.
- `decision.allowed_effects`: empty list.
- Governance and permit keyrings: empty objects.
- `policies/absorption-approval.json`: absent.

No governance or permit keys, approval, permit, or production secret were created. The signer must stop before signing while these prerequisites are absent.

## Repository controls — verified and remaining gap

GitHub ruleset `protect-absorption-replay-ledger` is Active and targets exactly `refs/heads/aios-absorption-replay-ledger`. Its currently verified rules are:

- Deletion blocked.
- Non-fast-forward updates (force-push) blocked.
- No bypass actors.

**Important limitation:** this ruleset does not currently contain the `update` rule. It therefore does not restrict ordinary fast-forward writes to the ledger branch. Do not describe the ledger as fully immutable or writer-restricted yet.

Adding an `update` restriction with no bypass would also block the apply workflow's current `GITHUB_TOKEN` writes. Before enabling that rule, design and verify a narrowly scoped ledger-writer identity/bypass that GitHub supports for this repository. Do not add a broad user, maintainer, or administrator bypass merely to make writes pass.

## Verification

- Previous current-head CI run `44262163313` passed all three jobs on `ed83d1342d468c0a015cccb2b7596f34a7e157c5`.
- Subsequent changes in this PR must receive a new successful CI run before being treated as verified.
- CI success is code/test evidence only. It does not prove a live signer→apply run, Environment reviewer behavior, branch immutability, or a live parallel GitHub API race.
- No production execution has been performed. Keep this PR Draft and unmerged until the remaining repository-control gap and non-production end-to-end verification are resolved.
