# Conditional promotion gate: repo_patch@1

**Status: PROPOSED — NOT ACTIVE.** This document records the approved scope for preparing a promotion proposal. It is not itself a governance promotion decision and does not grant execution authority.

## Bounded operating scope

- Repository: `yanhul/try` only.
- Eligible workflow: exact workflow name `Strict Full TRY Suite` only.
- Source run must be completed and failed; bind the exact run ID, repository, immutable 40-character head SHA, workflow identity, and evidence digests.
- Maximum one repair attempt and one Draft PR per source run.
- Draft PR only. Never merge, enable auto-merge, push directly to a protected branch, deploy, release, publish, or modify production configuration, secrets, repository settings, branch protection, Actions permissions, or GitHub App installation.
- `UNKNOWN` is non-terminal: reconcile before any further action; no automatic replay.
- Issuer cannot approve its own authority or alter policy/capability status.

## Promotion remains blocked until every gate passes

1. **AIOS contract and permit:** a run-bound contract and permit resolve `repo_patch@1` against the exact immutable AIOS registry commit; all required identity, effect, attempt budget, policy digest, and evidence fields validate.
2. **Governance policy:** the governing policy is approved, digest-pinned, not expired, and explicitly permits only the bounded scope above. Approval of this proposal does not grant production authority.
3. **Issuer and attestation:** the independent issuer binds the exact run/repository/base SHA and emits a verifiable attestation; the verifier rejects missing, duplicate, conflicting, stale, or replayed records.
4. **Immutable store readback:** contract, permit, and attestation bytes are read back from the receipt's immutable Git commit and all recorded SHA-256 digests match.
5. **Effect receipt and reconciliation:** a controlled adapter test creates at most one Draft PR, reads it back from GitHub, confirms `draft=true` and `merged=false`, persists the receipt, and reconciles the exact effect/attempt lineage.
6. **Adversarial and recovery tests:** wrong run/SHA, wrong HMAC, altered bytes, duplicate records, invalid receipt, replay, and ambiguous-write recovery all fail closed or reconcile without duplicate mutation.
7. **Exact-commit CI:** AIOS test suite, test-audit gate, policy/capability conformance, authority-store checks, and the relevant TRY strict suite all pass on the exact commits under review.
8. **Independent governance review:** a reviewer other than the issuer approves the registry/policy promotion PR after inspecting the evidence bundle. The capability remains `CANDIDATE` until this review and all prior gates pass.

## Required evidence bundle

Attach immutable URLs/IDs for:
- AIOS commit and registry/policy digests;
- completed source workflow run ID, repository, and head SHA;
- issuer run and issuance receipt;
- immutable Git store commit plus record digests;
- verifier result;
- adapter request/result and exact Draft PR URL/readback;
- persisted effect receipt and reconciliation result;
- adversarial/recovery test run IDs and exact-commit CI run IDs.

No placeholders, health checks, or unauthenticated 401 probes count as evidence for the gates above.

## Current decision

The capability registry must remain `repo_patch@1: CANDIDATE` until the evidence bundle is complete and independently reviewed. If any gate is missing, expired, or inconclusive, the outcome is `BLOCKED`; do not issue authority and do not claim end-to-end PASS.
