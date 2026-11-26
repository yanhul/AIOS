# Next actions — ordered remediation

No P0 (no unsafe PASS reachable without store write access or key compromise — FACT/VERIFIED within audited scope).

## P1

| ID | Action | Findings | Depends on | Acceptance criteria |
|---|---|---|---|---|
| N-01 | Review & land remediation PR (F-01, F-02, F-14) into #180 branch | F-01 F-02 F-14 | — | CI green on its exact head; the 6 tests in `tests/test_stack_audit_remediation.py` fail on 140c032 and pass on head; independent reviewer sign-off |
| N-02 | Non-production PCB integration workflow (`workflow_dispatch`, `permissions: contents: read`, no secrets, pinned fixture kit stub committed under `tests/fixtures/`) driving both runners' `main()` across: fresh run, crash after intent (expect BLOCKED), crash after RECEIPT_VALIDATED + `reconcile_in_flight_attempt`, discover→redispatch, UNKNOWN receipt | F-01, G-05 | N-01 | Workflow artifacts contain per-scenario final state JSON; assertions on `effect_id` prefix `EF-`, `act()` count ==1 per logical op, expected terminal status; no network egress beyond checkout |
| N-03 | Owner decision on L3/L5 at-rest trust model: (a) declare store-writer trusted and enforce ACL (0700, dedicated uid) + document; or (b) authenticated state | F-03 F-04 F-15 | — | Written decision in `docs/` naming T1 in/out of scope |
| N-04 | If (b): HMAC-SHA256 chain over WAL records (`mac_i = HMAC(k, mac_{i-1} ‖ body_i)`) with key held by L3 runtime, plus external monotonic high-water mark (sequence+mac) stored outside the state dir (L6 authority store or signer). Ed25519 only if verification must be possible by a party without signing power (e.g. auditor) — signer then must be on the hot path per record. Authority-backed alternative: L6 signs RECEIPT_VALIDATED checkpoints only (lower cost, covers AT-01; AT-02 needs the high-water mark) | F-03 F-04 | N-03; key provisioning by owner (not by audit) | Tests: forge+recompute binding → rejected; tail truncation → BLOCKED; record append without key → rejected; key absent → fail closed |
| N-05 | Ed25519 permit lifecycle for `ci-autonomous-repair`: job writes `permit-request.json` (contract, permit, digest) as artifact → stops BLOCKED_AWAITING_ATTESTATION → external signer (separate account/runner, OIDC-authenticated pull, approves by policy) issues attestation with `issued_at`, `expires_at` (≤1h), `audience=repo@run_id`, `nonce` → resume job (`workflow_dispatch` with run_id) imports attestation into fresh authority dir and calls `authorize()`; verifier enforces expiry/audience; single-use recorded in L5 | F-05 F-06 | owner approval of signer placement | Tests: expired / wrong audience / reused nonce / revoked key / missing → BLOCKED; happy path with test-only keys from `tests/authority_keys.py` |
| N-06 | Rotation & failure handling: keyring supports ≥2 active keys + revoked list; rotation = add new → sign with new → revoke old after max TTL; signer outage → jobs stay BLOCKED (never fallback); keyring moved from `vars` to Environment-protected variable with required reviewers | F-07 | N-05, G-02 | Settings evidence; test that a revoked key fails during overlap window |

## P2

| ID | Action | Findings | Acceptance criteria |
|---|---|---|---|
| N-07 | `_fsync_dir`: raise on fsync error on POSIX (keep Windows no-op explicit); fsync `.staging` after `makedirs(batch_dir)`; store journal paths relative to `aios_dir` (format 3) with v2 read-compat | F-10 F-11 F-13 | Unit test with monkeypatched `os.fsync` raising EIO → commit fails; LazyFS/dm-flakey job (G-01) before any power-loss claim |
| N-08 | Boundary gate enforce: (1) land F-14 fix; (2) add L3→L5-only and L6-no-provider rules with fixtures; (3) commit `architecture_baseline.json` (currently empty); (4) CI runs `--strict --baseline`, failing on new findings and on stale baseline entries | F-14 | Regression tests per rule incl. relative/dynamic forms; strict job green on head; a seeded violation PR goes red |
| N-09 | Quarantine resolution requires operator record bound to batch digest (and L6 attestation once N-05 exists) | F-12 | `touch RESOLVED.json` no longer unblocks; test |
| N-10 | Separation of duties: verifier refuses if any Ed25519 private key file is readable at configured/default paths; split provider signing out of apply job | F-08 F-09 | Tests; workflow env diff |

## P3
- N-11 Document that `attempt` is fixed to 1 and that callers must make `logical_operation_id` unique per step (F-16).

## Decision

**NEEDS_REMEDIATION**

Reasons: F-01 (PCB runner non-functional after #180) and F-02 (L5 path escape) are VERIFIED defects in the stack — fixed only in a separate unreviewed PR; F-03/F-04 show the L3 WAL recovery does not resist a store writer and the trust model is undeclared; F-05 means the Ed25519 rollout leaves `ci-autonomous-repair` permanently BLOCKED. Not READY_FOR_MERGE; CI PASS does not change this.
