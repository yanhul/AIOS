# PR #180 — P1/P2 audit remediation

**Target:** `yanhul/AIOS` PR #180 `feat/l3-l5-identity-binding` @ `d5013f63f8215b144842ecd9acd3e5d90244312e`. The stack is #180 → #179 (`dce15b9`) → #178 (`d8de132`) → #177 (`7308ed2`).
**Fix commit (local):** `8223587953022ad7977e84bf632efb7c35f56c2c` on `fix/pr180-p1p2-remediation`.
**Final status:** `VERIFIED_LOCAL`. Remote: **NOT PUSHED (LOCAL_ONLY / PUSH_BLOCKED)**. PR #180 head is unchanged at `d5013f6`; CI was not triggered.

Evidence tags: **FACT** (read in code), **VERIFIED** (proven by a test run here), **INFERRED**, **ASSUMPTION**, **UNKNOWN**, **CONFLICT**.

## Preflight (FACT)
- The PR head on GitHub is `d5013f6`. The local checkout matched it exactly, so there was no divergence and no prior local user changes.
- The repository is public. No secrets, keys or CI configuration were modified.

## Closure matrix

| ID | Sev | Location (base) | Root cause | Fix | Evidence |
|---|---|---|---|---|---|
| P1-A | P1 | `core/orchestrator.py:174`, `core/durable_loop.py:623-652` | Recovery recomputed verification, then passed only the receipt on, so the `state_patch` was lost. The `RECEIPT_VALIDATED` record was trusted without binding verification, patch and action to the receipt. | A `recovery_binding` sha256 over identity + receipt + patch + verification + action. The recomputed verification must agree with the record; a fresh patch is applied only after `state_patch_validator`. | **VERIFIED** — 10 of 13 P1-A cases fail on base; all pass on the fix |
| P1-B | P1 | `core/effect_authority.py:1079-1112` | The ledger fold trusted event `attempt_id`, never recomputed `effect_id`, and silently skipped foreign-version events. | Canonical recomputation of `effect_id`/`attempt_id`; create-event contract, actor, permit, effect type and logical-operation checks; per-event substitution checks; mixed versions are CONFLICT; new create events bind `logical_operation_id`. | **VERIFIED** — 8 of 11 attacks were accepted on base; all 11 are CONFLICT on the fix |
| P2-A | P2 | `core/effect_authority.py:1079` | `verify_effect_ledger` called `recover_pending`, which rolls forward, deletes and quarantines. Its docstring said "read-only" (**CONFLICT**). | Read-only `inspect_pending` and `inspect_effect_ledger` returning VERIFIED, VERIFIED_SEPARATE, UNKNOWN or CONFLICT. Recovery is explicit in the orchestrator. | **VERIFIED** — byte-, size- and mtime-identical snapshots (`filesystem-integrity.json`) |
| P2-B | P2 | `core/orchestrator.py:108-115`, `:86-89` | `_block` used a raw `store.save`, leaving a stale `continue_contract` projection behind. | Persists via `_persist_state`. An unbuildable projection is dropped rather than left contradicting the state, so restart fails closed. | **VERIFIED** — 3 restart and crash tests |

The full per-finding record (exact fix lines, tests, remaining uncertainty) is in `findings.json`, and the crash scenarios are in `crash-matrix.json`.

## Required behaviours → status
- Normal execution and recovery use the same verifier, receipt validator and patch validator: **VERIFIED**.
- Receipt, verification, patch and action form one bound record tied to effect, attempt and operation identity: **VERIFIED**.
- Missing, altered, mismatched or partial recovery records are rejected, and repeated restarts are idempotent with provider calls = 1: **VERIFIED**.
- The provider is never replayed to rebuild evidence; UNKNOWN stays UNKNOWN (pending journal, quarantine, legacy ledger): **VERIFIED**.
- Legacy random IDs are never backfilled. Pre-fix create events verify as `VERIFIED_SEPARATE` and are left untouched: **VERIFIED**.
- BLOCKED never transitions to RUNNING and never dispatches again: **VERIFIED** for orchestrator restart paths.

## Stack audit (#177–#180)
- **S-1 (FACT, fixed):** the `test-audit-gate` would block #180. Six changed test files lacked `AIOS-*` metadata; it was added, and the gate with `--base pr179` now passes.
- **S-2 (FACT, open):** `architecture_boundary_check.py` runs in report-only mode. Its CI PASS does not enforce the boundary property.
- **S-3 (INFERRED):** a `RECEIPT_VALIDATED` intent persisted by the old code has no binding, so restart blocks it. This is fail-closed and needs operator action.
- **S-4 (UNKNOWN):** 2 pre-existing failures in `tests/test_repair_reconcile.py`, identical on base and fix.
- **S-5 (UNKNOWN):** #177–#179 were reviewed for scope and interaction only, not deep-audited line by line.
- **API compatibility (FACT):** `verify_effect_ledger` now adds a `verdict` key and new UNKNOWN statuses, and no longer performs roll-forward. The only in-repo caller is the orchestrator, which was updated. One exact-dict test was tightened to also assert `verdict`.

## Remaining uncertainty / not claimed
- The L3 WAL remains unauthenticated. `recovery_binding` is an unkeyed integrity digest; forged records still need agreement from L5 and the verifier (**ASSUMPTION:** L5 and the verifier are trusted).
- Not verified: fsync durability on real power loss, atomicity of the file-backed StateStore, and the PCB durable runners end-to-end.
- A CI PASS is not proof of production safety.

## Merge recommendation
**Do not merge automatically.** Keep the stack order (#177 → #178 → #179 → #180), require human review of the full stack, and require a green CI run on the pushed head.
