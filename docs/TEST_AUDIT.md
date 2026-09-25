# AIOS Test Reality & Conformance Audit

Adapted from the OpenClaw `test-audit` method (read-only source: OpenClaw `.agents/skills/test-audit/`).

## Purpose

AIOS test PASS means executable evidence of an observable contract or invariant, not merely execution of assertions.

### Authoring gate

Every new or materially changed test must be able to answer, in the test file:

- `AIOS-CONTRACT:` — the observable behavior/invariant/independent contract protected.
- `AIOS-REGRESSION:` — a credible regression that should fail.
- `AIOS-OWNER:` — the production boundary that owns the contract.
- `AIOS-COVERAGE-GAP:` — why existing proof does not already catch it.
- `AIOS-BASELINE:` — how pre-fix RED is established for a regression, or why baseline RED is not applicable.

A test must not be accepted merely because its name sounds meaningful.

## Junk patterns

The gate flags these for review:

- assertion-free tests;
- exact source/import/string checks used as a substitute for executable behavior;
- duplicate invocation of an already-owned contract;
- mocks that implement the behavior being asserted;
- fixtures that manufacture the receipt/admission/order that production is supposed to create;
- negative controls that pass through an unrelated guard;
- test-only production seams;
- tests coupled to private implementation shape where the owning boundary can prove the contract.

A flag is not automatic deletion. Retain when the test independently protects a documented API, protocol, storage, security, platform, migration, release, or architecture contract.

## Owner-boundary rule

One primary test owner per contract at the strongest reachable boundary.

For AIOS effect execution, the canonical lineage is:

`contract → permit → effect → attempt → receipt → evidence → evaluation`

A lower layer may have its own test only when it protects a distinct risk that the owner boundary cannot reach.

## Regression proof

For a bug fix:

`baseline RED → repair → GREEN → control/revert RED → restore`

A test that never failed on the intended pre-fix behavior is not sufficient proof of the repair.

## Mutation proof

For high-value conformance contracts, deliberately mutate the owner so the keeper test must fail, then restore the owner exactly.

Priority mutation targets:

- stale writer rejection;
- UNKNOWN → DISPATCHED retry fencing;
- attempt identity;
- receipt/evidence lineage;
- authority/policy binding;
- capability snapshot/drift;
- terminal-state authorization.

## R/F/C/D audit ledger

For subsystem audits:

- **R** retain — name contract + credible failure.
- **F** fix assertion — contract is valid but proof is vacuous/wrong.
- **C** consolidate — name the stronger keeper boundary.
- **D** delete — name the remaining proof or absence of contract.

Deletion requires evidence. Do not optimize for deletion count.

## Current AIOS owner map

| Contract area | Primary owner boundary | Proof requirement |
|---|---|---|
| Durable loop lifecycle | `core/durable_loop.py` | observable state/history + failure persistence |
| Effect authority | `core/effect_authority.py` | contract/permit/effect/attempt transition |
| Evidence | `core/evidence.py` + evidence gate | typed evidence accepted/rejected at boundary |
| Mutation/state integrity | `core/mutation.py` | atomicity, identity, replay, tamper rejection |
| Independent verification | `core/adversarial_verification.py` | verifier independence + bounded repair |
| Registered workloads | `scripts/run_3_workload_conformance.py` | real workload evidence + verification refs |

This map is a starting owner map, not a claim that every test has already been audited.

## Audit handoff

Every completed audit should report:

1. baseline SHA and baseline result;
2. test files/declarations reviewed;
3. R/F/C/D ledger;
4. keeper boundary per retained contract;
5. production seams removed;
6. mutation/control evidence;
7. focused/full validation actually run;
8. production LOC versus test/support LOC;
9. remaining follow-ups.

Never convert UNKNOWN into PASS by inference.
