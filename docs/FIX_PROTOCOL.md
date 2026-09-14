# Governed Fix Protocol

Status: NORMATIVE for autonomous engineering/fix workflows.

## Purpose

An agent must not treat a local test pass, a state mutation, or its own claim as proof that a defect is fixed. The control layer governs the definition of a fix and the evidence required to promote it.

## Required lifecycle

`PROBLEM -> INVARIANT -> LIFECYCLE TRACE -> BROKEN BOUNDARY -> ROOT CAUSE -> FIX PLAN -> PATCH -> REGRESSION -> REAL RUNTIME -> EVIDENCE -> BOUNDARY CROSSED -> VERIFIED`

The agent may propose and execute changes inside the supplied policy. It cannot redefine the invariant, evidence requirements, acceptance criteria, budget, or terminal condition.

## Mandatory fix-plan fields

Before a patch is authorized, the harness must have an immutable `FixPlan` containing:

- violated invariant;
- lifecycle being traced;
- exact broken boundary;
- root cause;
- proposed fix;
- regression proof required;
- runtime proof required;
- externally governed terminal condition.

Missing fields are a fail-closed condition.

## Promotion rule

`TESTS_PASS` is not `FIXED`.

`STATE_MIGRATED` is not `FIXED`.

`RUNTIME_STARTED` is not `FIXED`.

A fix may be promoted to `VERIFIED` only when an external verifier has concrete evidence that the runtime crossed the previously broken boundary and the required regression proof passed.

The agent cannot self-attest `FIXED`.

## Required runtime proof

For a lifecycle bug, proof must cover the transition itself, not merely its predecessor. Example:

`BC202 OOS_FAIL -> FAILURE_ANALYSIS -> BC203 CANDIDATE -> BC203 EXECUTION -> RECEIPT -> DECISION`

If any required transition is absent, the result remains `BLOCKED`/`INCONCLUSIVE` according to external policy.

## Durable harness integration

Fix workflows use the canonical loop:

`OBSERVE -> DECIDE/PLAN -> ACT -> VERIFY -> PERSIST STATE -> RESUME`

The fix protocol is a governance layer around that loop. It prevents the model from forgetting the root-cause/invariant method between iterations and prevents conversational context from becoming the source of truth.

See `core/fix_protocol.py` for the fail-closed data types and verification helpers.
