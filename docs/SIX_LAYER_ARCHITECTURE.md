# AIOS Six-Layer Architecture Contract

Status: proposed normative boundary contract. This document defines logical ownership, not a requirement to deploy six services.

## Architecture

```text
L6  AIOS Authority & Evidence
    Policy · Contract · Permit · Effect authorization · Receipt validation
    Reconciliation · Verification · Promotion / terminal decision
                         |
                         v
L5  Durable State & Event Ledger
    Append-only events · durable snapshots/checkpoints · idempotency
    attempt/effect lineage · recovery and replay
                         |
                         v
L4  Graph Orchestrator
    DAG · dependencies · branching · scheduling · interrupts
    node-level workflow state and orchestration decisions
                         |
                         v
L3  Loop Controller
    Plan · Act · Observe · Evaluate · bounded retry · stop
                         |
                         v
L2  Harness Adapter
    Claude Code · Gemini CLI · OpenHands · custom runtime adapters
                         |
                         v
L1  Model & Tools
    LLMs · MCP · Git · shell · CI · repository/service APIs
```

The arrows describe governed interaction, not unrestricted call permission. Implementations may combine layers in one process or split them across processes. Layer ownership and contracts remain distinct.

## Ownership and invariants

| Layer | Owns | Must not own |
|---|---|---|
| L6 Authority & Evidence | Policy, immutable contract, permit validation, capability/effect authorization, receipt acceptance, reconciliation verdict, verification and promotion criteria | Provider execution, workflow scheduling, mutable agent-owned policy |
| L5 Durable State & Event Ledger | Durable facts about transitions, immutable attempt/effect lineage, event history, checkpoints, idempotency and recovery records | Policy decisions, graph planning, provider calls |
| L4 Graph Orchestrator | DAG structure, dependencies, branching, scheduling and interrupts | Permit issuance, evidence acceptance, provider-specific execution semantics |
| L3 Loop Controller | One bounded observe/plan/act/evaluate cycle and stop/retry requests | Changing policy/budgets, minting authority, declaring unverified success |
| L2 Harness Adapter | Protocol translation, runtime lifecycle calls, mapping runtime results to adapter contracts | Granting authority, changing contracts, promoting evidence |
| L1 Model & Tools | Model inference and concrete tool/provider operations | AIOS authority, durable truth, self-approval |

### Cross-layer invariants

1. **Authority is not execution.** Only L6 can authorize an effect; L2/L1 execute only an already-authorized operation.
2. **Durable state is not orchestration.** L5 records committed facts; L4 derives the next graph action from those facts.
3. **A graph node is not a permit.** Scheduling or reaching a node never grants permission to perform an external effect.
4. **A loop result is not evidence by assertion.** L3/L2/L1 output is untrusted until L6 validates it and binds it to the exact effect/attempt/receipt lineage.
5. **Retries create new attempts.** Prior attempts are immutable. UNKNOWN is not proof of non-execution; retry requires explicit governed authorization and reconciliation rules.
6. **Resume must not replay an effect.** Resume/recovery first reconciles the existing attempt. It must not call provider execute again merely because the local process restarted.
7. **No reverse authority dependency.** L6 policy/evidence decisions cannot depend on an agent's self-reported PASS, and L1/L2/L3/L4 cannot mutate L6 policy or promotion criteria.
8. **No false terminal state.** PASS requires the contract's required evidence and verification gates; unresolved ambiguity yields BLOCKED or INCONCLUSIVE according to policy.

## Contract surfaces

- L6 → L5: validated transition command; L5 commits it atomically and returns a durable event/record identity.
- L5 → L4: committed state/event stream or checkpoint; never an uncommitted in-memory guess.
- L4 → L3: node invocation with immutable node/contract identity, dependency results and bounded budget.
- L3 → L2: one operation request conforming to a declared harness capability contract.
- L2 → L1: scoped provider/tool invocation using only supplied capabilities.
- L1 → L2 → L3: raw output and provider receipt candidate; not trusted evidence.
- L3/L4 → L6: proposed outcome plus provenance references; L6 independently validates.
- L6 → L4/L3: authorization/decision and permitted next action; no worker can override it.

## Current implementation mapping (initial, code-inspection based)

| Layer | Current candidates | Mapping confidence / caveat |
|---|---|---|
| L6 | `core/authority.py`, `core/effect_authority.py`, `core/provider_authority.py`, `core/verification.py`, `core/reconcile.py`, evidence/attestation modules | Strong functional match. Some modules combine policy decisions with persistence operations; split responsibilities at API/transaction boundaries before moving files. |
| L5 | `core/durable_wal.py`, `core/wal_state_store.py`, Firestore effect/permit stores and related repositories | Partial. Multiple storage implementations exist; authoritative ownership, consistency model and event-to-snapshot relationship need a full backend-by-backend audit. |
| L4 | `core/orchestrator.py` | Not yet demonstrated as a DAG/graph orchestrator. Current inspected implementation bridges governed execution to the durable loop; do not label it a full L4 graph engine. |
| L3 | `core/durable_loop.py` | Strong loop-controller match: observe/decide/act/verify, policy-bounded steps and terminal states. |
| L2 | `core/runtime.py`, `core/durable_runtime.py`, `adapters/**` | Strong adapter/provider boundary candidate. Audit each adapter for authority bypass and replay behavior. |
| L1 | Model integrations, MCP/tool clients, Git/shell/CI and provider APIs | Capability/tool plane; inventory is not exhaustive in this initial audit. |

This is an initial mapping, not a completed repository-wide import graph. A module may contain code owned by more than one layer; classify functions and side effects, not filenames alone.

## Dependency rules

Allowed direction for direct calls/data contracts:

- L6 may use L5 persistence interfaces to commit validated decisions.
- L5 exposes committed records to L4/L3/L6; it does not call providers.
- L4 invokes L3 and consumes committed L5 state plus L6 decisions.
- L3 invokes L2 and submits observations/evaluation inputs to L6.
- L2 invokes L1 and returns untrusted outputs/receipt candidates upward.
- L1 has no dependency on AIOS internals.

Prohibited patterns:

- L1/L2/L3/L4 importing policy internals to mint or widen permits.
- L2/L3/L4/L5 calling promotion APIs on behalf of an agent without L6 validation.
- L5 scheduling provider calls or deciding retry eligibility.
- L4/L3 treating task completion, process exit code, or model text as a verified receipt.
- L2 resume path re-executing an already-dispatched external operation instead of reconciling it.
- Any lower layer mutating immutable contract, policy digest, evidence requirements, retry budget or terminal criteria.

## Rollout policy

1. Inventory imports, write paths, provider calls and state stores before enforcing import restrictions.
2. Mark each finding as FACT (source-backed), VERIFIED (reproduced by test), INFERRED or UNKNOWN.
3. Add architecture tests in report-only mode first; establish a reviewed baseline.
4. Convert only confirmed invariants into blocking CI checks.
5. Refactor incrementally with behavior-preserving tests; no wholesale service split.
6. Do not merge, deploy, create production resources or change production IAM as part of architecture mapping.

## Definition of architecture conformance

A change is conformant only when its PR identifies the owning layer, interfaces crossed, state read/written, authority exercised, provider effects possible, evidence emitted, recovery behavior and tests proving the relevant invariants.
