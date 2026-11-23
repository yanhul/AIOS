# Six-Layer Boundary Audit — Initial Findings

Audit target: `yanhul/AIOS` default branch `main`
Audit type: source/document inspection, not a complete static import-graph or dynamic execution audit.
Audit branch: `architecture/six-layer-boundary-audit`

## Executive result

The six-layer model can be applied to the existing implementation without splitting AIOS into six services. The repository already contains meaningful L6, L5, L3 and L2 building blocks. L4 is not yet evidenced as a dedicated graph orchestrator. The immediate risk is not missing services; it is ambiguous ownership between authority, persistence and orchestration, plus runtime recovery semantics.

No runtime code was changed by this audit.

## Evidence-backed observations

| ID | Finding | Evidence inspected | Classification | Impact |
|---|---|---|---|---|
| F-01 | The current architecture document identifies AIOS as an authority/evidence control plane and external substrates as owners of scheduling, persistence, retries, resume, planning and agent loops. | `docs/ARCHITECTURE_CURRENT.md`, `docs/ROADMAP_CURRENT.md` | FACT | Existing direction is compatible with L6 and adapter boundaries, but does not by itself define six logical layers. |
| F-02 | The target architecture already defines governance/control plane and capability/workload plane, evidence-bound evaluation, durable execution and promotion invariants. | `docs/TARGET_ARCHITECTURE.md` | FACT | Six-layer contract should refine this document, not replace its invariants. |
| F-03 | `core/durable_loop.py` implements a governed loop with observe/decide/act/verify, terminal states and protected state fields. | Source inspection of `core/durable_loop.py` | FACT | Strong L3 candidate. It should not grow into a DAG scheduler. |
| F-04 | `core/orchestrator.py` exposes `GovernedRuntimeExecutor` and `run_governed_execution()`, wiring authority checks, contract policy, a state store and the durable loop. | Source inspection of `core/orchestrator.py` | FACT | This is a governed execution bridge, not evidence of a DAG/branching graph engine. Classify as L3/L4 boundary glue until a true graph contract exists. |
| F-05 | `core/runtime.py` owns provider adapter protocol, receipt validation, attempt execution, retry dispatch and resume entry points. | Source inspection of `core/runtime.py` | FACT | It currently spans L2 adapter translation and L6 evidence/effect semantics. Refactor by responsibility/API, not by blindly moving the file. |
| F-06 | `core/runtime.py::resume_attempt()` currently calls `_submit_runtime(..., "resume", ...)` and then calls `execute_attempt(...)` for the same dispatched attempt. | Source inspection of `core/runtime.py` on `main` | FACT | High-risk replay boundary: a resume can invoke provider execute again rather than reconcile the existing operation. Must be fixed or explicitly proven safe before treating recovery as conformant. |
| F-07 | Durable storage candidates include WAL and state-store modules as well as Firestore effect/permit stores. | Repository tree and source inspection of `core/durable_wal.py`, `core/wal_state_store.py`, effect-store modules | FACT | L5 exists in pieces; authoritative source of truth and consistency/transaction boundaries need a store inventory. |
| F-08 | `docs/ARCHITECTURE.md` retains an older M1/M1.5 description and future-work statements that conflict with the newer current/target architecture documents. | `docs/ARCHITECTURE.md` compared with `docs/ARCHITECTURE_CURRENT.md` and `docs/TARGET_ARCHITECTURE.md` | FACT | Documentation drift can mislead implementation and reviewers. This audit does not rewrite historical milestone documentation. |
| F-09 | `docs/STATE_MODEL.md` describes a project entity state engine as not implemented. It is not the same thing as the newer execution effect/attempt ledger. | `docs/STATE_MODEL.md` compared with current runtime/effect modules | FACT | Avoid claiming that one implementation proves the other; clarify domain-state vs execution-state ownership. |

## Highest-priority boundary defects / gaps

### P0 — Resume must reconcile, not replay

The inspected `main` implementation of `resume_attempt()` submits a runtime resume and then calls the provider execution path again. This conflicts with the invariant that a restart must recover/reconcile the same attempt without creating a second external effect.

Required remediation:
- Resume the exact existing attempt identity.
- Ask the provider adapter or external runtime for a read-only reconciliation result.
- Accept only authenticated, effect/attempt-bound evidence.
- Keep UNKNOWN when the provider cannot establish the outcome.
- Never call `adapter.execute()` as a side effect of resume.
- Add tests proving execute-call count does not increase during resume, including timeout/crash/ambiguous receipt cases.

Note: this finding is about the inspected default-branch source. A separate unmerged PR may contain a candidate fix; it does not change this main-branch finding until merged or otherwise integrated and verified.

### P1 — Establish one explicit L5 source-of-truth contract

Inventory each store and answer:
- Which records are authoritative for contract, permit, effect, attempt, receipt and workflow checkpoint?
- Which store is append-only event history, and which is a derived snapshot?
- Are effect/attempt transitions atomic with their event/outbox records?
- What is the replay/recovery rule after partial writes or backend unavailability?
- Are local WAL stores test-only, single-node runtime stores, or supported production stores?

Do not collapse distinct stores until consistency and deployment requirements are proven.

### P1 — Separate L6 decisions from L5 mechanics

The existing effect-authority and provider-evidence paths contain both semantic decisions and persistence operations. Define a narrow command/query contract:
- L6 validates whether a transition is allowed and what evidence is admissible.
- L5 atomically persists the authorized transition and returns committed identity.
- L5 never decides policy or invokes a provider.
- L6 never treats an uncommitted write or agent assertion as a committed fact.

This is a responsibility boundary; it does not require a new service or immediate file split.

### P2 — L4 is not yet a proven in-repository graph engine

The inspected `core/orchestrator.py` is a bridge to the durable loop. The current architecture explicitly recommends reusing external workflow substrates. Therefore:
- Do not build a generic DAG engine just to fill the diagram.
- Define an optional GraphOrchestrator contract only if a real multi-node DAG workload requires it.
- Otherwise let the external substrate own graph scheduling while AIOS L6 governs each effect and L5 records the durable authority/effect lineage.

### P2 — Documentation reconciliation

Use `docs/SIX_LAYER_ARCHITECTURE.md` as the six-layer boundary contract. Later update older docs with explicit status/supersession pointers rather than deleting historical milestone records or silently rewriting history.

## Proposed next implementation sequence

1. Fix and test the resume/reconciliation replay defect (P0).
2. Produce a complete L5 store inventory and source-of-truth decision table.
3. Define typed L6↔L5 transition interfaces and test atomicity/fail-closed behavior.
4. Decide whether L4 is external or an optional AIOS graph contract; do not implement a scheduler by default.
5. Add architecture checks for prohibited imports and side effects after the ownership map is reviewed.
6. Reconcile architecture docs and add the six-layer map to PR templates/review checklist.

## What this audit does NOT claim

- It does not claim a complete import graph, all modules or all side effects were inspected.
- It does not claim any architecture test or CI gate has passed.
- It does not claim six-layer conformance.
- It does not change runtime behavior or production resources.
- It does not merge any PR.

## Acceptance criteria for the follow-up implementation

- A resumed dispatched attempt never re-executes the provider operation.
- Every provider effect has immutable effect/attempt identity and bounded authorization.
- UNKNOWN remains non-terminal unless reconciled under policy; no blind retry.
- Event/attempt/effect persistence is atomic where the contract requires it.
- Graph scheduling cannot grant authority.
- Loop/harness/model output cannot self-promote to VERIFIED/PROMOTED.
- CI rejects at least the tested prohibited dependency and replay patterns.
