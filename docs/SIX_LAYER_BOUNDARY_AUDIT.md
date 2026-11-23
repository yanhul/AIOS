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


## P0–P5 execution addendum (2026-11-23)

This addendum separates work that can be established from the inspected default branch from candidate changes that remain unmerged.

### P0 — Resume/replay safety

- **FACT on `main`:** the original `resume_attempt()` called `execute_attempt()` for an already-dispatched attempt.
- **Candidate implementation:** PR #167 changes resume to call read-only `adapter.reconcile()`; missing/ambiguous provider results remain `UNKNOWN`; resume does not call `adapter.execute()`.
- **Regression correction:** the existing durable-runtime bridge fixture previously expected resume success from an adapter with no reconciliation method. That expectation contradicted the no-replay invariant. The fixture now supplies an explicit read-only reconciliation method.
- **Verification:** the earlier PR #167 CI run `45125149786` had 849 passed, 16 skipped, 1 failed. The sole failure was the stale expectation in `tests/test_m6_durable_runtime_bridge.py::test_resume_reuses_exact_dispatched_attempt_after_ambiguous_submission`. The fixture correction is commit `ee635c7cd8c2616c4bc5e6fd29bfe46de4b0cf0c`; its CI run `45129143045` was in progress when this addendum was written.
- **Status:** implementation candidate present; full CI verification pending; PR #167 remains unmerged. This does not establish provider-side exactly-once behavior.

### P1 — L5 persistence/source-of-truth inventory

| Record family | Current implementation observed on `main` | What is actually established | Gap / decision needed |
|---|---|---|---|
| Contract / permit / attestation | `core/authority.py`; `<aios_dir>/authority/{contracts,permits,attestations}/`; `commit_batch` | File-backed records; contract identity and permit/attestation validation | Define supported multi-process/multi-host deployment and backup/restore contract |
| Governing policy | `core/policy_registry.py`; `<aios_dir>/policies/` | Content-addressed immutable JSON policy records | Clarify lifecycle/retention and whether policy records share the same transactional boundary as contract/permit |
| External effect / attempt / event | `core/effect_authority.py`; `<aios_dir>/effects/` and `<aios_dir>/events/`; `core/mutation.py::commit_batch` | Effect transition and corresponding event are committed in one file mutation batch with a precondition/CAS check | Event history is file-per-event, not a separately demonstrated append-only database ledger; audit retention/recovery at deployment scale |
| Domain/project state | `core/state.py`, `core/mutation.py`, `.aios/<type>/{events,snapshots,...}/` | Domain entity layout and a staged journal/roll-forward mutation boundary | This domain state is not the same object model as execution effect/attempt state |
| Durable loop state / memory | `core/durable_loop.py::StateStore`; `core/wal_state_store.py`; `core/durable_wal.py` | WAL-backed state projection and memory namespace; checksummed records and process lock in the WAL implementation | Not shown to be the authoritative store for contract/permit/effect records; no proven cross-store atomic transaction |
| Capability registry | `core/capability_store.py` | Atomic snapshot replacement of registry data | Snapshot store is separate from authority/effect mutation journal |

**Finding:** L5 is currently a set of distinct persistence mechanisms, not one unified ledger. The repository evidence does not justify declaring any single database or WAL the global source of truth. Keep per-domain authority explicit; define a cross-store consistency/recovery contract before consolidation. In particular, do not describe a WAL snapshot as proof that a provider effect occurred.

### P2 — L6 decision vs L5 persistence boundary

- **FACT:** `core/effect_authority.py` validates contract/permit/effect/attempt transitions and calls `commit_batch` to persist effect records and events.
- **FACT:** `core/authority.py` persists contract, permit and attestation files through the same mutation primitive.
- **INFERENCE:** semantic authority and storage mechanics are coupled at module/function level, even though their conceptual responsibilities differ.
- **Decision:** retain the current implementation boundary for compatibility; define a typed L6 command/query contract and an L5 repository/transaction interface before moving code. The L5 interface may commit only an L6-authorized transition and return committed record/event identities; it must not decide policy or call providers.
- **Not claimed:** no new interface or atomicity guarantee has been implemented by this audit.

### P3 — L4 graph-orchestration placement

- **FACT:** `core/orchestrator.py` wraps `run_durable_loop()` and `GovernedRuntimeExecutor`; it is not evidence of a general DAG engine.
- **FACT:** `docs/ARCHITECTURE_CURRENT.md` says external substrates own scheduling, retries, resume, planning and agent loops.
- **Decision:** L4 remains an external-substrate responsibility for the current architecture. AIOS exposes governed node/effect contracts and consumes committed evidence. Add an optional in-process GraphOrchestrator only after a concrete multi-node DAG use case and its recovery semantics are specified.
- **Constraint:** a graph node or scheduler event never grants effect authority.

### P4 — Architecture conformance enforcement

- **Current status:** no blocking six-layer import/side-effect conformance gate is established by this audit.
- **Required first gate:** report-only inventory of imports and side-effect call sites, with explicit allowlist and owner review. It must detect at minimum: provider execution from L5, authority/promotion calls from L1/L2/L3/L4, and resume-to-execute replay.
- **Promotion rule:** convert a rule to blocking CI only after its baseline and false-positive behavior are reviewed. A grep-only check is not sufficient proof of runtime call behavior.
- **Not claimed:** no architecture CI test has passed or been added in this addendum.

### P5 — Documentation and review contract

- `docs/ARCHITECTURE_CURRENT.md` remains the current implementation boundary and identifies external substrates as owners of execution mechanics.
- `docs/TARGET_ARCHITECTURE.md` remains the target vision and explicitly says not all target components are implemented.
- `docs/SIX_LAYER_ARCHITECTURE.md` refines those documents as a logical ownership map; it does not supersede them or require six services.
- `docs/ARCHITECTURE.md` is historical M1/M1.5 framing. It should receive a supersession pointer only after a separate minimal edit is reviewed; do not rewrite milestone history.
- Review checklist for future PRs: identify owning layer, interfaces crossed, authoritative state read/written, authority exercised, provider effects possible, evidence emitted, recovery behavior and tests.

### Consolidated P0–P5 status

| Priority | Outcome in this turn | Evidence / remaining gate |
|---|---|---|
| P0 | Candidate fix and stale test-fixture correction committed on PR #167 | Commit `ee635c7...`; CI run `45129143045` pending; PR unmerged |
| P1 | Source-of-truth inventory documented | Source inspection only; no cross-store consistency proof |
| P2 | L6/L5 responsibility boundary and interface contract specified | Design decision only; no code interface implemented |
| P3 | L4 assigned to external substrate for now | Consistent with current architecture; no graph engine added |
| P4 | Enforcement design and promotion rule documented | No blocking architecture gate added or claimed |
| P5 | Current/target/six-layer/historical doc precedence clarified | Historical doc edit remains separate; no history rewritten |

This is the maximum evidence-supported P0–P5 closure from the current source snapshot. It is not a claim that all six priorities are implemented or that AIOS is six-layer conformant.


## Implementation follow-through — P2/P4 (2026-11-23)

### P2 — L6→L5 persistence seam

- Added `core/authority_store.py` with a typed `AuthorityStore` protocol and `FileAuthorityStore` adapter.
- Routed contract/permit/attestation and external-effect journal commits/recovery through this L5 adapter from `core/authority.py` and `core/effect_authority.py`.
- The adapter delegates atomic batch/CAS mechanics to the existing journaled mutation primitive. It receives payloads and preconditions; it does not authorize policy, validate provider receipts, choose providers, or execute effects.
- This is a first in-process boundary seam, not a unified database, cross-store transaction, or multi-host consistency guarantee.

### P4 — report-only L5 dependency gate

- Added `scripts/architecture_boundary_check.py` and focused tests.
- Initial scope is deliberately narrow: the five named L5 persistence modules must not import adapter/provider/network execution surfaces.
- Added the report-only checker to the existing full-suite CI job. It emits machine-readable JSON and does not fail CI for baseline findings.
- `--strict` is available for a later reviewed promotion; it is not enabled in this change.
- This does not yet enforce every cross-layer rule or prove runtime call graphs.

