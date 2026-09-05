# AIOS Research Harvest

Status: **engineering baseline, 2026-09-05**

Research is a first-class harvest lane. A paper is not adopted as authority; it contributes an evidence-backed pattern, test hypothesis, or architectural constraint. Every item is classified against AIOS invariants.

## Reuse classes

- **ADOPT-PATTERN** — reimplement the mechanism inside AIOS contracts.
- **ADAPTER** — integrate behind a replaceable runtime/provider boundary.
- **REFERENCE** — architecture/evaluation insight only.
- **REJECT** — conflicts with AIOS authority, evidence, or terminal semantics.

## 2026 research findings

| Research | Finding relevant to AIOS | Treatment | Priority |
|---|---|---|---:|
| Barbaste et al., *Harness Engineering* (arXiv:2609.00006) | Production coding harnesses converge on hand-built runtime loops, deterministic retrieval, layered safety, persistent state, skills/MCP, and platform-like extension surfaces. | REFERENCE + ADOPT-PATTERN | P0 |
| Lin et al., *Agentic Harness Engineering* (arXiv:2604.25850) | Harness evolution can be a closed loop where each edit declares a prediction and is evaluated against subsequent outcomes; observability makes changes revertible and falsifiable. | ADOPT-PATTERN | P0 |
| Zhong & Zhu, *AI Harness Engineering* (arXiv:2605.13357) | Harness responsibility includes task specification, context, tools, memory, task state, observability, failure attribution, verification, permissions, entropy auditing, and intervention recording; episode packages make runs auditable. | ADOPT-PATTERN | P0 |
| Ning et al., *Code as Agent Harness* (arXiv:2605.18747) | Code can serve as the operational substrate for reasoning, action, environment modeling, and execution-based verification; evaluation must extend beyond final task success. | REFERENCE + ADOPT-PATTERN | P0 |
| Dhage, *Harness Engineering for Predictable Agentic Systems* (arXiv:2608.26197) | Structured planning/schema validation can reduce execution variance; constraint cost is model-dependent and must itself be measured. | ADOPT-PATTERN | P1 |
| Zheng et al., *OneDayAgent* (arXiv:2608.05013) | Long-horizon harnesses need bounded subtasks, execution memory under context pressure, and verify/repair of deliverables across backend models. | ADOPT-PATTERN | P0 |
| Ma et al., *LongHorizon-Harness* (arXiv:2608.01964) | Task state should live explicitly outside execution and be updated only from independently verified environment facts; manager, fresh-context executor, and read-only auditor form a strong state-control pattern. | ADOPT-PATTERN | P0 |
| Pai & Xian, *Long-Horizon State Tracking* (arXiv:2609.00012) | End-to-end success hides state-bookkeeping failure; dependent tool chains need explicit intermediate-state validation. | ADOPT-PATTERN | P0 |
| Mansoor et al., *Verified Tool Calls* (arXiv:2608.02645) | Tool calls are non-atomic; timeout/delayed visibility/partial updates require postcondition verification, verify-before-retry, and idempotency keys. | ADOPT-PATTERN | P0 |
| Sun et al., *Agentic Transaction* (arXiv:2608.13900) | Agent execution benefits from semantic Atomicity, Consistency, Isolation, and Durability; exploration/execution/validation can be treated transactionally. | REFERENCE + ADOPT-PATTERN | P0 |
| Mohammadi, *trajectory-judge* (arXiv:2609.00038) | Outcome-only judges miss silent trajectory faults; verification must inspect steps and fault classes, not only the final answer. | ADOPT-PATTERN | P0 |
| Li et al., *SilentProbe* (arXiv:2609.00035) | Prose-only tool constraints frequently fail silently; machine-checkable schemas materially improve error honesty. | ADOPT-PATTERN | P0 |
| Tan et al., *AgentChaos* (arXiv:2608.06790) | Runtime fault injection across crash/omission/value faults exposes robustness gaps and poor fault localisation. | ADOPT-PATTERN | P0 |
| Zhao & Zhao, *Runtime-Independent Persistent Agents* (arXiv:2609.00546) | Continuity-bearing identity, memory, and versioned body can be separated from replaceable reasoner/harness/host bindings; migration requires quiesce/checkpoint/validate/bind/rehydrate/resume. | REFERENCE + ADOPT-PATTERN | P0 |
| Jiang et al., *HarnessEvolve* (arXiv:2609.00829) | Self-evolution should separate execution, evaluation, optimization, and gating; candidate harness updates need quality/performance gates and held-out validation to prevent shortcut learning and regression. | ADOPT-PATTERN | P0 |
| Yan et al., *Harness-of-Harness* (arXiv:2609.01481) | Continual improvement benefits from small verifiable increments, independent evaluation, versioned histories, and reuse of capabilities rather than recreation. | ADOPT-PATTERN | P0 |
| Wu et al., *HarnessDev* (arXiv:2609.01437) | Harness creation/evolution gains can be unstable and transfer only partially across models; fixed-runtime evaluation is necessary to distinguish harness gains from model dependence. | REFERENCE + ADOPT-PATTERN | P0 |
| Sakhinana & Runkana, *Agentic Cloud Engineering* (arXiv:2609.00050) | Graph progression, bounded repair loops, zero-trust identity/authorization/capabilities, and machine-checkable operational evidence provide a strong governed-runtime pattern. | REFERENCE + ADOPT-PATTERN | P0 |
| Huang et al., *Harness the Memory* (arXiv:2608.15008) | No single memory substrate dominates; retrieval value depends on task regime and can become harmful as history grows, motivating explicit memory-substrate routing. | REFERENCE + ADOPT-PATTERN | P1 |
| Chen et al., *The Horizon Gap* (arXiv:2608.06663) | Across 1,547 papers, outcome-only signals become less informative with longer horizons; step-level diagnostics and explicit separation of long-horizon, long-context, and long-term memory are necessary. | REFERENCE + ADOPT-PATTERN | P0 |
| Bhardwaj et al., *SuperLocalMemory 4.0* (arXiv:2608.08253) | Governed memory writes need generation fences, policy registry, verify/compensate/erase ownership, and auditable completion manifests. | ADOPT-PATTERN | P1 |
| Margalit et al., *Governed Shared Memory* (arXiv:2606.24535) | Shared memory fails through leakage, stale propagation, contradiction persistence, and provenance collapse; scope, supersession, provenance, and policy-governed propagation are explicit primitives. | ADOPT-PATTERN | P1 |
| Wu & Zhu, *Agent Zero Memory* (arXiv:2608.29606) | Durable memory should preserve event/time provenance and citation-locked evidence; abstention is preferable to unsupported recall. | REFERENCE + ADOPT-PATTERN | P1 |

## Direct AIOS deltas

### P0 — enforce now

1. **Research evidence is not implementation authority.** Papers inform contracts/tests; they cannot redefine AIOS policy or terminal semantics.
2. **Trajectory is evidence.** Persist step/attempt/action/observation/verification references so a correct final result cannot erase a faulty path.
3. **Authoritative task state is outside execution context.** Execution may propose state; only independently verified evidence may advance the authoritative state machine.
4. **Intermediate-state checks.** Long dependency chains require checkpoint/state invariants at meaningful transitions.
5. **Non-atomic effect semantics.** Every effect gets immutable identity before dispatch; timeout/partial visibility becomes UNKNOWN; resume reconciles UNKNOWN before retry.
6. **Machine-checkable capability contracts.** Inputs, enums, permissions, side effects, postconditions, evidence outputs, and verification requirements must be schema-validatable where practical.
7. **Fault injection as conformance.** Inject pre-dispatch crash, post-dispatch timeout, partial update, corrupted output, duplicate resume, stale state, and provider faults.
8. **Trajectory-level verification.** Add silent-fault detection separately from outcome correctness.
9. **Continuity protocol.** Runtime/provider replacement must preserve authoritative AIOS state through checkpoint → validate → rebind → rehydrate → resume.
10. **Falsifiable harness evolution.** A harness change must record predicted impact, evidence window, evaluation result, held-out regression result, and rollback lineage; the agent cannot self-promote the change.
11. **Independent evaluation boundary.** Harness/workload implementation tests cannot be the sole promotion evidence; a separate evaluator must validate terminal artifacts against immutable criteria.
12. **Cross-model transfer test.** A harness improvement must be evaluated with fixed harness policy against multiple model backends, or explicitly marked model-specific.

### P1 — build next

13. Governed memory admission with generation fencing and provenance-bound writes.
14. Contradiction/supersession propagation rules for shared memory and experience.
15. Research episode packages linking task contract, trajectory, evidence, verification, outcome, and artifact.
16. Explicit measurement of harness overhead: latency, tokens, retries, and reliability gains.
17. Memory-substrate routing based on workload regime rather than a universal retrieval default.

## AIOS test consequences

A conformant workload should be evaluated at four distinct levels:

`Contract correctness -> Authoritative state/trajectory integrity -> Evidence/verification correctness -> Terminal/promotion correctness`

A passing final answer is insufficient if any earlier level is invalid.

## Source notes

Primary research sources include the arXiv records for the papers above. Research claims should be rechecked against the paper version and released evidence/code before being promoted from REFERENCE to ADOPT-PATTERN.