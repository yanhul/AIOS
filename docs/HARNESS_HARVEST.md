# Global Harness / Agent-System Harvest

Status: **engineering baseline, 2026-09-04**

This document records patterns worth harvesting into AIOS. It is an engineering inventory, not a claim that every project is production-safe or that every implementation should be copied.

## Selection rule

AIOS owns the authority boundary. External systems may contribute implementation patterns for execution, persistence, isolation, tracing, memory, routing, evaluation, and interoperability. They must not become the source of truth for:

- governing policy;
- evidence requirements;
- capability authority;
- budgets;
- promotion criteria;
- terminal conditions.

### Reuse classes

- **ADOPT-PATTERN** — reimplement the proven pattern inside AIOS contracts.
- **ADAPTER** — integrate behind an explicit runtime/provider boundary.
- **REFERENCE** — useful architecture only; do not import authority semantics.
- **REJECT** — conflicts with AIOS invariants or creates hidden control-plane authority.

## Harvest matrix

| System / family | Strong pattern to harvest | AIOS treatment | Priority | Why |
|---|---|---:|---:|---|
| LangGraph | checkpointed graph state, threads, time-travel, pending-write recovery, durable execution modes | ADOPT-PATTERN | P0 | Directly matches durable resume; improve AIOS step granularity and recovery semantics. |
| Temporal | durable workflow execution, activities, retries, signals, timers, deterministic workflow boundary | ADAPTER + ADOPT-PATTERN | P0 | Mature distributed-systems substrate; AIOS should keep policy/evidence above it. |
| OpenAI Agents SDK | explicit runner state, guardrails/tripwires, handoffs, sessions, tracing | ADOPT-PATTERN | P0 | Good execution lifecycle and observability primitives. |
| PydanticAI | typed dependencies, serialization boundaries, durable execution, retries, provider separation | ADOPT-PATTERN | P0 | Strong typed-contract discipline and provider isolation. |
| OpenHands | agent/runtime separation, event-driven execution, workspace/runtime abstraction | ADOPT-PATTERN | P0 | Useful workload/runtime boundary for coding and RE capabilities. |
| SWE-agent | structured trajectories, environment/tool abstraction, task execution records | ADOPT-PATTERN | P1 | Evidence-rich coding/RE trajectory model. |
| Aider | small composable coding loop, git-aware edits, replayable interaction history | ADAPTER / REFERENCE | P1 | Practical coding capability; keep git mutations behind AIOS effects. |
| Goose | extensible agent, provider/tool extension model, local-first execution | ADAPTER | P1 | Useful model/tool portability surface. |
| Letta | stateful agent memory, explicit memory blocks, persistence | ADOPT-PATTERN | P1 | Separate working state from long-lived experience; AIOS evidence remains authoritative. |
| LlamaIndex | retrieval/data connectors and agent workflows | ADAPTER | P1 | Capability for research/data workloads; provenance must remain AIOS-owned. |
| CrewAI | role/task/crew decomposition | REFERENCE | P2 | Useful decomposition patterns, but role semantics must not bypass AIOS authority. |
| AutoGen / AG2 | multi-agent conversation and delegation patterns | REFERENCE | P2 | Useful research patterns; avoid conversation-as-source-of-truth. |
| OpenAI Codex / Claude Code class harnesses | model/harness separation, tool execution, coding-agent ergonomics | REFERENCE | P0 | Confirms the common-harness boundary already adopted by AIOS. |
| OpenClaw | gateway/channel/tool integration | ADAPTER | P1 | Runtime surface only; never authority or evidence source. |
| browser-use | browser state/tool abstraction and autonomous web interaction | CAPABILITY ADAPTER | P1 | Natural reusable capability for research/RE; browser state is external context/evidence. |
| E2B | isolated execution sandboxes for agent code | ADAPTER | P0 | Strong candidate for safe execution effects. |
| Daytona | persistent sandboxes, snapshots, process/filesystem execution | ADAPTER | P0 | Persistent execution environments map well to long-running capabilities. |
| Decapod | repo-native governance, bounded convergence, proof-backed work | REFERENCE + ADOPT-PATTERN | P0 | Closest external architectural match to AIOS governance/convergence goals. |
| cl-agent | normalized episodes, replay, skill distillation, eval loops | ADOPT-PATTERN | P1 | Strong Experience/Evolution input model. |
| SuperLocalMemory | governed memory writes, generation fences, verify/compensate/erase, audit manifests | ADOPT-PATTERN | P1 | Useful for governed experience/memory transactions. |
| Agentic Transaction research | semantic atomicity/consistency/isolation/durability | REFERENCE | P0 | Provides a useful correctness vocabulary for external effects. |
| Runtime-independent persistent agents research | identity + durable memory + versioned body separated from runtime/harness/host | REFERENCE | P1 | Reinforces capability/runtime/provider separation and continuity. |
| MCP | standardized tool/resource protocol | ADAPTER | P0 | Interoperability layer for capability discovery/invocation. |
| A2A | agent-to-agent interoperability | ADAPTER | P1 | Future multi-agent network boundary; authorization remains AIOS-owned. |

## Concrete AIOS deltas from the harvest

### P0 — build now

1. **Durable step journal**: persist a stable execution ID, step ID, attempt ID, phase, action/effect ID, and verification outcome.
2. **Resume correctness**: resume from the last authoritative checkpoint without resetting budget or re-running already acknowledged work.
3. **External-effect protocol**: every side effect gets an AIOS effect ID and idempotency/reconciliation state before execution.
4. **Policy fingerprint**: persisted state is rejected if its immutable policy/contract fingerprint differs from the current control-plane policy.
5. **Terminal gate**: only the control plane can produce PASS/BLOCKED/INCONCLUSIVE.
6. **Evidence ledger**: every verification result points to structured evidence/provenance; summaries are derived views only.
7. **Runtime adapter boundary**: Temporal/LangGraph/OpenHands/OpenClaw/etc. remain replaceable execution adapters.
8. **Crash/fault tests**: inject interruption before action, after action, before verification, after verification, and during persistence.

### P1 — next

9. Capability graph planning with evidence-backed `requires/produces/composes_with/validated_by/works_under` edges.
10. Experience ledger: task -> capability/version -> action -> evidence -> result, including negative evidence.
11. Candidate capability evolution with regression, comparative evaluation, and external promotion gate.
12. Sandboxed execution adapters (E2B/Daytona/local container) with scoped filesystem/process/network permissions.
13. MCP/A2A capability discovery and invocation adapters.
14. Retrieval/memory subsystem with provenance, generation fencing, and governed writes.

## Non-negotiable rejection rules

- No external framework may redefine AIOS terminal states.
- No model/provider replay becomes authoritative evidence.
- No agent may enlarge its budget or permissions through a tool call.
- No memory summary becomes fact without evidence/provenance.
- No capability version self-promotes after modifying itself.
- No runtime adapter is allowed to mutate AIOS authority state except through the validated mutation/effect boundary.

## Evidence notes

The matrix was derived from current public documentation/repositories and recent research. Particularly relevant current sources include LangGraph persistence/checkpointing, OpenAI Agents SDK tracing/guardrails/run-state lifecycle, Daytona persistent sandboxes, Decapod governance, continual-learning episode/replay work, and recent research on runtime-independent persistence, governed memory, and agentic transactions.
