# Global Harness / Agent-System Harvest

Status: **engineering baseline, 2026-09-04**

This document records patterns worth harvesting into AIOS. It is an engineering inventory, not a claim that every project is production-safe or that every implementation should be copied.

## Selection rule

AIOS owns the authority boundary. External systems and research may contribute implementation patterns for execution, persistence, isolation, tracing, memory, routing, evaluation, and interoperability. They must not become the source of truth for:

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

## Research harvest

Research is a first-class harvest source. Papers are classified by architectural consequence, not by citation count or novelty alone.

| Research | Finding relevant to AIOS | AIOS treatment | Priority |
|---|---|---:|---:|
| **Harness Engineering: Anatomy, Architecture, and Evolution of Coding Agents** (arXiv:2609.00006, 2026) | Eleven production coding harnesses converge on custom async runtimes, deterministic retrieval, skills/MCP extension surfaces, and a platform-like harness layer. | REFERENCE + ADOPT-PATTERN | P0 |
| **Agentic Harness Engineering** (arXiv:2604.25850, 2026) | Harness evolution can be made falsifiable through component, experience, and decision observability; edits become predictions verified against later task outcomes. | ADOPT-PATTERN | P0 |
| **AI Harness Engineering: A Runtime Substrate for Foundation-Model Software Agents** (arXiv:2605.13357, 2026) | Runtime reliability is a system property spanning task specification, context, tools, memory, state, observability, failure attribution, verification, permissions, entropy auditing, and intervention recording. | ADOPT-PATTERN | P0 |
| **What makes a harness a harness** (arXiv:2606.10106, 2026) | Harness terminology needs operational boundaries separating runtime, framework, SDK, evaluator, and product. | REFERENCE | P1 |
| **The Last Harness You'll Ever Build** (arXiv:2604.21003, 2026) | Meta-level harness optimization can evolve task-specific scaffolds through evaluation loops. | REFERENCE | P1 |
| **Long-Horizon State Tracking in LLMs** (arXiv:2609.00012, 2026) | Tiny per-step errors compound over deep dependent tool chains; state-carrying itself must be evaluated independently from task interpretation. | ADOPT-PATTERN | P0 |
| **trajectory-judge: What Outcome-Only LLM Judges Miss** (arXiv:2609.00038, 2026) | Outcome-only judging misses silent trajectory faults; step-level fault localization materially improves detection. | ADOPT-PATTERN | P0 |
| **SilentProbe: Measuring Silent Failure in Production APIs Used as Agent Tools** (arXiv:2609.00035, 2026) | Prose-only API constraints can fail silently; machine-checkable schemas make tool behavior more observable and verifiable. | ADOPT-PATTERN | P0 |
| **From Storage to Experience** (arXiv:2605.06716, 2026) | Agent memory evolves from raw trajectory storage to reflection and experience abstraction; experience is a distinct layer. | ADOPT-PATTERN | P1 |
| **When Continual Learning Moves to Memory** (arXiv:2604.27003, 2026) | External memory does not remove continual-learning problems; representation and retrieval determine transfer, forgetting, and negative transfer. | REFERENCE + ADOPT-PATTERN | P1 |
| **Memory as a Controlled Process** (arXiv:2607.13591, 2026) | Memory retrieval/consolidation should be governed by context-dependent control rather than one fixed retrieval heuristic. | REFERENCE + ADOPT-PATTERN | P1 |
| **AgentDojo** (2024) | Tool-returned untrusted data can hijack agents; security evaluation must include realistic prompt-injection paths and tool interactions. | ADOPT-PATTERN | P0 |
| **AgentBench** (2023) | Agent performance is multi-dimensional; long-horizon reasoning, decision-making, and instruction following are distinct failure sources. | ADOPT-PATTERN | P1 |
| **Voyager** (2023) | Skill libraries plus environment feedback and self-verification can accumulate reusable executable behaviors. | REFERENCE + ADOPT-PATTERN | P1 |
| **Reflexion** (2023) | Feedback-derived episodic reflections can improve later attempts without changing model weights. | ADOPT-PATTERN | P1 |
| **Generative Agents** (2023) | Observation, planning, reflection, and memory retrieval form separable agent functions. | REFERENCE | P1 |
| **SWE-Bench Pro / SWE-Bench Mobile** (2025–2026) | Long-horizon, realistic engineering tasks expose large gaps and strong dependence on harness design; benchmark success is not equivalent to durable autonomy. | REFERENCE + ADOPT-PATTERN | P0 |

## Research-derived architecture deltas

### P0 — build now

1. **Durable step journal**: persist a stable execution ID, step ID, attempt ID, phase, action/effect ID, and verification outcome.
2. **Resume correctness**: resume from the last authoritative checkpoint without resetting budget or re-running already acknowledged work.
3. **External-effect protocol**: every side effect gets an AIOS effect ID and idempotency/reconciliation state before execution.
4. **Policy fingerprint**: persisted state is rejected if its immutable policy/contract fingerprint differs from the current control-plane policy.
5. **Terminal gate**: only the control plane can produce PASS/BLOCKED/INCONCLUSIVE.
6. **Evidence ledger**: every verification result points to structured evidence/provenance; summaries are derived views only.
7. **Runtime adapter boundary**: Temporal/LangGraph/OpenHands/OpenClaw/etc. remain replaceable execution adapters.
8. **Crash/fault tests**: inject interruption before action, after action, before verification, after verification, and during persistence.
9. **Trajectory-aware verification**: verify critical transitions and effects, not merely the final response/outcome.
10. **Machine-checkable capability schemas**: encode constraints, enums, preconditions, outputs, and failure states structurally; prose is explanatory only.
11. **Long-horizon state integrity tests**: test state propagation over deep dependent action chains independently from semantic task difficulty.
12. **Harness evolution as controlled experimentation**: every proposed harness change records its predicted effect, immutable experiment identity, observed outcome, and promotion decision.
13. **Adversarial tool-boundary tests**: untrusted tool output, prompt injection, malformed schemas, silent API failures, and confused-deputy attempts are explicit conformance cases.

### P1 — next

14. Capability graph planning with evidence-backed `requires/produces/composes_with/validated_by/works_under` edges.
15. Experience ledger: task -> capability/version -> action -> evidence -> result, including negative evidence.
16. Candidate capability evolution with regression, comparative evaluation, and external promotion gate.
17. Sandboxed execution adapters (E2B/Daytona/local container) with scoped filesystem/process/network permissions.
18. MCP/A2A capability discovery and invocation adapters.
19. Retrieval/memory subsystem with provenance, generation fencing, governed writes, and explicit experience abstraction.
20. Step-level evaluation schema separating observation, decision, action, effect, verification, and terminal outcome.
21. Controlled memory consolidation/pruning; never let retrieved experience silently become authoritative evidence.

## Non-negotiable rejection rules

- No external framework may redefine AIOS terminal states.
- No model/provider replay becomes authoritative evidence.
- No agent may enlarge its budget or permissions through a tool call.
- No memory summary becomes fact without evidence/provenance.
- No capability version self-promotes after modifying itself.
- No runtime adapter is allowed to mutate AIOS authority state except through the validated mutation/effect boundary.
- No outcome-only judge may be the sole verifier for a safety-critical or state-changing effect.
- No prose-only tool constraint may be treated as an executable precondition when a machine-checkable contract is required.
- Harness self-improvement must not modify the governing policy, evidence requirements, promotion criteria, or terminal conditions.

## Evidence notes

The matrix combines public implementation evidence with recent research. High-impact research anchors include arXiv:2609.00006, 2604.25850, 2605.13357, 2609.00012, 2609.00038, 2609.00035, 2605.06716, 2604.27003, 2607.13591, AgentDojo, AgentBench, Voyager, Reflexion, Generative Agents, and realistic long-horizon software-agent benchmarks. Research findings are treated as evidence for design hypotheses, not as authority for AIOS state or policy.
