# AIOS Execution-Plane Reuse Audit

Status: **DECISION BASELINE**

This document records the post-landscape decision for reducing AIOS-owned execution code.
It is a design constraint for future implementation, not an authorization for an agent to
change policy, contracts, evidence requirements, gates, evaluators, or terminal conditions.

## 1. Target architecture

```text
                    AIOS CONTROL PLANE

 Contract / Permit / Policy / Capability Authority
 Evidence / Verification / Gates / Terminal Conditions
 Effect Identity / Receipt Validation / Lineage
                         |
                  RuntimeAdapter
                         |
       +-----------------+------------------+
       |                 |                  |
   Temporal         openJiuwen          DBOS/Restate
   DeerFlow         AgentScope          Kimi SDK
   Open SWE         Qwen-Agent         Claude/Codex/Gemini
       |                 |                  |
       +------------- Skills / MCP / A2A -+
                         |
                    Sandbox / Tools
                         |
                    Environment
                         |
               Independent Verification
                         |
                  Provider Receipt
                         |
                         v
                    AIOS Evidence
```

## 2. Keep / delete / wrap matrix

| AIOS surface | Decision | Rule |
|---|---|---|
| `core/contract.py` | KEEP | Canonical immutable execution contract. |
| `core/authority.py` | KEEP | Durable authority/policy binding. |
| `core/effect_authority.py` | KEEP, narrow | Own semantic external-effect identity and evidence-bearing state; do not become a workflow engine. |
| `core/runtime.py` | REFACTOR | Keep only a thin provider-boundary protocol, authorization-before-dispatch, receipt validation, and UNKNOWN mapping. |
| `adapters/process.py` | KEEP as fallback/test adapter | Minimal bounded local adapter; not the general orchestration engine. |
| Agent loop | DELETE | Supplied by an external agent runtime. |
| Planning/decomposition | DELETE | Supplied by the selected agent runtime. |
| Retry scheduler | DELETE | Supplied by durable execution substrate. |
| Resume/checkpoint engine | DELETE | Supplied by durable execution substrate. |
| Generic workflow/DAG engine | DELETE | Supplied by Temporal/DBOS/Restate/etc. |
| Multi-agent orchestration | DELETE | Supplied by AgentScope/openJiuwen/Deep Agents/Open SWE/etc. |
| Skills engine | DELETE | Consume the Agent Skills ecosystem. |
| MCP implementation | DELETE | Consume MCP servers/clients through adapters. |
| Sandbox | DELETE | Use OpenSandbox/Daytona/E2B/provider runtime. |
| Memory engine | DELETE | Use ReMe/Mem0/Letta/LangMem/etc.; AIOS retains authoritative state only. |
| Model router | WRAP/EXTERNALIZE | Provider/router concern, not authority. |
| Coding agent | WRAP | Claude/Codex/Kimi/Qwen/Open SWE/OpenHands/etc. |
| GUI/computer-use agent | WRAP | UI agent is a capability/provider. |
| Evidence lineage | KEEP | AIOS-owned acceptance/evidence semantics. |
| Verification | KEEP | Independent verification remains outside the executing agent's authority. |
| Gates | KEEP | Final acceptance remains outside the agent. |
| Terminal conditions | KEEP | Agent cannot rewrite completion criteria. |
| Fail-closed transitions | KEEP | Undefined/consequential transitions remain rejected. |
| Logical/attempt/provider identities | KEEP | Must remain distinct and bound in receipts. |
| Provider receipt validation | KEEP | Success must be explicitly observed, never inferred. |
| Audit/lineage | KEEP | External runtime telemetry can be imported, but AIOS acceptance state remains authoritative. |
| Self-improvement/RL | EXTERNAL RESEARCH PLANE | AgentJet/AgentEvolver/JIT-style systems may optimize execution, but cannot modify AIOS governing criteria. |

## 3. Priority candidates

### Tier S — benchmark before adding more runtime code

1. **Temporal Agent Harness** — durable workflow execution, resumability, approval policy,
   typed agent contracts, replayable lifecycle events.
2. **openJiuwen Agent Runtime** — uniform agent deployment, process/Docker/Kubernetes
   execution, lifecycle and multi-tenant runtime management.
3. **DeerFlow 2.x** — super-agent harness, subagents, persistent memory, sandbox, skills,
   and durable RunStore/resume semantics.

### Tier S adapters/backends

4. **Kimi Agent SDK** — thin programmatic interface over the Kimi Code runtime; reuse
   existing tools, skills and MCP while exposing sessions, approvals and streaming.
5. **AgentScope 2.x** — agent orchestration, permissions, middleware, MCP/skills, sandbox,
   memory and deployment ecosystem.
6. **DBOS** — Postgres-backed durable workflow/checkpointing, including integrations with
   OpenAI Agents and Vercel AI.
7. **Restate** — durable agent handlers with journaled model/tool/routing steps.

### Tier A — research/optimization plane

8. AgentJet
9. AgentEvolver
10. JIT-Agent / harness synthesis approaches
11. AgentRL / OpenManus-RL

These remain outside the AIOS authority plane.

## 4. First implementation sequence

### Phase A — freeze the boundary

Do **not** add an autonomous controller.
Do **not** add a home-grown retry/resume/workflow engine.
Do **not** add a home-grown skills or MCP subsystem.

Reduce `core/runtime.py` to the smallest stable `RuntimeAdapter` contract needed to:

1. load and verify contract/permit;
2. verify provider capability and allowed effect;
3. create the logical external effect;
4. dispatch exactly one execution attempt through an adapter;
5. validate a provider receipt bound to effect + attempt + provider;
6. persist explicit success/failure or UNKNOWN;
7. never let the adapter mutate AIOS authority state.

### Phase B — prove one external durable substrate

Benchmark Temporal Agent Harness first. Keep the integration behind `RuntimeAdapter`.
Do not make Temporal's approval policy the source of truth for AIOS acceptance criteria.
Temporal may enforce execution-time approval; AIOS remains authoritative for contract,
capability, evidence, verification and terminal acceptance.

### Phase C — prove one Chinese runtime adapter

Benchmark Kimi Agent SDK and/or openJiuwen. The test must prove that AIOS can swap the
execution runtime without changing the contract/evidence/gate layer.

### Phase D — compare DBOS/Restate

Only after the Temporal spike, compare DBOS and Restate against the same acceptance suite:
crash recovery, no duplicate completed provider call, UNKNOWN semantics, receipt binding,
resume, and terminal-condition enforcement.

## 5. Non-negotiable authority rule

External runtimes may own:

- planning;
- decomposition;
- retries;
- scheduling;
- memory;
- model selection;
- tool execution;
- subagents;
- skills;
- sandboxing;
- runtime lifecycle.

External runtimes may **not** own:

- governing policy;
- AIOS contract schema;
- evidence requirements;
- final verification semantics;
- promotion/acceptance criteria;
- terminal conditions;
- authority to self-escalate capabilities.

The agent may iterate inside these boundaries, but it cannot rewrite the boundaries.

## 6. Acceptance criteria for runtime replacement

A candidate runtime is not accepted merely because its demo works. It must pass the same
AIOS boundary suite:

- authorization happens before provider dispatch;
- unauthorized capability is rejected before any provider call;
- logical operation ID, execution attempt ID and provider operation/receipt ID remain distinct;
- provider timeout/crash/malformed receipt becomes UNKNOWN rather than guessed success;
- explicit provider observation is required for terminal success/failure;
- recovery does not duplicate an already-completed provider operation when the substrate
  provides a durable checkpoint/idempotency mechanism;
- runtime cannot rewrite AIOS policy/contract/evidence/terminal criteria;
- evidence remains attributable to the concrete provider observation;
- terminal acceptance remains an AIOS decision.

## 7. Current AIOS conclusion

AIOS should become **smaller**, not become another general-purpose agent framework.
The differentiated product is the authority/evidence/control plane that can sit above
multiple agent runtimes.
