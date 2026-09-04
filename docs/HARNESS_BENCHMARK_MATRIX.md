# AIOS Harness Benchmark Matrix

Status: RESEARCH BASELINE — not a claim that every feature is implemented.

## Purpose

Benchmark non-China agent/harness systems for reusable architecture patterns. The objective is not to rank models by marketing claims. A feature enters AIOS only when its behavior is supported by primary documentation, source code, reproducible tests, or an explicit experiment.

## Systems reviewed

| System | Origin | Strong observed area | Candidate AIOS lesson | Adoption status |
|---|---|---|---|---|
| Claude Code | Anthropic / US | Coding harness, tool loop, project context | Harness as first-class runtime boundary | Reference only |
| OpenAI Codex CLI | OpenAI / US | Local coding agent, approvals, multimodal input | Provider-independent execution boundary; approval modes | Reference |
| Gemini CLI | Google / US | Session resume, skills/extensions, context files | Explicit session continuation + extension surface | Candidate |
| OpenHands | Open source | Model-agnostic coding-agent platform and control layer | Separate agent runtime/control surface from model | Candidate |
| Aider | Open source | Repository mapping, Git, automatic lint/test loop | Deterministic repo context + test feedback | Candidate |
| Letta | US / open source | Stateful agents, persistent memory, memory-as-files | Separate durable memory from active context | High-value candidate |
| LangGraph | Open source | Durable execution, checkpoints, HITL, stateful workflows | Explicit checkpoint/resume primitive | Reference architecture |
| Hermes Agent | Nous Research / US | Skills from experience, persistent memory, subagents, scheduling | Experience → skill pipeline; procedural memory | High-value candidate |
| Mistral Vibe | Mistral / France | Minimal CLI coding agent | Keep model/provider layer replaceable | Reference |
| OpenClaw | Open source | Embedded runtime, workspace/bootstrap/session contract | Agent workspace + session boundary | Candidate |
| SWE-agent | Princeton / open source | Research-oriented software-engineering agent | Benchmark-driven tool/action loop | Reference |

## Strongest patterns to import

### P0 — Durable execution

AIOS already defines and implements the governed loop:

`OBSERVE -> DECIDE/PLAN -> ACT -> VERIFY -> PERSIST STATE -> RESUME`

The external policy owns retry limits and terminal conditions. The agent cannot rewrite them.

### P0 — Evidence-bound memory

Memory must not become an unverified fact store. Persist provenance, origin, timestamp/version, evidence pointers, and verification status. Retrieval must preserve the evidence boundary.

### P0 — Runtime-independent identity/state

A durable workload should be able to replace model/provider/harness without silently losing governed state. Provider binding is replaceable; authority, contract, evidence and lineage are not.

### P1 — Skill/experience promotion

A successful trajectory may propose a reusable skill/capability version, but promotion must pass regression/evidence gates outside the agent. Failed and contradictory trajectories remain negative evidence.

### P1 — Deterministic repository context

Prefer deterministic file/tree/search/context mechanisms over opaque semantic retrieval for source code. Embeddings may be supplemental, never the authority for exact source selection.

### P1 — Session/workspace contract

Every workload should have an explicit workspace, bootstrap/context contract, session identity and recoverable state. This should be registered as capability metadata rather than hidden in prompts.

### P2 — Human intervention as a governed event

Human approval/inspection can be represented as an authority-bearing state transition, not merely a UI feature. Approval must be scoped to the contract/action and recorded in provenance.

## Strict anti-patterns

- Do not equate a stronger model with a stronger harness.
- Do not import provider-specific API/replay credentials into AIOS authority.
- Do not treat self-written memory as verified truth.
- Do not allow the agent to modify policy, evidence requirements, promotion criteria, budget, or terminal conditions.
- Do not claim a feature exists in a system without primary evidence.
- Do not use benchmark scores as proof of architectural correctness.

## Next implementation targets

1. Add a first-class `MemoryRecord` with provenance + verification state.
2. Add governed checkpoint/resume records to the execution state model.
3. Add capability-version candidate → evaluation → promotion gates.
4. Add provider/harness binding as replaceable infrastructure metadata.
5. Build one cross-repository endurance test using `try` as the first workload, then Android and RX50.

## Primary references

- OpenAI Codex CLI: https://github.com/openai/codex
- Gemini CLI: https://github.com/google-gemini/gemini-cli
- OpenHands: https://www.openhands.dev/
- Aider: https://github.com/Aider-AI/aider
- Letta: https://www.letta.com/
- LangGraph: https://github.com/langchain-ai/langgraph
- Hermes Agent: https://github.com/NousResearch/hermes-agent
- Mistral Vibe: https://github.com/mistralai/mistral-vibe
- OpenClaw: https://github.com/openclaw/openclaw

This document records architecture observations only. It is not a validation report and does not certify any external system or AIOS itself.
