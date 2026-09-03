# Harness Reference: Claude Code / Jarvis-style durable execution

Status: IMPLEMENTATION GUIDANCE. This document does not treat any external harness as an authority or as a benchmark claim.

## Purpose

Claude Code-class harnesses demonstrate an important separation: model capability and agent durability are different engineering layers. Jarvis-style work further motivates persistent state and replayable execution. AIOS adopts the durable-loop pattern without copying implementation details or making any claim about proprietary internals.

## AIOS rule

The workload agent is allowed to:

- observe state;
- propose a plan/decision;
- request an action through an authorized capability;
- inspect the result;
- propose verification/recovery actions.

The workload agent is **not** allowed to change:

- governing policy;
- evidence requirements;
- capability authority;
- execution budgets;
- promotion criteria;
- terminal conditions.

Those belong to the AIOS control plane.

## Canonical loop

`OBSERVE -> DECIDE/PLAN -> ACT -> VERIFY -> PERSIST STATE -> RESUME`

Persistence occurs after each meaningful iteration, not only at the end. A crash, timeout, interruption, or process restart therefore resumes from a recorded state rather than relying on conversational context.

## State model

Minimum durable state:

- execution/task identity;
- policy/contract reference;
- capability/version identity;
- current step and lifecycle status;
- observation/decision/action/verification records;
- evidence/provenance references;
- contradiction/block records;
- recovery/resume metadata;
- terminal result when reached.

Conversation history is not the source of truth for any of these fields.

## External policy boundary

The harness receives an immutable policy object from the control plane. The agent may iterate inside that policy but cannot enlarge its budget or redefine success. Exhausting the budget without a governed terminal decision produces `INCONCLUSIVE`, not an agent-selected success.

## Memory architecture

Use two distinct stores:

1. **Working state** — compact state required to resume the current execution.
2. **Evidence/history** — append-only or otherwise auditable records retrieved when needed.

Do not treat summaries as authoritative evidence. A summary is a derived view with provenance back to raw records.

## Provider/replay isolation

Provider-specific replay, API-key services, model gateways, and compatibility shims are experimental adapters. They must never become:

- the AIOS authority store;
- the evidence source of record;
- the promotion gate;
- a hidden dependency of the control plane.

A replayed response is an execution input/result and must carry provenance describing its provider, model, adapter, and replay status.

## What we borrow vs. what we add

| Pattern | AIOS treatment |
|---|---|
| Durable long-running loop | Adopt |
| Explicit persisted state | Adopt |
| Resume after interruption | Adopt |
| Model/harness separation | Adopt |
| Retrieval-based memory | Adopt, with provenance |
| Provider replay | Optional adapter only |
| Agent-controlled policy | Reject |
| Agent-controlled terminal criteria | Reject |
| Unverified memory promoted to fact | Reject |
| Self-promotion of modified capability | Reject |

## Proof requirement

A harness feature is not considered complete because an agent appears to run for a long time. It must demonstrate restart/resume, bounded execution, evidence preservation, verification, and externally governed terminal behavior.
