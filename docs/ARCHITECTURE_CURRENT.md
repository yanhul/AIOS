# AIOS Current Architecture

AIOS is the policy, authority, evidence and verification control plane — not an agent runtime.

```text
Contract → Permit → Capability → Effect
                         ↓
                 RuntimeAdapter
                         ↓
       Browser / Coding / Research Agent
                         ↓
                  Provider Receipt
                         ↓
              AIOS Verify → Gate → Terminal
```

## AIOS owns

- immutable execution contract and deterministic identity;
- permit binding and authorization;
- capability and allowed-effect checks;
- external-effect identity and semantic state;
- explicit attempt identity and bounded retry policy; UNKNOWN retry is fail-closed pending independent issuer verification;
- evidence requirements and provider-receipt binding;
- verification, gates and terminal conditions;
- audit/lineage and fail-closed behavior.

Agents and external runtimes cannot modify the governing contract, policy, capabilities, evidence criteria, evaluator, promotion criteria, retry budget or terminal conditions.

## Runtime boundary

`execute()` authorizes and establishes the first effect/attempt. `execute_attempt()` executes one already-dispatched attempt. UNKNOWN retry execution is currently BLOCKED. No retry may be dispatched until an independent issuer/verifier authorizes the exact effect and attempt.

The durable runtime adapter is deliberately thin. State reads, transition preconditions, and journaled writes for an effect share one cross-process mutation lock, so only one caller can claim a PLANNED dispatch.external substrates own scheduling, persistence, retry timing, resume, planning, subagents and agent loops. AIOS validates the handoff and provider evidence and remains the final authority.

Browser/computer-use, coding and research agents therefore enter as external providers/capabilities. AIOS does not become a browser-agent or workflow-engine clone.

## Durable loop

**Observe → Decide/Plan → Act → Verify → Persist State → Resume**

The substrate implements loop mechanics; AIOS governs authorization, evidence, verification and termination.

## Reuse rule

Reuse mature execution substrates for browser/computer use, coding-agent orchestration, MCP/connectors, skills, memory, sandboxing, scheduling and durable workflow execution. Do not duplicate those engines inside AIOS. See `REUSE_AUDIT.md`.

## Documentation status

This file records the current architecture and supersedes the older M1/M1.5 framing where it conflicts with the implemented contract/authority/effect/runtime boundary.
