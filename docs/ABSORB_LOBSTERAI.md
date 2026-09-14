# AIOS — LobsterAI absorption boundary

Status: absorbed as architecture patterns only. LobsterAI is not an AIOS dependency and does not become an authority layer.

## Absorb

1. **Durable session/workspace**
   - Long-running work is a durable session with explicit state, history and artifacts.
   - Resume must load persisted state before any new action.

2. **Runtime adapter boundary**
   - Product/session orchestration stays above the runtime.
   - OpenClaw, Gemini, Codex, Pi/OMP and future runtimes are adapters/providers.
   - Adapters return structured execution receipts; free-form runtime output is not authoritative state.

3. **Permission/approval binding**
   - Sensitive execution requires an AIOS-owned permit.
   - The permit binds the canonical effect/request to the execution attempt.
   - A changed command, scope, target, session or relevant execution context invalidates the permit.

4. **Scheduler as a worker trigger**
   - Scheduling only wakes/resumes a durable non-terminal workload.
   - The scheduler cannot alter policy, terminal criteria, evidence requirements or authority.
   - Duplicate dispatch is prevented by durable state + active-run detection.

5. **Failure/restart lifecycle**
   - Runtime startup, restart and repair are observable state transitions.
   - A crash or interrupted runtime resumes from the last persisted checkpoint rather than inventing continuation state.

## Do not absorb

- Electron/Cowork UI architecture.
- Product-specific skills or office workflows.
- Memory files as authoritative evidence.
- Runtime-specific policy as a second control plane.
- Unbounded autonomous retry.

## AIOS mapping

```text
session/workspace -> durable runtime state
scheduler          -> RESUME trigger
permission         -> CONTRACT -> PERMIT
runtime adapter    -> DISPATCH -> EXECUTE_ATTEMPT
runtime result     -> RECEIPT
verification       -> OBSERVED / EVIDENCED / VERIFIED
persistence        -> lineage + evidence + state
terminal decision  -> AIOS policy/gate only
```

The governing rule remains: runtime providers may execute; they cannot redefine AIOS policy, evidence requirements, promotion criteria, budget, authority or terminal conditions.
