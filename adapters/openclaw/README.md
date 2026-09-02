# AIOS — OpenClaw Adapter Boundary (Placeholder)

Status: M0 — boundary specification only. OpenClaw is NOT installed or configured.

## Documented boundary (future)

```
AIOS task
→ OpenClaw adapter
→ runtime
→ tools
→ structured result
→ AIOS validation
```

## Contract (documented intent)

- AIOS emits a task with a defined scope and permissions.
- The OpenClaw adapter translates the task to the runtime.
- The runtime executes against allowed tools.
- The adapter returns a structured result (not freeform).
- AIOS validates the result against the task contract and state rules before accepting it.
- No unvalidated result enters AIOS state.

## Current state

- No code, no installation, no configuration.
- Integration belongs to M6 (see `docs/ROADMAP.md`).
