# AIOS Roadmap — Current

## Done / implemented

- Contract identity and immutable execution contract.
- Durable permit authorization and contract/permit binding.
- External-effect identity and durable semantic state.
- Explicit `execute_attempt()` boundary.
- Dedicated UNKNOWN → retry-dispatch transition.
- Contract-bounded retry attempts.
- Provider receipt validation and fail-closed ambiguity handling.
- Thin durable-runtime adapter contract and binding validation.

## Current priority

### 1. Runtime substrate integration

Connect real execution substrates through `RuntimeAdapter` without moving authority into them.

Candidates include durable workflow runtimes, coding agents, browser/computer-use agents and research agents.

### 2. Resume / state handoff

Add the thin resume boundary needed to restore an external runtime execution while preserving AIOS effect/attempt identity and authority checks.

### 3. Provider adapters

Implement minimal adapters for selected substrates. The adapter should translate runtime acknowledgements/receipts into the existing AIOS evidence model rather than introduce another orchestration engine.

### 4. Verification and gates

Continue hardening evidence validation, verification and terminal-condition enforcement. These remain outside agent control.

### 5. Migration / deletion

As external substrates become usable, remove duplicated scheduler, retry, workflow, agent-loop and orchestration code from AIOS rather than accumulating parallel implementations.

## Explicit non-goals

AIOS will not build its own browser agent, computer-use agent, coding-agent workflow engine, generic scheduler, memory platform, skill marketplace or sandbox when a mature external substrate can provide that capability behind the authority boundary.

## Governing rule

The durable loop is:

**Observe → Decide/Plan → Act → Verify → Persist State → Resume**

Agents may iterate inside fixed policy, evidence requirements, promotion criteria, security controls and terminal conditions. Those governing rules remain outside the agent's authority.
