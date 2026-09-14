# Autoresearch Absorption

This document records the research-harness primitives absorbed from Karpathy's autoresearch and nanochat patterns. AIOS does not vendor or copy those repositories.

## Governing rule

The research agent may mutate only an explicitly bounded experiment surface. It must not mutate policy, evidence requirements, evaluation definitions, promotion criteria, terminal conditions, or durable-state authority.

## Canonical loop

`OBSERVE -> DECIDE -> AUTHORIZE -> ACT -> VERIFY -> PERSIST -> RESUME`

For research workloads, the loop is specialized as:

`HYPOTHESIS -> EXPERIMENT -> MEASURE -> COMPARE -> KEEP/REJECT -> PERSIST -> NEXT`

The research loop runs inside the AIOS durable loop rather than replacing it.

## Absorbed primitives

1. **Research program/policy** — human-controlled instructions define the search space, constraints, evaluation protocol, and stopping/promotion rules.
2. **Immutable evaluation boundary** — datasets, evaluators, cost models, and promotion gates are outside the agent mutation surface.
3. **Bounded mutation surface** — the agent receives an explicit list of files/configuration fields it may change.
4. **Fixed experiment budget** — each experiment has an immutable budget so comparisons remain meaningful. The budget is domain-specific; no fixed five-minute value is imposed.
5. **Experiment identity and lineage** — every attempt records experiment/hypothesis identity, parent lineage, code revision, configuration/data identity, and result.
6. **Durable experiment ledger** — success, failure, crash, invalidity, rejection, and promotion are distinct states; failures are evidence, not erased attempts.
7. **Failure -> repair -> retry** — recoverable failures may be repaired within bounded authority. Repair cannot redefine the failure criteria.
8. **Baseline -> delta -> decision** — improvements are measured against a fixed baseline/evaluation contract before promotion.
9. **Research organization** — exploration, experimentation, critique, validation, and promotion are roles/policies, not uncontrolled agent authority.
10. **Minimal reference implementations** — where practical, critical research semantics should have small deterministic references for parity checks.

## Non-goals

- Do not import Karpathy's model-training implementation into AIOS.
- Do not make AIOS a browser agent or workflow engine.
- Do not allow the agent to change governing policy or OOS/promotion criteria.
- Do not treat a single improved metric as proof of trading edge.

## TRY integration contract

TRY supplies the domain-specific hypothesis, strategy, data, and evaluation layers. AIOS supplies authority, durable execution, evidence, lineage, and resume semantics.

The resulting boundary is:

`AIOS policy/authority/runtime/evidence` -> `TRY experiment surface` -> `TRY evaluation` -> `AIOS evidence/decision/persistence`
