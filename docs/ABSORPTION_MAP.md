# AIOS Pattern Absorption Map

Status: IMPLEMENTED as AIOS-owned primitives; source repositories are references, not copied authority layers.

## Core primitives

| Primitive | Absorbed pattern | AIOS boundary |
|---|---|---|
| Immutable experiment lineage | OpenResearch + Nano/Aether | run/worktree/commit/artifact/result/log lineage is integrity-checked |
| Adversarial verification | Predator + agentic-loops | independent verifier; bounded repair/re-verify; no self-approval |
| Durable worker lifecycle | Nano/Aether + Herdr | WORKING/BLOCKED/DONE, monotonic checkpoint, resume token |
| Evidence/provenance | OpenResearch + protocol patterns | immutable digest-backed evidence records; raw evidence remains authoritative |
| Research worker abstraction | HyperResearch + last30days | provider-neutral worker contract; findings return to AIOS reconciliation |

## Worker capabilities

- `deep_research`: structured multi-stage research and evidence vault.
- `recent_signal_discovery`: recent multi-source discovery with persistent findings.
- `background_worker`: resumable long-running worker lifecycle.
- `coding_execution`: bounded execution with exit-code/test evidence and durable handoff.
- `market_universe_discovery`: TRY/tvscreener discovery only; never historical-data authority.

These capabilities are descriptive/registered workers. They do not grant policy, evidence, promotion, budget, or terminal authority.

## Explicit exclusions

- Provider/model-specific authority.
- Model self-approval or self-promotion.
- Benchmark/performance claims without evidence.
- Worker-controlled policy, evidence rules, promotion gates, budgets, or terminal conditions.
- Blind source-tree copying from external repositories.

## Control flow

`worker -> artifact/evidence -> independent verification -> AIOS reconciliation -> fixed gate -> PASS/BLOCKED/INCONCLUSIVE`

The AIOS control plane remains the only authority for governing policy, evidence requirements, promotion criteria, execution budgets, and terminal conditions.
