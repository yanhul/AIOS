# MiniMind governed workload adapter

MiniMind is treated as an external learning substrate. AIOS owns authorization,
policy, evidence requirements, promotion criteria, budgets, and terminal states.

This adapter does not import MiniMind or copy its training implementation into
the AIOS control plane. `runner.py` provides the bounded subprocess bridge used
when a separately installed MiniMind workload runner is available.

## Boundary

`contract -> capability resolve -> permit -> bounded workload -> receipt -> verification -> promotion`

MiniMind may perform model/data/training/rollout work only after AIOS has issued
a permit for the exact workload contract.

The workload MUST report immutable artifact identities (model, tokenizer,
dataset, code revision, environment) and training/evaluation receipts. A reward
score alone is not accepted as promotion evidence.

## Runner protocol

`MiniMindAdapter` sends one JSON object on stdin:

`{"contract": ..., "effect": ..., "attempt_id": ...}`

The external process MUST emit exactly one JSON receipt on stdout matching the
MiniMind receipt contract. The adapter validates capability, task binding,
artifact lineage, and required evidence before converting the result into the
AIOS `ProviderReceipt`. Non-zero exit, timeout, oversized I/O, malformed JSON,
or invalid receipts fail closed.

The provider operation is considered an observed execution success when a
schema-valid workload receipt is returned. `PROMOTE` remains a separate AIOS
terminal decision based on the independent locked-holdout evidence in that
receipt; the workload cannot promote itself by returning `PROMOTE`.
