# MiniMind governed workload adapter

MiniMind is treated as an external learning substrate. AIOS owns authorization,
policy, evidence requirements, promotion criteria, budgets, and terminal states.

This adapter is intentionally a boundary description plus validation helpers;
it does not import MiniMind or execute training code inside the AIOS control
plane.

## Boundary

`contract -> capability resolve -> permit -> bounded workload -> receipt -> verification -> promotion`

MiniMind may perform model/data/training/rollout work only after AIOS has issued
a permit for the exact workload contract.

The workload MUST report immutable artifact identities (model, tokenizer,
dataset, code revision, environment) and training/evaluation receipts. A reward
score alone is not accepted as promotion evidence.
