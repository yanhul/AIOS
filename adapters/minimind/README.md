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

The external process MUST emit exactly one JSON envelope on stdout:

`{"minimind_receipt": <MiniMind receipt>, "outcome": "OBSERVED_SUCCESS|OBSERVED_FAILURE",
"provider_operation_id": "minimind:<task_id>:<attempt_id>", "authentication": <provider receipt signature>}`

The workload signs with its own `minimind` key (`core.provider_authority.ProviderReceiptSigner`), held
in its own secret store. The AIOS parent never holds that key, never signs, and withholds AIOS keys and
keyrings from the child environment (see `docs/TRUST_ANCHORS.md`). The adapter validates capability,
task binding, artifact lineage, required evidence and operation id. Non-zero exit, timeout, oversized
I/O, malformed JSON, invalid receipts or a missing/invalid signature leave the effect `UNKNOWN`.

Only `PROMOTE` is an observed success. `REJECT`, `INCONCLUSIVE` and `BLOCKED` are recorded as
`OBSERVED_FAILURE` and never read as task success. `PROMOTE` remains a separate AIOS terminal decision
based on the independent locked-holdout evidence; the workload cannot promote itself.
