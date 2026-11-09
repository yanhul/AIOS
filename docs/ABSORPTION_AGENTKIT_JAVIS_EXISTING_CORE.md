# Absorption ledger: AgentKit and Javis OS patterns

Status: **ADAPT into existing AIOS core; do not add a parallel agent runtime.**

This ledger records where the accepted patterns belong in the current AIOS architecture. It is an implementation map, not a claim that upstream code was copied or that production integration is complete.

## 1. AgentKit-style orchestration

| Pattern | Canonical AIOS implementation | Boundary |
|---|---|---|
| Governed execution loop | `core/orchestrator.py`, `core/durable_loop.py` | AIOS controls the loop and re-authorizes on resume |
| Role handoff / delegation | `core/delegation.py` | A delegation is a proposal, not a permit or execution |
| Capability scoping | `core/capabilities.py`, `core/capability_store.py` | Only registered, active capabilities may be delegated |
| Independent verification | `core/verification.py`, `core/evidence.py`, `core/acceptance.py` | Executor review cannot self-certify AIOS PASS |
| Immutable execution context | `core/execution_lineage.py` | Lineage is provenance, never authority |

Accepted: explicit plans/handoffs, scoped capabilities, separate execution and verification roles, artifact/evidence references.

Rejected: treating an agent's own review as independent evidence; allowing orchestration to mint permits, mutate policy, execute arbitrary shell/worktrees, or promote its own result.

Do **not** add a second `core/agent_orchestrator.py` beside the existing orchestrator/delegation modules. The earlier draft implementation in PR #124 was a duplicate boundary prototype and is superseded by this mapping.

## 2. Javis OS-style durable worker lifecycle

| Pattern | Canonical AIOS implementation | Boundary |
|---|---|---|
| Durable state machine / resume | `core/durable_loop.py` | State transitions are bounded and revalidated |
| Crash-safe append-only journal | `core/durable_wal.py` | WAL replay is not an execution receipt |
| External effect authorization | `core/effect_authority.py` | Contract + permit gate every effect transition |
| Runtime adapter contract | `core/durable_runtime.py`, `core/runtime.py` | Runtime acknowledges effect/attempt/provider; AIOS retains authority |
| Attempt provenance | `core/execution_lineage.py` | Immutable policy/provider/environment/attempt lineage |

Accepted: durable transitions, replay, idempotent effect identity, explicit attempts, checkpoint/resume and evidence-bound observations.

Rejected: a second SQLite authority/queue inside AIOS, silent requeue after ambiguous execution, automatic retry of UNKNOWN, unrestricted plugins/shell, plaintext credentials, and claims of exactly-once execution based only on an idempotency key.

Scheduling/worker leases belong to the execution runtime. AIOS validates authority, effect identity, receipt/evidence, verification and promotion. An expired or ambiguous effect must remain UNKNOWN until explicit reconciliation and authorization.

## 3. Verification evidence already present

The following existing tests cover the canonical implementation paths; they are not evidence of a live external provider run:

- `tests/test_orchestrator.py`
- `tests/test_delegation.py`
- `tests/test_durable_loop.py`
- `tests/test_durable_loop_crash_recovery.py`
- `tests/test_durable_wal.py`
- `tests/test_m6_effect_authority.py`
- `tests/test_m6_durable_runtime_bridge.py`
- `tests/test_execution_lineage.py`

The previous PR #124 added a second plan/review data model rather than integrating these canonical modules. Keep it unmerged and use this ledger as the absorption decision.

## 4. Remaining integration gap

The canonical AIOS runtime protocol exists, but each TRY execution adapter still needs an explicit implementation that binds its provider submission and receipt to the AIOS `effect_id`, `attempt_id`, and provider identity. This must be tested against the pinned AIOS revision and the real authority/effect APIs—not a caller-supplied capability list or mocked verifier alone.

## 5. Source inventory limitation

The recoverable audit record names AgentKit and Javis OS as upstream pattern sources and AIOS/TRY as the destination architecture. A third independent upstream repository name/URL is not present in that record; it is intentionally not guessed here. No upstream source is vendored by this change.
