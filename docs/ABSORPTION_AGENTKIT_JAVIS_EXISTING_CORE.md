# Absorption ledger: AgentKit and Javis OS

Status: **selective ADAPT; no upstream runtime vendoring and no production completion claim.**

This ledger distinguishes upstream facts from architectural decisions. The source repositories are Coinbase AgentKit and Javis OS; AIOS is the destination authority/evidence control plane.

## 1. Coinbase AgentKit — correct source classification

Upstream: https://github.com/coinbase/agentkit

Coinbase AgentKit is a wallet and on-chain action toolkit, not a general-purpose agent orchestration framework. Its Python implementation exposes:
- `ActionProvider` and `Action` abstractions;
- decorator-registered action metadata;
- Pydantic argument schemas;
- wallet-provider injection and network support checks;
- framework extensions for agent integrations.

Relevant files include `python/coinbase-agentkit/coinbase_agentkit/action_providers/action_provider.py` and `action_decorator.py`.

**Accept as design references only:** typed action metadata, explicit argument schemas, provider capability declarations and network/provider compatibility checks. These may inform future capability-adapter contracts.

**Reject for current AIOS scope:** Coinbase wallet implementations, signing, on-chain transaction execution, token/payment actions, wallet credentials and any implication that AgentKit supplied AIOS's orchestrator/delegation design. No AgentKit orchestration engine was identified in the audited source.

Destination: AIOS `core/capabilities.py` / `core/capability_store.py` remain the authority for registered capabilities. This PR does not implement a Coinbase wallet or a new action-provider runtime.

## 2. Javis OS — Nguyễn Minh Quý fork, pinned snapshot audit

**Source identity verified:** https://github.com/minhhoan1007/javis-os  
**Audited fork HEAD:** `8a38217d9f6e9c54e83898fb3242a6fd5c4ca6d5` (2026-09-07).  
**Repository metadata:** description `Nguyễn Minh Quý`; fork of `blogminhquy/javis-os`. This is a fork snapshot, not an independent upstream. Its recorded HEAD is 967 commits behind the upstream main observed on 2026-11-09; do not silently substitute current upstream code for this pinned audit.

### Verified in the pinned source
- `server/task_store.py`: SQLite task queue; WAL, `busy_timeout=5000`, `BEGIN IMMEDIATE`; status-guarded claim; unique per-brain idempotency-key index; task/run/event records.
- `server/tasks.py`: asyncio dispatcher/workers; lease 90 seconds, heartbeat every 20 seconds, dispatcher scan every 5 seconds; bounded worker count; stale-worker housekeeping.
- `TaskStore.reclaim_stale`: expired tasks can be moved back to `ready`; previous run marked `stale`; event recorded.
- `tests/python/test_tasks_autonomous.py`: legacy JSON migration/snapshot, compare-and-set claim, dependency promotion, dispatcher and worker lifecycle tests. The claim test checks a second claim against the same store; it is not a multiprocess race or external-effect crash test.

### Not verified in this pinned fork
No `once_ledger.py`, standalone workflow-run store, or checkpoint subsystem was found in its tracked tree. Do not attribute once-only execution, exactly-once semantics, provider receipt reconciliation or checkpoint recovery to this fork.

### Absorb decision: selective ADAPT, not vendor
- **Useful scheduler patterns:** bounded dispatch, atomic database claim, task/run/event history, heartbeat and dependency promotion. Treat them as queue mechanics only.
- **Do not copy stale reclaim as external-effect retry authority.** The code requeues an expired task. If a worker performed an external action and died before recording completion, a new worker can repeat that action. A queue lease is not an effect fence and does not prove the provider did nothing.
- **Do not equate task idempotency with side-effect idempotency.** The unique key deduplicates enqueue within a brain; title normalization also coalesces active tasks. Neither proves a provider effect happened once.
- **AIOS remains authoritative** for effect/attempt identity, permits, receipts, UNKNOWN and reconciliation. TRY may own scheduling, but any side effect must pass through the AIOS authority/runtime boundary.

## 3. Three-repository decision

The decision set is **Coinbase AgentKit, Javis OS and AIOS**:
- Coinbase AgentKit: typed action-provider interface patterns only; wallet/on-chain implementation rejected for current scope.
- Javis OS: task-store/worker lifecycle patterns only; application runtime not vendored.
- AIOS: destination authority, evidence, verification and promotion control plane.

TRY remains the research/provider-execution consumer. Google AI Pro automation is outside this decision set.

## 4. Existing AIOS implementation evidence

The canonical modules/tests already present include:
- `core/orchestrator.py`, `core/delegation.py`
- `core/durable_loop.py`, `core/durable_loop_crash_recovery` coverage
- `core/durable_wal.py`
- `core/effect_authority.py`
- `core/durable_runtime.py`
- `core/execution_lineage.py`
- `tests/test_orchestrator.py`, `tests/test_delegation.py`, `tests/test_durable_loop.py`, `tests/test_durable_wal.py`, `tests/test_m6_effect_authority.py`, `tests/test_m6_durable_runtime_bridge.py`, `tests/test_execution_lineage.py`

These tests cover AIOS's own governed primitives; they do not prove that upstream AgentKit or Javis OS code was imported or that production TRY adapters are complete.

## 5. Remaining work / status

This PR is an evidence-corrected architecture decision record only. It does not change AIOS runtime code. TRY PR #63 adds a cross-repository fixture test against a pinned AIOS revision using a fake provider/runtime. That test demonstrates boundary identity checks and UNKNOWN handling in the fixture, not live provider behavior, production scheduling, lease recovery or reconciliation.

Production integration still requires a TRY-owned runtime adapter that binds provider submission and receipt to the AIOS `effect_id`, `attempt_id` and provider identity, then persists verifiable receipt/evidence and exercises explicit UNKNOWN reconciliation.
