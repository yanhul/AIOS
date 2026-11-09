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

## 2. Javis OS — source identity unresolved; prior attribution withdrawn

**Status: UNKNOWN.** The repository previously cited as `https://github.com/blogminhquy/javis-os` is not the Javis OS source the project owner intended. The earlier source-specific file paths and implementation claims in this section are withdrawn and must not be treated as verified upstream facts.

A GitHub repository search also surfaced `dodungvanphong/javis-os`, but its README identifies itself as a copy pointing back to `blogminhquy/javis-os`; it is not accepted as the intended source. No alternative repository has yet been verified against the original audit.

**Absorb decision: BLOCKED pending source identity.** Do not attribute SQLite task-store, atomic-claim, lease, heartbeat, once-only ledger, checkpoint, MCP or memory patterns to Javis OS until the correct repository and commit are identified and audited.

The AIOS/TRY ownership boundary below remains an independent architectural decision, not evidence derived from Javis OS:
- AIOS owns authority, effect/attempt identity, durable evidence and governed reconciliation.
- TRY owns provider execution and any future worker scheduling/lease implementation.
- An expired or ambiguous external effect remains UNKNOWN; a queue lease expiry alone must never authorize a new attempt.

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
