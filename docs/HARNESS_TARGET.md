# AIOS Pro Harness Target Contract

Status: **implementation target**

The common harness is an AIOS execution primitive, not a separate agent. Workloads such as research, coding, reverse engineering, Android/device work, and RX50 engineering plug into the same contract as capabilities.

## Canonical lifecycle

`OBSERVE -> DECIDE/PLAN -> AUTHORIZE -> ACT -> VERIFY -> RECONCILE -> PERSIST -> RESUME`

`AUTHORIZE` is explicit even though the compact reference loop often writes `ACT` directly: no external effect may execute without the control-plane authorization boundary.

## Authority split

### Control plane owns

- contract and policy identity;
- capability authority and permissions;
- execution budget and retry budget;
- evidence requirements;
- verification rules;
- contradiction handling;
- PASS/BLOCKED/INCONCLUSIVE terminal gate;
- promotion/version gate;
- durable authoritative state.

### Workload agent owns

- observations;
- candidate plans/decisions;
- capability requests;
- interpretation of tool results;
- proposed recovery actions.

The agent cannot mutate the first list.

## Durable execution state

Every run must have a stable identity and explicit state fields:

```text
execution_id
contract_id + contract_version
policy_digest
capability_id + capability_version
runtime/provider identity
step_id
attempt_id
phase
budget_remaining
retry_budget_remaining
pending_effect_id (nullable)
last_checkpoint_id
observation_ref(s)
decision_ref(s)
action_ref(s)
verification_ref(s)
evidence_ref(s)
contradiction_ref(s)
recovery/resume metadata
terminal_status (nullable)
```

The authoritative store is not conversation history.

## External effect protocol

A side effect is a transaction-like boundary:

`PREPARE -> AUTHORIZE -> DISPATCH -> ACK/UNKNOWN -> RECONCILE -> VERIFIED/FAILED`

Rules:

1. Allocate an immutable `effect_id` before dispatch.
2. Persist the prepared effect before the external call.
3. Dispatch with an `attempt_id` and idempotency key when supported.
4. Persist ACK or UNKNOWN immediately after return/timeout.
5. On resume, reconcile UNKNOWN before issuing a new side effect.
6. Only verification can move the effect to VERIFIED.
7. An unknown external effect is never silently treated as failed or successful.

## Checkpoint semantics

Checkpoint after every meaningful state transition, not only at terminal completion.

A restart must:

- load the last valid checkpoint;
- validate the policy digest and capability version;
- preserve consumed budget;
- preserve terminal/recovery state;
- reconcile pending effects;
- continue from the recorded phase.

If the persisted state is invalid or policy identity differs, fail closed to `BLOCKED`.

## Verification and evaluation semantics

Final outcome is necessary but not sufficient for critical effects. AIOS evaluates the trajectory where required:

```text
observation -> decision -> authorization -> action -> external effect -> verification -> terminal outcome
```

A verifier may require:

- structured evidence references;
- deterministic state assertions;
- step-level checks for critical transitions;
- effect provenance and provider response identity;
- contradiction checks;
- fault-injection coverage.

Outcome-only model judges are advisory for non-critical interpretation. They are never the sole authority for safety-critical state transitions or promotion.

## Tool/capability schema semantics

Capability contracts must encode machine-checkable constraints wherever enforcement depends on them:

- input types and allowed values;
- preconditions;
- required permissions;
- effect declarations;
- output schema;
- explicit failure/unknown states;
- evidence produced;
- verification strategy.

Prose can explain a constraint but cannot silently substitute for an executable precondition.

## Long-horizon state semantics

Deep action chains must preserve authoritative state independently of model context. Conformance testing must distinguish:

- task interpretation failure;
- decision/planning failure;
- state-carrying failure;
- tool/provider failure;
- verification failure;
- persistence/recovery failure.

Per-step success does not imply end-to-end correctness; state propagation and effect reconciliation are explicit test targets.

## Experience and memory semantics

AIOS separates three layers:

1. **Trajectory/state** — what happened in a particular execution.
2. **Reflection/derived knowledge** — summaries or abstractions derived from trajectories.
3. **Experience** — reusable task/capability/action patterns bound to evidence and verification.

Memory retrieval can influence planning but does not become authoritative evidence merely because it was retrieved. Experience promotion requires external evidence, verification, and the control-plane promotion gate.

Memory consolidation, pruning, and retrieval policy are themselves bounded capabilities; they cannot rewrite governing policy or terminal criteria.

## Harness evolution semantics

Harness changes are controlled experiments, not unconstrained self-modification.

Each candidate evolution records:

```text
change_id
parent_harness_version
changed_component(s)
predicted_effect
experiment_contract
evaluation_dataset/version
observed_result
evidence_refs
verification_refs
promotion_decision
```

A change may be promoted only by an external evaluation/promotion gate. The evolving harness cannot alter the governing policy, evidence requirements, promotion criteria, budgets, or terminal conditions that judge it.

## Terminal semantics

Exactly three terminal states exist:

- `PASS`: acceptance criteria and required evidence are satisfied.
- `BLOCKED`: policy, authorization, contradiction, invalid state, or unrecoverable execution condition prevents completion.
- `INCONCLUSIVE`: the bounded budget ended without enough evidence for PASS and without a governed BLOCKED decision.

The agent never chooses a terminal state directly.

## Evidence semantics

Evidence is structured and provenance-bearing:

```text
source
captured_at
producer
artifact_ref
claim
verification_level
hash/digest when applicable
```

A summary can point to evidence but cannot replace it.

## Runtime/provider contract

The runtime adapter is replaceable. It may provide:

- scheduling;
- process/container execution;
- checkpoint storage implementation;
- retries/timers;
- streaming;
- model/provider calls;
- sandboxing;
- transport.

It may not provide AIOS authority, promotion, terminal criteria, or evidence truth.

## Capability contract

A capability declares:

- stable identity + version;
- inputs/outputs;
- required permissions;
- environment/context requirements;
- side effects;
- evidence it can produce;
- verification strategy;
- known limits/failure modes;
- provenance/source.

A capability version becomes trusted only through external evidence and promotion gates.

## Required conformance tests

A runtime/capability adapter is not conformant until it passes fault-injection tests for:

1. crash before authorization;
2. crash after authorization but before dispatch;
3. timeout after dispatch (UNKNOWN effect);
4. duplicate resume;
5. stale policy digest;
6. stale capability version;
7. budget exhaustion;
8. invalid terminal proposal;
9. missing evidence;
10. contradictory evidence;
11. corrupted checkpoint;
12. provider/runtime replacement with preserved AIOS state;
13. deep dependent action-chain state corruption;
14. silent API/tool failure;
15. untrusted tool-output prompt injection;
16. trajectory fault that leaves the final user-visible outcome apparently correct;
17. harness evolution whose predicted improvement is not reproduced;
18. memory retrieval that conflicts with authoritative evidence.

The test suite must assert both the final status and the persisted state/evidence trail.
