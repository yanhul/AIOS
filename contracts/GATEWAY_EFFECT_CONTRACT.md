# AIOS ↔ Harness Gateway Effect Contract v2 (Gateway protocol v4)

This document defines the cross-repository adapter boundary. It does not create a second authority plane.

## Ownership

| Field | Owner | Gateway role |
|---|---|---|
| `effect_id` | AIOS effect producer | bind/persist |
| `action` | AIOS/domain workload contract | validate/bind |
| `capability_ref` | AIOS capability registry | resolve/bind; never mint |
| `authority_ref` | AIOS authority/permit layer | require/bind; never mint |
| `evidence_ref` | AIOS/domain evidence layer | require/bind |
| `lineage_ref` | AIOS/domain lineage layer | require/bind |
| `idempotency_key` | effect producer | bind/persist |
| `attempt_id` | Gateway | allocate uniquely per attempt |
| `attempt_fence` | Gateway attempt boundary | allocate monotonically per effect and bind to the attempt |
| `target_sha` | Gateway ticket/worker boundary | bind exact worker revision |
| receipt status | worker/verifier | Gateway persists; AIOS reconciles |

## Admission rule

An effect may cross the gateway only when:

1. the workload contract is structurally valid;
2. `capability_ref` is versioned and granted by that workload contract;
3. `action` is listed in `allowed_effects`;
4. `authority_ref` is non-empty and was issued by the AIOS authority layer;
5. `evidence_ref`, `lineage_ref`, and `idempotency_key` are present;
6. the gateway's own target, identity, nonce, expiry, fence, and governance checks pass.

The adapter MUST NOT mint permits, capability versions, evidence, lineage, or authority references.

## Attempt-fence semantics

`attempt_fence` is a gateway-issued, per-effect monotonic fence attached to exactly one `attempt_id`. A receipt MUST carry the exact fence issued for that attempt. AIOS MUST reject a receipt when the fence is missing, non-integer, negative, or different from the fence bound to the dispatched effect. The adapter does not allocate or advance the fence. Gateway protocol v4 persists attempt/receipt history, requires the exact gateway-issued attempt_fence on each receipt, and rejects replayed BEGIN_EFFECT from authorizing a second execution.

## Target semantics

`target_sha` identifies the exact worker revision selected by the gateway for the attempt. It is mandatory at the receipt boundary and MUST be present on the dispatched effect before execution. A receipt MUST carry the exact same `target_sha`; AIOS MUST reject a missing or mismatched target rather than treating it as execution `UNKNOWN`.

## Receipt rule

A receipt MUST bind at least `effect_id`, `attempt_id`, `attempt_fence`, `target_sha`, `evidence_ref`, `lineage_ref`, and `idempotency_key`. `UNKNOWN` is not success and MUST remain unresolved until an explicit governed reconciliation occurs.

## Canonical flow

`AIOS Workload Contract → Capability Resolve → AIOS Authority/Permit → Gateway Effect Adapter (protocol v4) → Human/Boundary Authorization → Durable Gateway Attempt(+attempt_fence,target_sha) → Worker → Durable Receipt → AIOS Reconcile`


## Protocol v4 transport and recovery

AIOS uses the Gateway JSONL CLI as a one-request process boundary. Every command may start a fresh process; the Gateway state file is the durable source for ticket, attempt, receipt, and hash-chained event history. A transport timeout or malformed response is an unresolved outcome, not permission to repeat the provider operation. A repeated `BEGIN_EFFECT` returns the original attempt with `replayed=true` and `execute_allowed=false`.

The AIOS adapter accepts receipt statuses explicitly and does not infer `COMPLETED` from a timeout, missing receipt, process restart, or `UNKNOWN`. The pinned cross-repository CI test creates and authorizes an isolated ticket, dispatches once, restarts the CLI between operations, records `UNKNOWN`, and verifies one durable attempt and one unresolved receipt.
