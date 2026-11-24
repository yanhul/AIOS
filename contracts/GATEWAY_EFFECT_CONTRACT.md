# AIOS ↔ Harness Gateway Effect Contract v4

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

`attempt_fence` is a gateway-issued, per-effect monotonic fence attached to exactly one `attempt_id`. A receipt MUST carry the exact fence issued for that attempt. AIOS MUST reject a receipt when the fence is missing, non-integer, negative, or different from the fence bound to the dispatched effect. The adapter does not allocate or advance the fence.

## Target semantics

`target_sha` identifies the exact worker revision selected by the gateway for the attempt. It is mandatory at the receipt boundary and MUST be present on the dispatched effect before execution. A receipt MUST carry the exact same `target_sha`; AIOS MUST reject a missing or mismatched target rather than treating it as execution `UNKNOWN`.

## Receipt rule

A receipt MUST bind at least `effect_id`, `attempt_id`, `attempt_fence`, `target_sha`, `evidence_ref`, `lineage_ref`, and `idempotency_key`. `UNKNOWN` is not success and MUST remain unresolved until an explicit governed reconciliation occurs.

## Protocol v4 execution boundary

AIOS sends the validated effect contract to Gateway protocol v4. Gateway owns
its durable ticket, authorization, BEGIN_EFFECT replay fence, attempt ID and
monotonic fence. The AIOS adapter maps the returned Gateway attempt into the
already-persisted AIOS effect before provider execution is allowed. A replayed
or non-executable Gateway response MUST NOT create a new AIOS dispatch.

AIOS persists the complete Gateway binding atomically with its DISPATCHED
transition: Gateway attempt ID, fence, target SHA, evidence reference, lineage
reference and idempotency key. A partial binding is invalid. Provider receipts
must match the AIOS attempt and all persisted Gateway fields; Gateway receipts
must match the ticket and exact Gateway attempt/fence.

Gateway receipt persistence precedes AIOS reconciliation. UNKNOWN remains
unresolved. A late terminal receipt may reconcile the same Gateway attempt only
when the provider observation is authenticated by the configured provider
trust anchor and bound to the exact AIOS effect/attempt. A terminal Gateway
receipt without authenticated AIOS observation remains pending; it is not
promoted to OBSERVED_SUCCESS/OBSERVED_FAILURE.

AIOS direct retry is blocked for Gateway-backed UNKNOWN effects. A retry must
first be authorized and issued by Gateway, then be mapped to a new AIOS attempt
through a dedicated Gateway retry protocol. Until that protocol is implemented,
Gateway-backed UNKNOWN is intentionally non-retryable through this adapter.

## Canonical flow

`AIOS Workload Contract → Capability Resolve → AIOS Authority/Permit → Gateway Effect Adapter → Human/Boundary Authorization → Attempt(+attempt_fence,target_sha) → Worker → Receipt → AIOS Reconcile`
