# AIOS ↔ Harness Gateway Effect Contract v1

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
| `target_sha` | Gateway ticket/worker boundary | fence exact worker revision |
| receipt status | worker/verifier | Gateway persists; AIOS reconciles |

## Admission rule

An effect may cross the gateway only when:

1. the workload contract is structurally valid;
2. `capability_ref` is versioned and granted by that workload contract;
3. `action` is listed in `allowed_effects`;
4. `authority_ref` is non-empty and was issued by the AIOS authority layer;
5. `evidence_ref`, `lineage_ref`, and `idempotency_key` are present;
6. the gateway's own target, identity, nonce, expiry, and governance checks pass.

The adapter MUST NOT mint permits, capability versions, evidence, lineage, or authority references.

## Receipt rule

A receipt MUST bind at least `effect_id`, `attempt_id`, `target_sha`, `evidence_ref`, and `lineage_ref`. `UNKNOWN` is not success and MUST remain unresolved until an explicit governed reconciliation occurs.

## Canonical flow

`AIOS Workload Contract → Capability Resolve → AIOS Authority/Permit → Gateway Effect Adapter → Human/Boundary Authorization → Attempt → Worker → Receipt → AIOS Reconcile`
