# AIOS Permit Lifecycle / Revocation Contract v1

Status: NORMATIVE DESIGN CONTRACT

This document defines the lifecycle semantics of AIOS execution permits. It does not implement revocation and does not create a second authority plane.

## 1. Purpose

A permit proves that an authority decision was issued for a specific immutable contract, task, actor, capability set, effect set, budget, and policy. Cryptographic validity alone does not prove that the permit remains currently authorized.

AIOS therefore distinguishes:

- **integrity** — the permit is authentic and its immutable contents have not changed;
- **authorization status** — the permit is currently usable for a new governed effect attempt.

A valid permit MAY be revoked without becoming cryptographically invalid.

## 2. Ownership

| Concern | Owner | Rule |
|---|---|---|
| Permit issuance | AIOS authority boundary / authorized issuer | creates an immutable permit |
| Revocation decision | authority issuer / governing authority | decides whether an issued permit remains authorized |
| Revocation source of truth | AIOS Core authority state | durable, auditable current status |
| Authorization enforcement | AIOS Core | every consequential authorization MUST consult current status |
| Gateway enforcement | external-effect boundary | consumes AIOS authorization; MUST NOT create a second revocation authority |
| Contract epoch | AIOS contract authority | optional coarse-grained invalidation, not a substitute for per-permit revocation |

External authority may request or cause revocation, but the enforcement boundary remains AIOS Core.

## 3. Immutable permit identity

A permit is content-bound and immutable once persisted.

`permit_id` remains stable for the lifetime of the permit.

Revocation MUST NOT mutate the permit artifact itself. Revocation is a separate lifecycle record keyed by `permit_id`.

Therefore:

`permit artifact != permit lifecycle state`

A verifier MUST be able to distinguish an unchanged permit from its current authorization status.

## 4. Lifecycle states

The normative lifecycle is:

`ISSUED -> ACTIVE -> REVOKED`

Optional terminal state:

`ISSUED -> EXPIRED`
`ACTIVE -> EXPIRED`

Rules:

1. A newly persisted permit becomes `ACTIVE` only after successful authority validation.
2. `REVOKED` is terminal.
3. `EXPIRED` is terminal.
4. `REVOKED` and `EXPIRED` permits MUST NOT authorize a new effect attempt.
5. Revocation MUST NOT be represented by deleting the permit artifact.
6. Re-activation of a revoked or expired permit is forbidden. A new permit MUST be issued.

Until expiry semantics are implemented, `EXPIRED` is reserved and MUST NOT be inferred from timestamps that are not part of the authoritative contract.

## 5. Revocation record

The revocation state SHOULD be represented independently from the immutable permit artifact and MUST contain at least:

- `permit_id`
- `status`
- `revoked_at` when status is `REVOKED`
- `revoked_by` / authority identity
- `reason_code`
- `record_version` or monotonic lifecycle sequence
- provenance/evidence reference for the authority decision

The exact storage mechanism is an implementation detail, but updates MUST be atomic and durable.

## 6. Authorization rule

`authorize(contract_id, permit_id)` MUST establish all of the following before authorizing a new consequential effect:

1. canonical contract exists and is valid;
2. canonical permit exists and is valid;
3. permit is bound to the canonical contract;
4. capability/effect/policy constraints remain valid;
5. permit lifecycle status is `ACTIVE`;
6. if a contract epoch is used, the permit's epoch remains current;
7. the authorization decision is auditable.

A missing, malformed, contradictory, or unknown lifecycle record MUST fail closed.

## 7. Revocation timing

Revocation applies to **new authorization decisions** after the revocation becomes authoritative.

An already dispatched attempt is not retroactively transformed into `REVOKED` merely because its permit is later revoked. Its receipt MUST still be reconciled against the effect/attempt bindings and current governance rules.

A retry is a new authorization decision and therefore MUST re-check permit lifecycle status. A revoked permit MUST NOT cross the dispatch boundary for a retry.

## 8. Concurrency / race rule

The authority check and creation of a newly authorized dispatch decision MUST use a consistent lifecycle observation.

If revocation races with authorization, the implementation MUST provide a deterministic ordering point. It MUST NOT report authorization as successful after observing a committed revocation.

The implementation MAY use a transaction, monotonic authority sequence, or equivalent serialization mechanism.

## 9. Contract epoch

A contract epoch MAY be included as an additional invalidation mechanism:

`contract_id + authority_epoch`

An epoch change invalidates permits bound to prior epochs.

Epoch semantics are coarse-grained and MUST NOT be used to model selective per-permit revocation. If both mechanisms exist:

`permit_active AND permit_epoch == current_epoch`

are required for authorization.

Changing the immutable contract content still creates a new `contract_id`; epoch is therefore an authority-lifecycle primitive, not a replacement for contract identity.

## 10. Attestation interaction

Attestation proves the binding of the contract, permit, and issuer. It does not by itself prove that the permit is currently active.

Therefore:

`verify_attestation() == cryptographic/binding validity`

and

`authorize() == current authorization validity`

A revoked permit MUST fail authorization even if its attestation remains cryptographically valid.

## 11. Gateway interaction

The Gateway adapter MUST:

- receive an AIOS-authorized permit;
- preserve the authoritative `permit_id`;
- reject missing or inconsistent authority bindings;
- never mint, revoke, reactivate, or reinterpret permits;
- rely on AIOS Core for current authority status.

Gateway receipt/attempt state is independent from permit lifecycle state.

## 12. Audit requirements

Every lifecycle transition MUST be auditable with:

`permit_id -> previous_status -> new_status -> authority -> reason -> evidence/provenance -> lifecycle_sequence`

The audit record MUST be durable and must not overwrite the historical transition.

## 13. Failure semantics

The following conditions MUST fail closed for consequential authorization:

- unknown permit;
- malformed lifecycle record;
- missing lifecycle record when lifecycle enforcement is enabled;
- `REVOKED` permit;
- `EXPIRED` permit;
- lifecycle record contradicts authoritative permit identity;
- stale lifecycle sequence;
- stale contract epoch;
- unverifiable revocation authority/provenance.

These conditions MUST NOT be converted into successful authorization or silently downgraded to a workload-level `UNKNOWN`.

## 14. Non-goals

This contract does not define:

- a universal external identity system;
- a distributed consensus protocol;
- provider-specific gateway revocation;
- retroactive cancellation of already executed physical effects;
- automatic expiry until expiry fields and clock semantics are explicitly specified.

## 15. Required future implementation proof

Before declaring permit revocation implemented, AIOS MUST have tests demonstrating at least:

1. active permit authorizes;
2. revoked permit is rejected;
3. revoked permit cannot retry/redispatch;
4. valid attestation cannot bypass revocation;
5. revocation survives process restart;
6. revocation record cannot be silently replaced by an older state;
7. selective revocation of permit A does not revoke permit B;
8. contract-wide epoch invalidation rejects prior-epoch permits if epochs are implemented;
9. in-flight attempt semantics remain distinct from new authorization;
10. Gateway crossing cannot create or bypass lifecycle state.
