# Firestore authority store (staging primitive)

## Status

This batch adds a create-only, content-addressed Firestore authority artifact
store and an Ed25519 verification boundary. It is a staging primitive, not a
production-ready worker. `create_production_worker()` remains deliberately
blocked until the existing execution path consumes this store end-to-end.

## Trust model

- `AIOS_AUTHORITY_TRUST_ANCHOR` contains the deployment-pinned JSON map of
  `key_id` to `{public_key, principal, revoked}`. The trust anchor itself must
  be provisioned out-of-band and pinned by deployment configuration.
- Authority signatures use Ed25519 and bind the canonical record digest,
  issuer key ID, principal, issue time, and expiry.
- The private issuer key is never loaded by this verifier or stored in
  Firestore. No HMAC fallback exists.
- Revoked, unknown, malformed, expired, or incorrectly bound keys/records
  fail closed.
- Records are stored under their SHA-256 digest and written with Firestore
  create semantics. An identical replay is idempotent; a conflicting write
  is rejected. There is no update method.

## Current boundary / remaining integration

The current Firestore effect executor still calls `core.authority` and reads
contract, permit, attestation, policy, and capability data from the local
AIOS directory. This new store does not silently replace that path. Before a
stateless Cloud Run worker can be enabled, a follow-up integration must:

1. Resolve contract, permit, policy, capability snapshot, and issuer signature
   from Firestore by pinned digest.
2. Validate each artifact's schema and recompute contract/permit/policy and
   capability snapshot identities.
3. Cross-bind contract ID, permit ID, actor, capabilities, allowed effects,
   policy digest, expiry, and revocation state before authorization.
4. Route `execute_firestore_effect` and `resume_firestore_effect` through that
   verified authority context; prohibit filesystem fallback in production.
5. Add emulator tests for these full cross-artifact bindings and worker
   bootstrap, then verify ADC/workload identity in an isolated GCP staging
   project before any production resource is considered.

## Tests

`tests/test_firestore_authority.py` exercises create/read, immutable replay,
record tampering, signature tampering, expiry, revocation, and project binding
with a deterministic in-memory Firestore client double. These tests do not
claim a live Firestore Emulator or GCP staging run.

## M10/M11 follow-on: Firestore evolution ledger

The self-improvement integration adds `core.firestore_evolution_store` beside,
not inside, the immutable authority artifact store. Experience, candidate,
evaluation, CI evidence, decision and event records are kept in separate
Firestore collections. Signed `CAPABILITY_BOOTSTRAP_DECISION`,
`CAPABILITY_PROMOTION_DECISION` and `CAPABILITY` artifacts remain in
`aios_authority_records`; the evolution ledger verifies them through this
store before moving the active capability projection.

`FirestoreAuthorityResolver` can now receive an active-capability lookup. The
Cloud Run composition root supplies `FirestoreEvolutionStore.get_active_capability`
and requires `AIOS_REQUIRE_ACTIVE_CAPABILITY_REGISTRY=true`, so a missing,
unsigned, mismatched or superseded-by-current-pointer capability is denied.
The active pointer is still a mutable Firestore projection. Project-level
`roles/datastore.user` is not collection-scoped, so production must isolate
registry writes from the worker identity using a separate permission boundary
before deployment. No GCP resource or IAM policy was applied by this change.
