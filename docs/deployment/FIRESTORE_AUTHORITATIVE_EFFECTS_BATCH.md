# Firestore authoritative effects batch

Status: **IMPLEMENTED AS AN ISOLATED FIRESTORE-FIRST EXECUTION PATH — NOT YET THE DEFAULT AIOS PATH; TESTS NOT EXECUTED**

Branch: `integration/firestore-authoritative-effects-v1`
Parent: PR #144 head `2429dbc67e8b7e15c817256c90faf658c313ffb0`

## Added

- `core/firestore_effect_store.py`: transactional effect/attempt state, revision CAS, immutable dispatch intent, stable provider idempotency key, durable UNKNOWN, immutable verified receipt, terminal state and event records.
- `core/firestore_execution.py`: Firestore-first execution and recovery entrypoints. Contract/permit authorization and provider receipt verification remain in AIOS. The entrypoint creates and dispatches in Firestore before invoking the provider; recovery calls `adapter.reconcile()` for the exact existing attempt and never calls `adapter.execute()`.
- `tests/test_firestore_effect_store.py`: in-memory transaction tests for effect creation, dispatch commit, crash before provider, crash after provider side effect but before receipt, UNKNOWN blocking a new attempt, terminal receipt commit, stale CAS, receipt-acknowledgement crash and transaction atomicity.

## State machine

```
PLANNED --transactional dispatch intent--> DISPATCHED
DISPATCHED --ambiguous provider result--> UNKNOWN
DISPATCHED or UNKNOWN --AIOS verifies bound provider receipt--> OBSERVED_SUCCESS / OBSERVED_FAILURE
```

No transition from UNKNOWN to a new attempt is implemented. No exactly-once claim is made. Recovery must reconcile the same attempt using the persisted idempotency key; if the provider cannot reliably look up/reconcile that key, the effect remains UNKNOWN.

## Receipt trust boundary

The store accepts a receipt only through `record_verified_receipt()`, which is documented as an internal trusted call after the existing AIOS `_verify_provider_receipt()` verifier succeeds. The Firestore store itself does not verify Ed25519/HMAC signatures and is not an issuer or trust anchor. The Firestore-first orchestrator invokes the existing verifier and mints AIOS evidence before committing the immutable receipt and terminal effect in one transaction.

## Important remaining integration blockers

1. **Existing default path is unchanged.** `core.runtime.execute()` and `core.effect_authority` still use filesystem-backed effect state. This branch adds explicit `execute_firestore_effect()` / `resume_firestore_effect()` entrypoints but does not silently redirect the old API or fall back between stores. Production must select the Firestore path explicitly through a reviewed worker entrypoint/runtime factory.
2. **No production worker wiring.** No Cloud Run entrypoint, workload identity adapter, service account, or deployment manifest was added.
3. **No retry path.** Firestore retry is intentionally absent until independent asymmetric retry issuance and durable authenticated NOT_APPLIED reconciliation are integrated. The current production HMAC retry path remains blocked.
4. **No Firestore SDK dependency/build lock/OCI image** is declared in this branch.
5. **No emulator or live-cloud tests were executed.** Tests use an in-memory transaction double; it is not evidence of Firestore transaction semantics, IAM behavior, or crash durability.
6. **No GCP resources were created or changed.** No Firestore API/database, IAM binding, Cloud Run Job, secret, or image was provisioned.

## Required gates before Cloud Run

- Wire the Firestore-first entrypoints as the only production effect-state path; prevent production use of filesystem-backed `execute()`.
- Add pinned `google-cloud-firestore` dependency, reproducible non-root OCI build and Cloud Run Job entrypoint using ADC/workload identity.
- Run repository unit tests and Firestore Emulator tests with concurrent CAS, transaction retry, crash/restart and receipt replay.
- Verify provider idempotency-key lookup/reconciliation and signed receipts with a real non-production provider test double or sandbox.
- Verify IAM least privilege, database location/edition, backup/restore and operational recovery in non-production GCP.
- Keep retry blocked until independent Ed25519 issuer and signed NOT_APPLIED reconciliation are complete.
- Obtain explicit approval for database ID, location, edition, backup/retention and spend before provisioning any billable database.

**Decision:** code path is present for review, but the existing AIOS default path has not yet been replaced. Do not merge, deploy or promote based on this branch alone.
