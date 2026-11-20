# Firestore authoritative effects batch

Status: **FIRESTORE EMULATOR GATE PASS; FULL REPOSITORY TEST SUITE PASS LOCALLY; PRODUCTION WORKER BLOCKED BY NON-DURABLE AUTHORITY**

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

1. **Worker factory/deployment is not wired.** `core.runtime.execute()` and `resume_attempt()` now accept an injected `effect_store` and route through Firestore. With `AIOS_REQUIRE_FIRESTORE_EFFECT_STORE=true`, the legacy filesystem path is rejected (no fallback). However, no production worker factory currently constructs/injects the Firestore client using ADC and enables this guard; `core.effect_authority` legacy functions remain available for local/dev and other direct callers.
2. **No production worker wiring.** No Cloud Run entrypoint, workload identity adapter, service account, or deployment manifest was added.
3. **No retry path.** Firestore retry is intentionally absent until independent asymmetric retry issuance and durable authenticated NOT_APPLIED reconciliation are integrated. The current production HMAC retry path remains blocked.
4. **No Firestore SDK dependency/build lock/OCI image** is declared in this branch.
5. **Emulator evidence is limited to the tested state transitions.** GitHub Actions run #44706519557 completed successfully; official Firestore SDK integration tests reported 3 passed, covering restart/same-attempt recovery, UNKNOWN blocking a new attempt, and concurrent dispatch CAS. This does not establish live GCP IAM, ADC/workload identity, database configuration, or Cloud Run behavior.
6. **No GCP resources were created or changed.** No Firestore API/database, IAM binding, Cloud Run Job, secret, or image was provisioned.

## Required gates before Cloud Run

- Add the production worker factory that constructs Firestore client with ADC, injects `FirestoreEffectStore`, and sets `AIOS_REQUIRE_FIRESTORE_EFFECT_STORE=true`; ensure all production entrypoints go through the guarded runtime API and no direct filesystem authority calls remain.
- Add pinned `google-cloud-firestore` dependency, reproducible non-root OCI build and Cloud Run Job entrypoint using ADC/workload identity.
- Run repository unit tests and Firestore Emulator tests with concurrent CAS, transaction retry, crash/restart and receipt replay.
- Verify provider idempotency-key lookup/reconciliation and signed receipts with a real non-production provider test double or sandbox.
- Verify IAM least privilege, database location/edition, backup/restore and operational recovery in non-production GCP.
- Keep retry blocked until independent Ed25519 issuer and signed NOT_APPLIED reconciliation are complete.
- Obtain explicit approval for database ID, location, edition, backup/retention and spend before provisioning any billable database.

**Decision:** code path is present for review, but the existing AIOS default path has not yet been replaced. Do not merge, deploy or promote based on this branch alone.


## Independent repository test audit — 2026-11-20

- A clean clone of the PR head was tested outside GitHub Actions in a separate Linux environment.
- Initial full-suite execution exposed 8 failures in `tests/test_firestore_effect_store.py`: the fixture omitted the now-required `max_attempts` field, and the idempotency-key assertion encoded a literal backslash-zero instead of the NUL separator used by the implementation.
- Both test defects were corrected. The complete local suite then reported **851 passed, 19 skipped, 1 warning**.
- The Firestore Emulator integration gate separately reported **3 passed** in workflow run #44706519557.
- The workflow now runs the complete repository test suite with the emulator active, not only the three emulator-specific tests. That new CI execution remains pending; local success is not represented as a GitHub Actions result.

The authority backend, Ed25519 issuer/trust-anchor integration, reproducible OCI build, ADC validation against GCP, and Cloud Run execution remain unimplemented or unverified. Keep the worker deployment blocked.
