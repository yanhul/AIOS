# Firestore adapter implementation status

Status: **CODE ADDED — NOT EXECUTED / NOT CLOUD-VERIFIED**

Branch: `integration/firestore-execution-ledger-v1`
Parent integration contract: PR #143, `integration/cloud-runtime-fail-closed-batch`

## Implemented in this branch

- `core/firestore_runtime.py` implements the existing `DurableRuntime` surface for Firestore.
- `submit()` validates the exact AIOS `DISPATCHED` effect and deterministic attempt ID, then transactionally persists effect identity, attempt identity, provider idempotency key, and a deterministic dispatch event.
- Repeating the same effect/attempt is idempotent. Conflicting identity, mismatched project, malformed lineage, or an unconfirmed Firestore transaction fails closed.
- `resume()` requires exact effect/attempt readback and does not call a provider.
- `retry()` is intentionally blocked. The current runtime interface does not carry a durable prior-attempt UNKNOWN transition plus an authenticated NOT_APPLIED reconciliation proof into the Firestore ledger. Allowing a new attempt here would weaken the retry boundary.
- `tests/test_firestore_runtime.py` adds deterministic in-memory tests for idempotent submit, identity conflict, resume binding, retry block, and invalid dispatch input.

## Important limitations — do not interpret this as a production adapter

1. **Not wired to a deployed worker.** The existing `core/runtime.py` calls `DurableRuntime.submit/resume/retry`, but no Cloud Run entrypoint or runtime factory constructs this adapter.
2. **Local state remains authoritative to current AIOS code.** `effect_authority.py` still commits effect transitions to the local filesystem before `DurableRuntime.submit()`. A Firestore write failure prevents provider execution, but the local DISPATCHED record is not recoverable as the sole source of truth after a replaceable Cloud Run worker disappears.
3. **Receipt lifecycle is not integrated.** This adapter does not persist/verify provider receipt envelopes, terminal observations, or restart reconciliation outcomes.
4. **Retry remains disabled.** No new attempt can be admitted through this adapter until durable UNKNOWN and signed NOT_APPLIED proof are integrated and independently verified.
5. **No Firestore SDK dependency is declared.** The production constructor requires `google-cloud-firestore`; the repository currently has no dependency lock/build manifest. Dependency pinning and reproducible OCI packaging remain separate blockers.
6. **No tests have been run by this change.** The new tests use an in-memory transaction double; they are not Firestore emulator tests and are not proof of real Firestore transaction behavior.
7. **No GCP resource has been created or modified.** No Firestore API/database/IAM/service account/Cloud Run Job/image/secret was provisioned by this branch.

## Required next closure batch

- Refactor effect persistence behind a ledger port so Firestore is the durable source of truth before provider invocation; retain filesystem storage only for local development/tests.
- Extend the port with durable UNKNOWN, verified receipt persistence, terminal CAS, and same-attempt reconciliation.
- Bind authenticated Cloud Run workload identity and immutable environment/attempt/trajectory lineage.
- Add pinned dependency/build manifests and a non-root OCI Job entrypoint.
- Run unit tests, Firestore emulator contention/crash tests, then non-production GCP IAM and restart/recovery tests.
- Implement and verify the independent asymmetric retry issuer before enabling retry.
- Only after these gates, request approval for exact Firestore database ID, location, edition, backup/retention and spend, then provision staging.

**Decision:** this branch is a first code increment behind a draft PR. It is not a completed authority + execution-substrate integration, and it must not be deployed or promoted.
