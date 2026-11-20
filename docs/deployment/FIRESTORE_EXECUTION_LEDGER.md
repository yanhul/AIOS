# Firestore execution ledger contract

Status: **SELECTED DESIGN — NOT PROVISIONED / NOT IMPLEMENTED**

Owner decision: use Google Cloud Firestore in project `aios-cloud-runtime-381714` as the durable execution ledger for the Cloud Run substrate. Target region is `asia-southeast1`, subject to a read-only location/API/edition check before database creation. This approval does not authorize creating a billable database or claiming that the existing Git-based authority store has become operational.

## Responsibility split

- **AIOS** remains the policy/authority control plane: validates contract and permit, creates the logical effect, verifies substrate lineage, verifies provider receipts, and authorizes or blocks retries.
- **Firestore** is the transactional execution ledger: persists effect/attempt state, dispatch intent, provider idempotency keys, signed receipt envelopes, and reconciliation observations. It is not an issuer, reviewer, trust anchor, or independent authority store.
- **Authority issuer/store** remains a separate trust domain. Its issuer and reviewer keys are not stored in Firestore documents. Its read-only consumer boundary and signed issuance/readback must be implemented and independently verified before production promotion.
- **Cloud Run Jobs** are replaceable workers. Local container files are scratch only; no correctness-critical state may depend on them.
- **Provider** owns the external side effect. Firestore cannot atomically commit a transaction with a provider API.

## Non-negotiable distributed-systems rule

There is no cross-system transaction spanning Firestore and a provider API. Therefore this design does **not** claim exactly-once side effects.

Every provider operation must use a stable idempotency key derived from the immutable effect ID and attempt ID, and the provider must support idempotent submission and lookup/reconciliation by that key. The key is persisted before the provider call. If the provider lacks both capabilities, an ambiguous dispatch cannot be retried automatically: preserve `UNKNOWN` and require a separately authorized/manual reconciliation decision. Never infer “not executed” from a missing receipt.

## State model

The authoritative effect states remain compatible with AIOS semantics:

- `PLANNED`: authorized effect exists; no dispatch intent has been committed.
- `DISPATCHED`: durable dispatch intent and attempt identity were committed before invoking the provider. This does not prove the provider completed the operation.
- `UNKNOWN`: dispatch may have reached the provider, but a verified outcome is not available. No new attempt may be started automatically.
- `OBSERVED_SUCCESS` / `OBSERVED_FAILURE`: reached only after verifying a provider receipt bound to effect, attempt, provider, operation/idempotency key, outcome, observation digest and execution-lineage digest.

Transitions are compare-and-swap operations using an incrementing revision. Terminal states are immutable. An UNKNOWN effect may move to a terminal observed state only through reconciliation of the **same** attempt, or through a separately approved asymmetric retry authorization that creates a **new** attempt. A missing/invalid receipt never moves an effect to success.

## Firestore data layout

Use a dedicated Firestore database, not the default database shared with unrelated applications. Exact database ID and location are deployment configuration and must be reviewed before creation.

### `effects/{effect_id}`

One document per logical external effect:

- immutable identity: `effect_id`, `contract_id`, `permit_id`, `actor`, `effect_type`, `provider`, `policy_digest`, `max_attempts`
- state: `state`, `current_attempt_id`, `attempt_number`, `revision`
- bound context: `execution_lineage`, `lineage_digest`
- timestamps: server-generated `created_at`, `updated_at`
- terminal pointer: `verified_receipt_id` (only when terminal receipt verification succeeds)

Client-supplied timestamps are informational only; server timestamps govern ledger ordering. Do not store provider credentials, private keys, reviewer secrets, or raw sensitive payloads in this document.

### `effects/{effect_id}/attempts/{attempt_id}`

One immutable identity document per attempt, plus monotonic lifecycle fields:

- `attempt_id`, `attempt_number`, `provider`, `provider_revision`
- `dispatch_idempotency_key` and provider operation lookup key
- `state`: `PREPARED`, `DISPATCHED`, `UNKNOWN`, `OBSERVED_SUCCESS`, `OBSERVED_FAILURE`
- exact contract/permit/effect and lineage digests
- `dispatch_committed_at`, `provider_acknowledged_at` (if returned), `receipt_persisted_at`
- receipt reference/digest and provider operation ID, never unsigned caller claims promoted to evidence

Attempt identity and idempotency key cannot be edited after creation. A retry is a new attempt document, not mutation/reuse of a prior attempt.

### `effects/{effect_id}/events/{event_id}`

Append-only application audit events with deterministic event ID, event type, prior/new revision, actor principal, attempt ID, payload digest, and server timestamp. Deny update/delete to worker identities. Firestore IAM is not WORM storage; export/backup and independent signed authority receipts are required for stronger retention/tamper evidence.

### `reconciliation/{effect_id__attempt_id}`

A durable reconciliation work record keyed by effect and attempt, with lease owner/expiry, provider lookup result digest, last checked time, and outcome. Leases are advisory and acquired transactionally. Lease expiry does not authorize a second provider submission.

## Required transaction protocol

1. **Create effect:** validate AIOS contract and permit first. In a Firestore transaction, create the effect only if absent; identical replay is idempotent, conflicting content blocks.
2. **Prepare attempt:** validate current effect revision/state and lineage. Create the attempt with a deterministic attempt ID and stable provider idempotency key. CAS the effect revision.
3. **Commit dispatch intent:** in one Firestore transaction, persist `DISPATCHED`, attempt ID, idempotency key and audit event before calling the provider. If transaction outcome is uncertain, read back by deterministic IDs; do not call provider until the committed record is confirmed.
4. **Invoke provider:** send the exact persisted idempotency key. The worker must not invent a new key after timeout/restart.
5. **Persist receipt:** verify the provider's Ed25519 signature and all effect/attempt/provider/operation/outcome/lineage bindings before a Firestore transaction writes the receipt envelope, event and terminal state with CAS. Store the signed envelope and digest; keep private signing keys only in the provider workload's protected secret store.
6. **Crash/restart:** if the worker restarts after dispatch intent without a verified receipt, mark/retain `UNKNOWN` and reconcile using the same provider idempotency key. A positive provider lookup plus valid signed receipt may resolve the same attempt. A negative or inconclusive lookup does not prove absence unless the provider contract explicitly guarantees authoritative negative lookup.
7. **Retry:** only AIOS may validate a separately signed asymmetric retry authorization against a pinned issuer public key, scope, effect, attempt, expiry and replay registry. Firestore transactionally records consumption of the authorization and creates a new attempt. HMAC-only, missing, expired, replayed, revoked, wrong-effect or wrong-attempt authorization fails closed.

## IAM and network boundary

- Use a dedicated user-managed Cloud Run Job service account; no downloaded service-account keys.
- Runtime identity receives only the minimum Firestore data permissions required for the selected API path. Do not grant project Owner/Editor or database administration to the worker.
- Database creation/admin belongs to a separate deployment principal, not the runtime service account.
- Prefer a narrow authenticated ledger API if Firestore's native IAM granularity cannot enforce append-only event/receipt behavior for the worker. Do not rely on application convention alone for a security boundary.
- Restrict ingress/egress; no public unauthenticated worker endpoint.
- Firestore client traffic must use Google-authenticated transport. Caller-supplied actor strings are audit labels, not authentication.
- Keep issuer private keys, reviewer private keys and provider private keys outside Firestore and outside Git/image/build logs.

## Required conformance tests

- Concurrent create of same effect: one canonical record; conflicting payload rejected.
- Concurrent attempt preparation/dispatch: CAS prevents two current attempts for one effect.
- Crash before dispatch transaction: no provider call is possible.
- Crash after dispatch commit but before provider call: restart uses the same idempotency key; no fresh attempt.
- Crash after provider effect but before receipt persistence: reconciliation finds the same provider operation; no duplicate side effect.
- Crash after receipt persistence but before worker acknowledgement: readback returns the same verified terminal receipt; no re-execution.
- Duplicate/reordered/replayed receipt, wrong signature, wrong key ID, wrong provider, wrong effect, wrong attempt, wrong operation ID, wrong lineage digest, expired receipt: reject.
- Missing provider idempotency/lookup support: preserve UNKNOWN and block automatic retry.
- Firestore transaction contention, timeout, unavailable database and ambiguous commit: read back deterministic IDs; fail closed if commit cannot be established.
- Worker identity with no database permission, wrong project/database, or wrong audience: reject.
- Restore/readback drill from backup and independent authority-store verification.

Tests must run against the Firestore emulator for deterministic transaction/failure coverage and against a non-production GCP project for real IAM, regional database, Cloud Run identity and restart behavior. Emulator PASS is not live cloud proof.

## Provisioning and promotion gates

Before creating a database:
1. Read-only verify Firestore API enabled, supported database location, database availability, IAM capabilities and project billing/cost controls.
2. Confirm whether the database is Standard or Enterprise and document required feature/transaction semantics; do not assume an edition.
3. Confirm project-scoped budget configuration and logging/backup costs. The existing owner-supplied VND 100,000 budget was reported as billing-account scoped, not project scoped.
4. Obtain explicit approval for database ID, location, edition, backup/retention and expected spend.

Before staging:
- Implement adapter and emulator tests.
- Implement provider idempotency/lookup contract for each provider.
- Implement asymmetric retry issuer and pinned public-key verification.
- Provision separate deployer, worker and authority issuer identities.
- Prove receipt persistence/readback and all crash points on a non-production deployment.

Production remains **BLOCKED** until independent reviewer attestation, authority-store issuance/readback, live Cloud Run identity verification, Firestore IAM, provider signed receipt, crash/recovery E2E, restore drill and explicit human promotion all have evidence.

## Decision record

Owner approved Firestore as the durable execution ledger on 2026-11-20. This file records the design contract only. It does not assert that Firestore has been enabled, a database has been created, an adapter has been implemented, or any cloud test has passed.
