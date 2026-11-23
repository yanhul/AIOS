# Cloud Run worker integration

Status: **CODE AND CONFIGURATION ADDED — NOT DEPLOYED OR CLOUD-VERIFIED**

This batch adds the production composition root, two authenticated HTTP routes,
a bounded Cloud Tasks outbox publisher, and Terraform for IAM/Scheduler wiring.
It does not create GCP resources.

## Routes

- POST /dispatch — accepts Cloud Tasks delivery only. The app verifies the
  Google-signed OIDC ID token audience and exact task-invoker service-account
  email, then checks the task envelope against Firestore. It reconciles the
  exact persisted attempt and never calls adapter.execute().
- POST /outbox/reconcile — accepts Cloud Scheduler only. It verifies the
  Scheduler service-account identity, scans PENDING/expired-lease outbox
  records, claims each by Firestore transaction, and publishes deterministic
  Cloud Tasks task IDs. Partial failures return 503 so Scheduler retries.

Cloud Run IAM must also require authentication. The application-level token
check distinguishes the two invoker identities because both identities have
service-level roles/run.invoker on the same service.

## Required runtime configuration

The Cloud Run service must set these values explicitly:

- AIOS_REQUIRE_FIRESTORE_EFFECT_STORE=true
- AIOS_REQUIRE_EXECUTION_LINEAGE=true
- AIOS_FIRESTORE_PROJECT_ID
- AIOS_AUTHORITY_TRUST_ANCHOR (JSON Ed25519 public-key trust anchor)
- AIOS_AUTHORITY_ATTESTATION_SECRET_VERSION (explicit numeric Secret Manager
  resource, e.g. projects/PROJECT/secrets/NAME/versions/7; aliases such as
  latest and raw environment secrets are rejected)
- AIOS_RECONCILIATION_ADAPTER_FACTORY
  (trusted module:callable under aios_worker_adapters.*)
- AIOS_CLOUD_TASKS_PROJECT
- AIOS_CLOUD_TASKS_LOCATION
- AIOS_CLOUD_TASKS_QUEUE
- AIOS_CLOUD_TASKS_TARGET_URL (HTTPS service URL ending in /dispatch)
- AIOS_CLOUD_TASKS_INVOKER_EMAIL
- AIOS_SCHEDULER_INVOKER_EMAIL
- AIOS_CLOUD_RUN_SERVICE_URL (base service URI, used as OIDC audience)
- AIOS_OUTBOX_LEASE_SECONDS
- AIOS_OUTBOX_TASK_TTL_SECONDS
- AIOS_OUTBOX_BATCH_LIMIT

The worker runtime service account needs Firestore datastore access, Cloud Tasks
enqueue permission on the existing queue, and Secret Manager access only to the
existing authority-attestation secret. At startup, AIOS reads the explicit numeric
AIOS_AUTHORITY_ATTESTATION_SECRET_VERSION through ADC; it does not accept the HMAC
secret as a raw environment value. Secret version selection/rotation remains an
operator-controlled deployment input. Cloud Tasks and Scheduler use separate
dedicated invoker service accounts. The Terraform module adds service-level
Cloud Run invoker members and the required token-minting/actAs grants.

## Provider reconciliation plugin is still a deployment dependency

The base repository defines
aios_worker_adapters.protocol.ReadOnlyReconciliationAdapter and constrains
the factory import to the aios_worker_adapters package. It intentionally does
not ship a provider-specific implementation.

A deployment must install a reviewed adapter module that:
1. has name equal to the provider selected by the signed capability;
2. implements reconcile(contract, effect, attempt_id);
3. performs read-only provider lookup using the persisted idempotency key or
   provider operation identity;
4. returns a ProviderReceipt only when the provider supplies an authenticated,
   effect/attempt-bound observation; returns None when inconclusive;
5. never implements recovery by calling execute or replaying the operation.

Until that provider-specific module is installed and independently tested,
the worker can start only if its factory is available; a missing factory or
adapter fails closed. The app never substitutes a fake reconciliation result.

## Authority binding

FirestoreEffectStore.create_effect persists the complete immutable
authority_digests bundle supplied to execute_firestore_effect when using
FirestoreAuthorityResolver. A restarted worker resolves contract, permit,
attestation, policy and exact ACTIVE capability records from Firestore,
verifies Ed25519 issuer signatures and cross-bindings, then calls only the
provider adapter's reconcile method. Effects without the complete digest bundle
are rejected by the production reconciler.

## Terraform scope

infra/cloudrun/worker_access.tf:
- owns the complete roles/run.invoker binding on an existing Cloud Run service,
  allowing only the two dedicated invoker service accounts and removing
  allUsers/other unlisted invokers;
- grants roles/datastore.user to the existing worker runtime identity;
- grants roles/cloudtasks.enqueuer on an existing queue;
- grants Secret Manager access to one named existing attestation secret;
- grants token creation to the Google-managed Cloud Tasks/Scheduler service
  agents on their respective invoker service accounts;
- creates a Cloud Scheduler job for POST /outbox/reconcile.

It does not create the Cloud Run service, Cloud Tasks queue, service accounts,
Firestore database, Secret Manager secret, KMS key, or registry image.
Terraform inputs require the project, region, existing service/queue names,
service-account emails, schedule, time zone and existing secret ID. The
deployment owner must review a plan before any apply.

## Verification boundary

CI validates Python tests, Firestore Emulator integration, Docker build and
Terraform formatting/validation. This is not proof of Cloud Run IAM, token
verification against live Google identities, Scheduler delivery, or provider
reconciliation in GCP. No staging/production apply has been run.

## Selected provider: Gemini Developer API (design decision; adapter not implemented)

Gemini Developer API is the selected model provider. For asynchronous work, prefer
its Interactions API with `background=true`: creation returns an interaction ID,
and `GET /v1beta/interactions/{id}` retrieves the interaction status/result.
See the official [background execution guide](https://ai.google.dev/gemini-api/docs/background-execution)
and [getting started guide](https://ai.google.dev/gemini-api/docs/get-started).

This API capability is not, by itself, an exactly-once execution guarantee or a
provider-signed AIOS receipt. Recovery by GET is possible only after the
interaction ID has been durably bound to the exact Firestore attempt. A crash
after Gemini accepts the create request but before that ID is committed leaves
an ambiguous attempt; AIOS must keep it UNKNOWN and must not submit a replacement
request automatically. The current Firestore execution path does not yet persist
an interaction ID before treating the provider operation as recoverable.

Before a Gemini adapter can be enabled, implementation and tests must establish:
1. a Firestore CAS binding of the returned interaction ID to one immutable
   effect/attempt, rejecting conflicting IDs;
2. crash tests at the boundary between Gemini create and Firestore ID commit;
3. read-only GET reconciliation for that persisted ID, mapping only confirmed
   terminal states and retaining UNKNOWN for missing/inaccessible/inconclusive
   results;
4. a trusted receipt-attestation design compatible with AIOS provider receipt
   verification. Gemini's returned interaction object is not to be represented
   as a Gemini-signed Ed25519 receipt;
5. explicit handling of create-request timeouts: no blind resubmission, because
   a client-generated AIOS idempotency key is not evidence that Gemini deduplicates
   create requests.

No Gemini API key is present in this repository, no Gemini request has been
made, and no adapter or production secret has been created by this decision.
