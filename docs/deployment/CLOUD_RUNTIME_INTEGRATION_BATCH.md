# Cloud runtime integration blocker batch

Status: **ADMITTED — IMPLEMENTATION BLOCKED ON SUBSTRATE CONTRACT**
Base: `2d2545926aae6eefd65a98239e74ea5b605ecde9` (PR #142 head)
Target: a cloud-hosted OCI container runtime with a dedicated workload identity.
This document does not claim that a cloud account, runtime, image registry, or deployment exists.

## Scope and safety boundary

AIOS remains the authority/evidence control plane. The cloud execution substrate owns
container scheduling, immutable image/environment revision, process lifecycle, durable
trajectory identifiers, and restart/reconciliation orchestration. It must not mint AIOS
permits, reviewer trust, provider receipts, or retry approvals.

The runtime must fail closed:
- No authenticated workload identity => no production preflight or dispatch.
- No exact deployed repository/commit/environment/executor binding and valid independent
  reviewer attestation => deployment remains BLOCKED.
- No substrate-supplied immutable lineage for every initial/retry dispatch => no dispatch.
- No authenticated provider receipt persisted and verified after restart => outcome remains
  UNKNOWN; never re-execute an ambiguous dispatched attempt.
- No independent asymmetric retry issuer with pinned public-key verification, expiry and
  replay protection => UNKNOWN retry remains disabled.
- No authority-store authenticated issuance/readback and conformance evidence => no promotion.
- No production secrets, private keys, or reviewer signatures in Git, image layers, build logs,
  CI artifacts, or agent/workload environments.

## Repository facts observed at admission

1. `core/runtime.py` describes AIOS as a thin provider boundary and states that durable
   scheduling, retries, resume, planning and agent loops belong to an external substrate.
2. `scripts/check_production_authority.py` validates deployment-supplied secrets, keyrings,
   reviewer identity and a time-bounded Ed25519 attestation. It does not discover or
   authenticate a cloud workload identity.
3. `docs/PRODUCTION_AUTHORITY_RUNBOOK.md` requires substrate-supplied
   `environment_revision`, `attempt_id`, `trajectory_id` and lineage digest.
4. No Dockerfile, cloud deployment manifest, or production service entrypoint was found
   at the admitted PR #142 head during this audit.
5. PR #142 explicitly blocks production HMAC retry authorization/dispatch pending an
   independently operated asymmetric retry issuer. Its runbook/preflight still requires
   a non-empty active HMAC retry issuer keyring. This mismatch must be resolved without
   weakening the runtime retry block or inserting a synthetic issuer.
6. Existing CI is repository verification only; it is not evidence of a live cloud deployment.
   GitHub Actions usage is not assumed available for production deployment.

## Integration work items

### CR-1 — Substrate contract and identity adapter
- Cause: AIOS expects trusted executor/environment metadata and real lineage but the
  repository has no cloud substrate adapter.
- Reproduction: inspect `core/runtime.py`, the production runbook and preflight; there is
  no production cloud adapter/entrypoint in the audited tree.
- Required implementation: define a narrow adapter contract that obtains workload identity
  from the selected cloud platform's authenticated identity mechanism; bind immutable
  image digest, environment revision, attempt ID and trajectory ID. Never accept caller-
  provided identity strings as authentication.
- Closure: negative tests for absent, malformed, stale, wrong-audience, wrong-subject and
  cross-environment identity; positive test against the platform's real identity token
  verifier; lineage tests for initial and retry dispatch.

### CR-2 — OCI packaging and cloud deployment
- Cause: no image build definition or deployment manifest exists at the admitted head.
- Required implementation: reproducible non-root OCI image, pinned runtime dependencies,
  read-only root filesystem where supported, dropped Linux capabilities, resource limits,
  health/readiness semantics that do not expose secrets, and image digest promotion.
- Closure: clean reproducible build; image vulnerability/SBOM evidence; runtime starts with
  no secrets and stays non-ready; deployment rejects mutable tags and untrusted revisions.
- Do not select a cloud vendor, registry, or billing plan implicitly. Bind these only after
  the owner selects/provisions the actual cloud project and region.

### CR-3 — Authority and trust provisioning
- Cause: deployment-only trust material is not provisioned and no real production
  reviewer attestation exists for a deployed commit/environment.
- Required implementation: secret-manager references and pinned trust roots; reviewer,
  executor and retry issuer are distinct principals; no secret generation in CI.
- Closure: production preflight on the target platform using protected secrets and a
  reviewer signature over the exact deployment tuple; prove secret non-disclosure in logs.

### CR-4 — Retry issuer/preflight consistency
- Cause: production preflight requires an active HMAC retry issuer while production
  retry execution is explicitly blocked for HMAC issuers.
- Required implementation: reconcile the preflight schema with the independent
  asymmetric retry-issuer design; do not enable retries until a separate public-key
  registry, signature verification, expiry and replay protection are implemented.
- Closure: tests show HMAC-only issuer cannot satisfy production readiness; asymmetric
  issuer succeeds only with a pinned key and correct scope; expired, replayed, revoked,
  wrong-effect and wrong-attempt signatures fail closed.

### CR-5 — Durable execution, receipt and restart conformance
- Cause: cloud scheduler/queue and provider receipt persistence are not integrated or
  demonstrated on a real target substrate.
- Required implementation: persist dispatch/attempt before invoking provider; idempotent
  operation identity; persist authenticated receipt atomically with terminal state;
  restart reconciliation never re-executes an ambiguous dispatched operation.
- Closure: crash injection before dispatch, after dispatch/before provider response,
  after provider effect/before receipt, and after receipt/before acknowledgement;
  readback from the real authority store after process restart; duplicate-side-effect
  adversarial test; unresolved ambiguity remains UNKNOWN.

### CR-6 — Promotion and operations
- Cause: no live deployment evidence, alerting, backup/restore or rollback proof.
- Required implementation: staged non-production deployment, observability without
  secrets, bounded resource/egress policy, backup/restore, immutable rollback target,
  explicit human promotion.
- Closure: operational runbook, deployment and rollback drill, authority-store restore
  drill, exact image digest + commit + environment + reviewer attestation evidence.

## Batch acceptance gate

All CR-1 through CR-6 must have reproducible tests and measurable closure evidence.
A documentation-only or CI-only PASS cannot close a live cloud integration gate.
No production deployment, dispatch, retry, capability promotion, or merge is authorized
by this batch record.

## Required owner inputs before platform-specific implementation

- Cloud provider/project and region.
- Container registry and deployment service.
- Identity mechanism and expected issuer/audience/subject claims.
- Authority-store endpoint and authentication mechanism.
- Secret-manager location and authorized operators.
- Network/egress constraints and operational owner.

Until these are provided, the correct state is **BLOCKED — CLOUD SUBSTRATE NOT PROVISIONED**.


## Selected platform: Google Cloud Run

Owner selection recorded:
- Provider: Google Cloud
- Runtime: Cloud Run
- Region: `asia-southeast1` (Singapore)
- Project: not yet created
- Provisioning state: **BLOCKED — no project/billing/IAM evidence**

Platform-specific constraints:
- Use a dedicated user-managed Cloud Run service account as runtime identity; never use a downloaded service-account key.
- Deploy only an immutable Artifact Registry image digest, not a mutable tag.
- Keep the service private by default; grant invocation only to the explicitly authorized caller.
- Store authority/provider secrets in Secret Manager and grant the runtime identity access only to the exact required secrets.
- The deployer needs Cloud Run deployment permissions, Artifact Registry read access, and `iam.serviceAccounts.actAs` on the selected runtime service account. The runtime identity receives only the permissions required by its actual authority-store/provider calls.
- Cloud Run workload identity proves the Google service account principal to Google APIs. AIOS must still verify the platform-issued identity token's signature, issuer, audience, subject and environment binding; caller-supplied identity claims are never authentication.

### GCP preflight — read-only, before project creation

Run these only after installing/authenticating `gcloud`. They inspect the currently authenticated account and visible resources; they do not create a project or enable APIs:

```sh
gcloud auth list
gcloud config list
gcloud projects list
gcloud organizations list
gcloud billing accounts list
```

Required authorization evidence:
- Project creation requires `resourcemanager.projects.create`, commonly via `roles/resourcemanager.projectCreator` on the parent organization/folder. A user-created project normally grants its creator Owner on that project.
- To create the project already linked to a billing account, the creator needs Project Creator plus `roles/billing.user` on that billing account. If linking billing later, the caller needs Billing Account User on the billing account and Project Billing Manager on the project (or equivalent permissions).
- A visible billing account is not proof that it is open, funded, or usable. Confirm its status and payment profile in the Billing console before provisioning.
- If an organization/folder is selected, record its ID and applicable organization policies; do not silently create the project under an unintended parent.

A successful list command is not a complete IAM permission test. Before mutation, record the authenticated principal, selected parent, effective roles/permissions, billing account status, and explicit owner approval for project creation and billing linkage.

### Cost gate

Cloud Run is usage-priced and region-dependent. Google publishes a monthly free tier, but it is calculated using the stated reference region pricing and aggregated across projects on a billing account; it is not a guaranteed zero-cost allowance for this Singapore deployment. Artifact Registry storage, Secret Manager usage, network egress, logging/monitoring, builds and any always-on/minimum instances can also incur charges.

Before provisioning, produce a workload estimate with explicit assumptions for:
- request/job count and duration;
- CPU, memory, concurrency and maximum instances;
- minimum instances (default to zero);
- image/storage size and retention;
- Secret Manager versions/accesses;
- log volume/retention and outbound network traffic;
- build frequency and artifact retention.

Use the official Cloud Run pricing page and Pricing Calculator with `asia-southeast1` selected. Do not publish a monthly cost number until those workload inputs and regional rates are known.

Budget controls:
- Create a project-scoped monthly Cloud Run spend-cap budget if the billing account and service are eligible; configure a separate alerts budget for other billable services.
- A normal alerts-only budget is not a hard spending cap. Even spend caps use estimated costs and enforcement is not instantaneous; they do not guarantee that no overage can occur.
- Keep Cloud Run minimum instances at zero, cap maximum instances, use request-based billing unless the runtime contract proves otherwise, and restrict egress.
- Do not enable unrelated APIs, create GPUs, provision databases, or add paid networking components in this batch without a separately reviewed requirement.

### Provisioning stop conditions

Do not create the project or any billable resource until all are true:
1. Authenticated Google principal and intended parent are identified.
2. Project Creator permission is verified.
3. A valid billing account/payment profile is confirmed, with the required billing-link permissions.
4. The owner approves the project ID/name and billing linkage.
5. A Singapore-region cost estimate and budget/spend-cap plan are reviewed and approved.
6. The repository's CR-1 through CR-6 implementation gates and authority-store integration plan remain intact.

No service account keys, API keys, reviewer private keys or provider secrets may be placed in GitHub, CI variables without protected environment controls, container images or chat.


## GCP provisioning evidence update — 2026-11-20

The owner has since supplied CLI/console evidence for the following state. This section
supersedes the earlier "project not yet created" and "no project/billing/IAM evidence"
statements above; it does not claim a live runtime deployment.

- A dedicated GCP project exists and reports lifecycle `ACTIVE`.
- The project billingInfo reports `billingEnabled: true` and a non-empty billing account name.
- The authenticated project principal reports `roles/owner` on that project.
- The linked billing account reports `open: true`; the principal reports `roles/billing.admin`
  on that billing account.
- The following APIs are enabled: `run.googleapis.com`,
  `artifactregistry.googleapis.com`, and `secretmanager.googleapis.com`.
- An Artifact Registry Docker repository named `aios-runtime` exists in
  `asia-southeast1`, with Google-managed encryption and zero stored image data at the
  time of the supplied listing.
- The owner created a monthly VND 100,000 budget with 50%, 80%, and 100% current-spend
  thresholds. The returned budget has `ownershipScope: BILLING_ACCOUNT`, not a
  project-only scope. Therefore it is not evidence of a project-isolated cost budget;
  project-scoped cost control remains OPEN. The budget is an alerting control, not a
  guaranteed hard spending cap.
- The repository project ID and billing account ID are intentionally not copied into
  this public repository document. They must be supplied to deployment tooling through
  protected configuration, not committed as secrets or treated as trust anchors.

### Current repository/runtime audit

The audited `main` tree has a Python CLI entrypoint (`aios.py` -> `cli/aios.py`).
The CLI supports bounded local `inspect` and `snapshot` commands and describes itself
as standard-library-only. The inspected tree has no HTTP application entrypoint,
Dockerfile, dependency lockfile, or Cloud Run deployment manifest. AIOS state is stored
on the local filesystem under the project state directory. Consequently:
- A Cloud Run Service must not be invented by wrapping the CLI in a guessed HTTP server.
- A Cloud Run Job is not production-safe merely because the CLI can execute: state
  durability, substrate-supplied identity/lineage, authenticated receipts and restart
  reconciliation must first be bound to a real durable authority store and execution
  substrate.
- Do not deploy a container that reports healthy while production authority preflight
  or durable-state requirements are unsatisfied.

### Remaining blockers after GCP foundation provisioning

1. **CR-1 identity/substrate adapter:** no verified Cloud Run identity-token verifier
   and immutable execution-lineage adapter.
2. **CR-2 OCI packaging:** no reproducible image/build contract or deployable application
   entrypoint; no SBOM/vulnerability evidence.
3. **CR-3 trust provisioning:** no protected production trust roots, real independent
   reviewer attestation, or verified Secret Manager references/readback.
4. **CR-4 retry issuer:** production preflight and retry implementation remain inconsistent;
   HMAC retry authority must not be substituted for the required independently operated
   asymmetric issuer.
5. **CR-5 durable state:** local filesystem state is not yet integrated with a durable
   external authority store; crash/restart and duplicate-effect conformance on Cloud Run
   are unproven.
6. **CR-6 operations/promotion:** no live deployment, alerting/rollback drill, or
   authenticated authority-store restore evidence.

**Current decision: GCP FOUNDATION PROVISIONED; AIOS RUNTIME DEPLOYMENT BLOCKED.**
No Cloud Run service/job, container image, service account, production secret, provider
dispatch, retry, or promotion was created by this update.
