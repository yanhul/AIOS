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
  from the selected cloud platform's authenticated identity mechanism; bind immutable image
  digest, environment revision, attempt ID and trajectory ID. Never accept caller-provided
  identity strings as authentication.
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
