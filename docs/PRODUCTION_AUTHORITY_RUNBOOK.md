# Production authority activation runbook

This gate is intentionally fail-closed. Repository CI uses synthetic keys only
to test verification logic; it does not provision or claim production trust.

## Required protected deployment secrets / variables

Set these in the production deployment environment (not in the repository):

- `AIOS_REQUIRE_EXECUTION_LINEAGE=true`
- `AIOS_AUTHORITY_ATTESTATION_SECRET`: random secret, at least 32 characters.
- `AIOS_PROVIDER_KEYRING` (when HMAC-based providers are used): JSON object keyed by provider; each active entry
  contains a deployment-only `secret` (at least 32 characters),
  `scopes: ["provider.receipt.sign"]`, and optional `revoked: true`. It may be an empty object when all deployed providers use Ed25519.
- `AIOS_RETRY_ISSUER_ED25519_KEYRING`: JSON object keyed by retry issuer; each active entry contains only `key_id`, 32-byte hex `public_key`, and optional `revoked: true`. The matching private key is held only by the separately protected issuer.
- `AIOS_PROVIDER_ED25519_KEYRING`: verifier-side public key registry. The
  `minimind` entry is mandatory and must contain a valid `key_id` and 32-byte
  hex `public_key`; private keys must remain in the workload secret store.
- `AIOS_DEPLOYMENT_EXECUTOR_ID`: stable identity of the deployment executor.
- `AIOS_DEPLOYMENT_ENVIRONMENT`: exact deployment environment name.
- `AIOS_DEPLOYMENT_REVIEWER_KEYRING`: protected identity registry mapping
  reviewer principal IDs to their Ed25519 public keys and revocation status.
  The registry itself must be pinned by the organization/deployment trust root.
- `AIOS_DEPLOYMENT_REVIEWER_ATTESTATION`: JSON signed by that reviewer.

The deployment platform must also provide `GITHUB_REPOSITORY` and
`GITHUB_SHA` (or equivalent values when invoking the validator outside GitHub).
The reviewer attestation has exactly these fields:

```json
{
  "repository": "yanhul/AIOS",
  "commit": "<exact deployed commit SHA>",
  "environment": "production",
  "executor_id": "<AIOS_DEPLOYMENT_EXECUTOR_ID>",
  "reviewer_id": "<independent reviewer principal>",
  "issued_at": 0,
  "expires_at": 0,
  "signature": "<Ed25519 signature over canonical JSON of all preceding fields>"
}
```

The reviewer principal must differ from the executor and all retry issuers.
The attestation must be valid at verification time and live no longer than 24h.
The public key must be pinned by the deployment trust configuration; do not
accept a public key supplied only inside the attestation itself.

## Execution substrate lineage contract

When the production lineage flag is enabled, every initial dispatch and retry
must pass a lineage record into `runtime.execute(..., lineage=...)` or
`retry_dispatch(..., lineage=...)`. The record must be supplied by the actual
execution substrate, not fabricated by AIOS:

- `policy_revision`: must equal the persisted contract's `policy_digest`.
- `capability_snapshot`: must exactly equal the contract capability list and
  policy digest snapshot.
- `provider_revision`: must match the selected provider's authorized
  capability version (for example capability ref `provider-x@1`).
- `environment_revision`: immutable deployment/image/environment revision.
- `attempt_id`: exact AIOS attempt ID.
- `trajectory_id`: stable ID from the owning runtime/trajectory system.
- `lineage_digest`: digest produced by `ExecutionLineage.as_record()`.

AIOS binds this record to the exact contract ID, permit ID, provider and
attempt. It revalidates the binding on every authoritative effect load and
copies it into the immutable terminal provider receipt. Missing, stale,
tampered, or mismatched lineage blocks production dispatch/receipt verification.

## Retry issuer status

The current HMAC retry issuer is symmetric and must not be treated as an
independent trust domain. While `AIOS_REQUIRE_EXECUTION_LINEAGE=true`,
AIOS deliberately blocks both HMAC authorization issuance and retry dispatch.
Production UNKNOWN retries remain BLOCKED until a separately operated issuer
signs the fully bound authorization with an asymmetric key and AIOS verifies
it using a pinned public-key registry, including expiry and replay protection.
Do not inject retry signing secrets into AIOS, TRY, agents, or subprocesses.

## Preflight

Run in the actual production deployment environment after injecting the
protected values:

```bash
python scripts/check_production_authority.py
```

The command prints only non-secret readiness metadata. It does not print key
material. A successful preflight is necessary but does not prove that a
provider workload actually holds its private signing key; perform a live
provider receipt challenge and verify its persisted receipt before promotion.

Never generate replacement production secrets in CI or commit them to Git.
If a reviewer key or signing secret is unavailable, the correct result is
BLOCKED, not a synthetic PASS.

## Independent Ed25519 retry issuer (integrated verifier protocol)

Production retry approval no longer uses `AIOS_RETRY_ISSUER_KEYRING` or an
in-process HMAC secret. Configure `AIOS_RETRY_ISSUER_ED25519_KEYRING` as a
protected deployment variable containing only public keys:

```json
{
  "issuer:production-approver": {
    "key_id": "ed25519:<first-32-hex-of-sha256-of-raw-public-key>",
    "public_key": "<32-byte-Ed25519-public-key-hex>",
    "revoked": false
  }
}
```

The independent issuer owns the matching private key outside AIOS and signs a
`RETRY_AUTHORIZATION_ED25519` record. The signature covers the authorization
ID, exact effect/contract/permit, actor, provider, full UNKNOWN-state digest,
previous and next attempt IDs, reason, unknown reason, scope, algorithm, key
ID, and validity window. AIOS imports the signed record with
`import_retry_authorization(...)`, validates it against the current persisted
UNKNOWN effect using the pinned public-key registry, then atomically consumes
it with the retry dispatch. Reuse, expiry, stale state, changed provider,
changed attempt, wrong actor, revoked key, or invalid signature fails closed.

The legacy `AIOS_RETRY_ISSUER_KEYRING` is retained only for non-production
test compatibility. It is rejected whenever `AIOS_REQUIRE_EXECUTION_LINEAGE=true`.
The production preflight now requires the Ed25519 public-key registry and at
least one non-revoked issuer distinct from the deployment executor and
reviewer. Do not copy a private key into AIOS or its CI environment.

This software integration does not provision the issuer's private key or the
production public-key trust anchor, and it does not prove a live issuer run.
Production remains BLOCKED until the independently operated issuer workflow,
protected environment approval, public-key pinning, immutable readback, and a
live signed authorization → AIOS import → provider NOT_APPLIED reconciliation
→ single-use retry → persisted receipt → restart verification are evidenced.