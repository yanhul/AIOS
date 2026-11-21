# M10/M11 Firestore integration and promotion gates

Status: implementation in review; no GCP resources, IAM changes or workflows
have been applied. The GitHub `workflow_run` ingestion trigger becomes active
only after this workflow is present on the repository default branch.

## Authority boundary

- `FirestoreAuthorityStore` remains the create-only, content-addressed store
  for Ed25519-signed authority artifacts. It is not repurposed as a mutable
  application ledger.
- `FirestoreEvolutionStore` persists M10/M11 records and audit events in
  separate append-only collections. A transaction also maintains the latest
  evaluation pointer and the active capability projection.
- The active pointer can be bootstrapped only by a signed
  `CAPABILITY_BOOTSTRAP_DECISION` bound to a signed `CAPABILITY` artifact.
- Promotion requires a signed `CAPABILITY_PROMOTION_DECISION`, a signed ACTIVE
  `CAPABILITY` artifact, the exact candidate and latest PASS evaluation,
  distinct proposer/evaluator/approver identities, successful GitHub CI
  evidence bound to the candidate source commit, and a Firestore CAS against
  the currently active base version.
- The Cloud Run authority resolver checks the active pointer and its signed
  decision. A stale or missing pointer denies capability resolution.
- No code in this batch issues Ed25519 signatures or holds private issuer keys.
  An authorized authority issuer must publish the signed decision and signed
  capability artifacts before bootstrap/promotion can proceed.

## Firestore collections

| Collection | Purpose | Write semantics |
|---|---|---|
| `aios_experiences` | M10 positive and negative experience records | create-only |
| `aios_capability_candidates` | M11 candidate snapshots | create-only |
| `aios_capability_evaluations` | Independent evaluations | create-only |
| `aios_capability_latest_evaluations` | Latest evaluation projection per candidate | transaction CAS/set |
| `aios_ci_evidence` | GitHub Actions run and artifact digests | create-only |
| `aios_capability_decisions` | Promotion/bootstrap decision ledger | create-only |
| `aios_active_capabilities` | Currently active signed capability pointer | transaction CAS/set |
| `aios_evolution_events` | Append-only mutation event identities | create-only |

The active pointer is a mutable projection, not the authority itself. Every
read resolves and verifies the signed capability and the signed decision that
justifies the pointer, including its revision and predecessor digest.

**Production isolation blocker:** the existing worker role `roles/datastore.user`
and the proposed automation role are project-level Firestore grants, not
collection-scoped. A compromised worker identity could write the pointer
collection even though application code never exposes that mutation. Before
production, isolate the evolution registry in a separately permissioned
Firestore database/project or route activation through a separately
permissioned authority service. The Terraform binding in this PR is only a
staging wiring primitive and must not be applied as proof of least privilege.

## CI evidence ingestion

`.github/workflows/ci-evidence-ingestion.yml` runs after a completed
`Firestore Emulator Gate` workflow. It queries GitHub's authenticated API,
requires the pinned workflow path and a completed successful run, requires the
Firestore Emulator job to have succeeded, rejects fork-origin evidence,
verifies the workflow source-file SHA-256 against the reviewed repository
variable, downloads the emulator log artifact without executing it, hashes the
ZIP, and stores a content-addressed CI evidence record. Promotion requires at least one
such record matching both repository and candidate source commit.

The workflow is deliberately separate from the source CI workflow: ingestion
must not claim the overall run succeeded while the run is still in progress.
GitHub's `workflow_run` trigger only runs after this workflow is on the default
branch. Until then, CI evidence ingestion is not operational.

## Manual GitHub variables and IAM prerequisites

Set these repository Actions variables only after the existing GCP staging
project and workload identity federation have been reviewed:

- `AIOS_GCP_WIF_PROVIDER`: full Workload Identity Provider resource name.
- `AIOS_GCP_SERVICE_ACCOUNT`: existing service account impersonated by GitHub.
- `AIOS_FIRESTORE_PROJECT_ID`: exact existing Firestore project ID.
- `AIOS_AUTHORITY_TRUST_ANCHOR`: pinned public Ed25519 trust-anchor JSON.
- `AIOS_FIRESTORE_WORKFLOW_SHA256`: SHA-256 of the reviewed
  `.github/workflows/firestore-emulator.yml` bytes on the default branch. The
  ingestor fetches that file at the source run commit and rejects evidence if
  the workflow file differs, preventing a PR from silently replacing the gate.

The service account must have Firestore datastore read/write access and the
WIF provider must restrict the repository, workflow/ref and audience. Terraform
adds a binding for an existing service account only; it does not create a
service account, WIF provider, database, key or secret. Review Terraform plan
before any apply. Do not store issuer private keys in GitHub variables or
secrets. Runtime callers using `create_firestore_evolution_service()` must set
`AIOS_EVOLUTION_BACKEND=firestore`; this is an explicit runtime environment
setting, not a repository Actions variable, and the factory has no filesystem
fallback.

## Initial activation and subsequent promotion

1. Publish a signed `CAPABILITY` artifact with `status=ACTIVE` and a signed
   `CAPABILITY_BOOTSTRAP_DECISION` binding its digest. Run the
   `AIOS Capability Registry Bootstrap` workflow once per capability.
2. Candidate and evaluation records are appended to Firestore by the governed
   M11 API. Their evidence references must include the immutable `ci://CI-...`
   record produced after the source workflow completes.
3. The independent authority issuer publishes a signed
   `CAPABILITY_PROMOTION_DECISION` binding candidate ID, latest evaluation ID,
   approver, base/target versions, evidence references and the new signed
   capability digest.
4. Run `AIOS Capability Promotion Gate`. The transaction rechecks candidate,
   evaluation, latest-evaluation pointer and active base, then appends decision
   and event and advances the active pointer atomically.
5. Cloud Run resolves the active pointer and verifies the signed decision and
   capability before the capability can be used for recovery/reconciliation.

No model/provider output, green CI badge, workflow dispatch identity or
unsigned callback is itself promotion authority. A missing or inconclusive
record fails closed.

## Non-goals / operational limits

- No GCP staging project, Firestore database, WIF provider, service account,
  IAM policy, Cloud Run service or secret was created or changed.
- No workflow was run against GCP; the workflows are dormant until repository
  variables and external WIF/IAM prerequisites exist.
- Artifact hashes bind downloaded GitHub ZIP bytes. They do not by themselves
  constitute a Sigstore artifact attestation or a cryptographic signature from
  the CI runner. Trust in the source run comes from the authenticated GitHub
  API, repository/workflow pinning and GitHub's workflow-run controls.
- The workflow currently ingests emulator log artifacts and job conclusions;
  it does not ingest JUnit XML or infer test counts from logs.
- This integration does not deploy the newly promoted code. It updates the
  Firestore active capability pointer only after a signed authority decision.
