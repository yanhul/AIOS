# AIOS Self-Improvement: Experience and Capability Evolution

Status: PARTIAL IMPLEMENTATION. The local developer ledger remains available;
a Firestore-only M10/M11 service, transactional evolution ledger, CI evidence
ingestion workflow, signed promotion/bootstrap workflows and active capability
resolver binding are now implemented in code. They have not been run against a
GCP project. Production IAM isolation, WIF configuration, issuer integration,
contribution/relationship learning and deployment orchestration remain open.

## 1. Governed loop

`OBSERVE -> RECORD EXPERIENCE -> ANALYZE -> PROPOSE CANDIDATE -> INDEPENDENT EVALUATION -> AUTHORITY GATE -> PROMOTE or BLOCK -> LEARN`

AI/model workers may discover issues, propose patches, and summarize evidence.
They cannot change policy, evidence requirements, budgets, terminal conditions,
or promotion rules. The control plane remains authoritative.

## 2. M10: experience record

`core.experience_memory.record_experience()` appends an immutable record with:

- capability ID and version;
- task ID and contributor identity;
- PASS, BLOCKED, or INCONCLUSIVE outcome;
- evidence references and run ID;
- source commit and artifact SHA-256;
- optional effect, attempt, and receipt lineage;
- verifier, evaluation ID, and verification level.

PASS is rejected unless effect -> attempt -> receipt is complete, evidence refs
exist, verifier differs from contributor, an evaluation is linked, and the
verification level is VERIFIED_DIGITAL or VERIFIED_PHYSICAL. A trusted
pass-evidence callback must independently validate the receipt, evidence and
evaluation references and return exactly true. Negative outcomes remain
recorded and are not rewritten as success.

The experience and its audit event are committed in one shared mutation batch.
Loading checks content identity and the matching audit event. This detects
record/event mismatch and accidental or unilateral edits; it is not a
cryptographic defense against a privileged actor rewriting both files. The
local store does not sign records or establish actor authenticity. It uses the
local `.aios` state tree and shared filesystem mutation lock, and does not
claim multi-host/Firestore durability. Production identity and receipt
authenticity must be supplied by trusted authority/evidence callbacks.

## 3. M11: candidate and version lifecycle

`core.capability_versions` exposes:

1. `propose_candidate`: immutable source commit, patch digest, base version,
   candidate version, run ID, change summary and evidence references.
2. `evaluate_candidate`: independent evaluator identity/version, PASS/FAIL/
   INCONCLUSIVE verdict, test-suite digest, comparison digest and evidence.
3. `promote_candidate`: requires latest evaluation PASS, distinct proposer,
   evaluator and approver, independent evaluation-provenance verification,
   evidence verifier returning exactly true, a fresh base version, and an
   AIOS promotion authorizer returning exactly true.
4. The local `rollback_capability` path remains a developer ledger operation.
   Production Firestore activation currently requires signed bootstrap and
   promotion decisions; signed rollback decision support remains a follow-up.

Semantic versions use MAJOR.MINOR.PATCH. A candidate based on a stale active
version cannot be promoted. A later FAIL/INCONCLUSIVE evaluation supersedes an
older PASS for promotion purposes.

## 4. Required separation of identities

- proposer: creates candidate patch;
- evaluator: independently evaluates the exact candidate and test suite;
- approver: authorizes promotion or rollback;
- evidence verifier: resolves all evidence references;
- authority callback: enforces policy/permit and returns exactly true.

The module does not mint these identities or decide who is trusted. Those
bindings must come from the deployment's AIOS identity and authority stores.
The Firestore promotion gate verifies a signed `CAPABILITY_PROMOTION_DECISION`
and a signed `CAPABILITY` artifact with exact candidate/evaluation/source/patch
bindings. It checks the latest PASS, three distinct identities, CI evidence for
the same repository and commit, active base version, signed revision and
predecessor digest, then atomically appends the decision/event and advances the
active pointer. The worker authority resolver checks the signed active pointer
before accepting the capability.

## 5. Explicit non-goals and remaining integration

The CI evidence workflow is triggered by `workflow_run` after the Firestore
Emulator Gate completes. It verifies the authenticated GitHub API run metadata,
pinned workflow path, completed successful jobs and emulator log artifact; it
stores the downloaded artifact ZIP SHA-256 and provenance in `aios_ci_evidence`.
The manual `AIOS Capability Promotion Gate` workflow activates only when the
independent issuer has already published both signed authority artifacts. The
one-time registry bootstrap is also a manual signed workflow. Neither workflow
creates or deploys GCP resources.

This implementation does not train a model, invoke a provider, execute a patch,
or deploy a candidate. The `workflow_run` ingestor only becomes active after its
workflow is present on the repository default branch and the repository WIF /
Firestore variables are configured. No GCP run has been performed.

A green unit test suite proves only the tested invariants. Local content
hashes and audit events are not signatures and do not resist a privileged,
coordinated rewrite of both record and event. The Firestore active pointer is a
mutable projection; a project-level `roles/datastore.user` grant is not
collection-scoped. A compromised worker identity could rewrite it, so before
production the evolution registry must be isolated in a separately permissioned
Firestore database/project or activation must be moved behind a separately
permissioned authority service. No IAM apply is authorized by this change.

No local Firestore Emulator or GCP staging run has yet been completed for this
batch. Tests do not prove production identity custody, Firestore durability,
provider correctness, or safe rollout. Missing or inconclusive evidence must
remain BLOCKED or INCONCLUSIVE.
