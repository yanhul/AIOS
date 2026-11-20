# AIOS Self-Improvement: Experience and Capability Evolution

Status: PARTIAL IMPLEMENTATION. The append-only local persistence and gate logic
are implemented on the self-improvement feature branch. A Firestore repository,
automatic CI artifact ingestion, active registry integration, and deployment
orchestration are not implemented by this change.

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
4. `rollback_capability`: separately authorized append-only rollback to a
   version present in the capability's prior decision history.

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

## 5. Explicit non-goals and remaining integration

This implementation does not train a model, invoke a provider, execute a patch,
change the active capability registry, or deploy a candidate. It does not
provide a Firestore adapter, cross-host locking, automatic CI artifact
discovery, statistical contribution/credit assignment, or a relationship graph.
Those remain required before M10/M11 can be declared operationally complete.

A green unit test suite proves only the tested local invariants. Local content
hashes and audit events are not signatures and do not resist a privileged,
coordinated rewrite of both record and event. Tests do not prove production
identity custody, Firestore durability, provider correctness, or safe rollout. Missing or inconclusive evidence must remain BLOCKED or
INCONCLUSIVE.
