# ADR: External execution substrate and independent retry authority

- Status: Accepted for implementation on PR #145
- Scope: repository code, Firestore Emulator, and CI only
- Production resources: explicitly out of scope
- Decision owner: AIOS authority boundary

## Context

AIOS owns authorization decisions and durable evidence. It is not the queue,
scheduler, or provider runtime. A transport retry is not permission to repeat
an external effect. Firestore remains authoritative for effect, attempt,
receipt, and retry-consumption state.

## Decisions

### A. Delivery and worker

Use Google Cloud Tasks for at-least-once task delivery and Cloud Run for a
stateless adapter. Cloud Tasks is a wake-up/delivery mechanism only; it is not
the source of truth and its retry policy must never create a new effect attempt.

The task envelope is an immutable reference, not authority:

- schema: `aios.effect.dispatch.v1`
- `effect_id`
- `attempt_id`
- `expected_revision`
- `dispatch_event_digest`
- `issued_at`
- `expires_at`

The worker must read the effect and attempt from Firestore and verify the
exact attempt/revision/event binding before invoking an adapter. Duplicate
delivery for a terminal effect is an acknowledgement-only operation.
A stale, missing, expired, or mismatched task is rejected without provider
execution. A task for an ambiguous `DISPATCHED` attempt may only reconcile that
same attempt; it must never call execute again. Transport retries may re-run
reconciliation/acknowledgement but cannot mint a new attempt.

Dispatch ordering is: commit Firestore dispatch intent -> enqueue Cloud Task.
If enqueue outcome is ambiguous, reconcile the task by deterministic task name
or re-enqueue the same immutable envelope. Never create a second effect attempt.
A durable outbox/reconciler is required before claiming lossless dispatch.

Cloud Run uses ADC/OIDC and least-privilege service identity. No key-file
credentials, private authority keys, or provider secrets are placed in task
payloads, environment literals, source, or container image.

### B. Attestation and secret lifecycle

HMAC verification remains a verifier operation. Production secret material
must be read through Secret Manager using the Cloud Run service identity.
Cloud KMS is reserved for asymmetric signing operations; it is not treated as
a generic HMAC-secret store. Secret versions are pinned per verification
operation and rotation/revocation behavior must be tested. No production
secret or IAM binding is created by this PR.

### C. OCI reproducibility

Pin the base image by digest; lock all transitive Python dependencies with
hashes; generate an SBOM; record source and build provenance; and perform two
independent builds from the same source. Compare OCI manifest, config, and
layer digests. A successful single Docker build is not reproducibility proof.
No registry push is permitted in this scope.

### D. Independent retry issuer

Retry authorization is signed by a separately operated Ed25519 issuer whose
private key is not available to AIOS. AIOS receives only pinned public keys.
The signed canonical payload binds:

- schema and issuer/key ID
- effect ID, contract ID, permit ID, actor, provider
- current attempt ID and attempt number
- exact current state (`UNKNOWN`) and state revision/digest
- NOT_APPLIED proof digest and verifier identity
- unique nonce, issued-at, expiry, and policy digest

AIOS verifies signature, issuer/key status, validity window, all bindings,
and the NOT_APPLIED proof. A Firestore transaction must atomically:
1. read the effect and current attempt;
2. confirm state is still UNKNOWN and all signed bindings still match;
3. confirm the authorization nonce has not been consumed;
4. write immutable authorization-consumption evidence;
5. create exactly the next attempt and move the effect to PLANNED (or the
   explicitly specified retry-ready state) with a revision increment.

Any mismatch, replay, expired/revoked key, inconclusive provider result, or
missing NOT_APPLIED proof fails closed. A timeout or missing response is not
proof of non-execution. Queue delivery retries do not call this transition.

## Required verification gates

- A: duplicate delivery, stale task, task expiry, crash after Firestore commit
  before enqueue, crash after provider response before receipt commit, and
  terminal redelivery; assert no duplicate provider execution.
- B: missing secret, wrong version, rotation overlap, revoked version, and
  least-privilege identity; emulator/unit tests cannot substitute for real IAM
  verification, so production lifecycle remains blocked until staging approval.
- C: hash-locked install, SBOM generation, two clean builds, digest equality,
  and provenance verification.
- D: invalid signature, altered field, cross-effect/attempt binding, expired
  authorization, revoked issuer, nonce replay, concurrent consume race,
  invalid NOT_APPLIED proof, and transaction rollback.

## Explicit non-goals

No production Firestore database, Secret Manager secret, KMS key, IAM binding,
Cloud Tasks queue, Cloud Run service, Artifact Registry push, external provider
call, or production side effect is created by this implementation batch.

## Completion semantics

Each gate is reported independently as VERIFIED, PARTIAL, or BLOCKED with
commit SHA, CI run, test names, and artifact references. Passing unit/emulator
tests does not prove production IAM, queue delivery, key custody, or provider
semantics.
