# TRY algorithm worker provenance receipt v1

## Purpose and trust boundary

P1 adds an AIOS-owned verifier for a signed TRY algorithm-worker receipt. The
worker signs the exact receipt with Ed25519; AIOS pins only the public key in
the deployment keyring under issuer try.algorithm_executor and scope
try.algorithm.execution.receipt.verify. The private key must remain in the
worker's secret store. The keyring is deployment policy, not request input.

The signed body binds contract, permit, effect ID, dispatch ID/digest, execution ID, attempt ID and number,
worker identity/build digest, executor Git revision/source digest, algorithm
specification digest, input digest, output artifact digest, result digest,
status, validity window, and signing key ID.

The caller must reconstruct every expected binding from persisted AIOS
contract/permit/dispatch/attempt records and deployment policy. Never copy
expected values from the receipt being verified.

## Status semantics

- COMPLETED / COMPLETED: AIOS authenticates the worker statement and immutable
  execution bindings. AIOS must still independently verify algorithm output
  and artifact contents before recording a verified outcome.
- UNKNOWN / IN_PROGRESS_OR_AMBIGUOUS: the attempt may have executed. It is
  recorded as UNKNOWN; retry is not authorized.
- No receipt status grants retry or promotion. Separate AIOS reconciliation
  and an explicit authority decision are required.

## Important limits

A valid Ed25519 signature proves that the holder of the pinned private key
signed the bound statement. It does not prove the worker host was uncompromised,
that the claimed binary was actually loaded, or that an artifact was produced
by a particular CPU/runtime. Stronger measured workload identity or platform
attestation is a separate deployment integration and is not claimed here.

This verifier is separate from core.algorithm_execution_receipt: one
authenticates the worker statement; the other independently checks
algorithm-result correctness. Both are needed.
