# Independent evidence trust boundary

## Current status

AIOS record seals and content digests provide integrity within the configured
AIOS write boundary. They do not prove that a provider originated an observation.
A caller-controlled evidence envelope or an unkeyed SHA-256 digest is not
issuer authentication.

Until an independently operated issuer/verifier and its trust roots are
provisioned and verified, AIOS must fail closed:

- UNKNOWN effects cannot be retried based on caller-supplied authorization.
- Provider responses cannot terminalize an effect as OBSERVED_SUCCESS or
  OBSERVED_FAILURE solely because their payload is well-formed or has a digest.
- A claimed execution whose result is ambiguous remains blocked; do not clear
  the claim or replay the provider call.
- A deployment HMAC seal proves AIOS accepted/persisted a record. It does not
  prove provider origin.

## Required verifier contract

A future verifier must validate a signed envelope against out-of-band trust
configuration. At minimum, the envelope must bind issuer, key identifier,
algorithm, signature, provider, effect ID, attempt ID, provider operation ID,
verdict/outcome, evidence digest, and an anti-replay identifier.

Trust configuration must define issuer authorization, key activation/revocation,
rotation, expiry, and the operator responsible for provisioning. The verifier
must reject unknown issuers, revoked keys, unsupported algorithms, malformed
bindings, stale/replayed attestations, and signatures over non-canonical data.

## Enablement gate

Do not enable retry or terminal observation until all of the following are
available and tested:

1. Trust roots are provisioned out-of-band and are not writable by the worker.
2. At least one independently operated provider/broker issuer is integrated.
3. Positive, negative, tampering, binding-mismatch, replay, expiry, and
   revocation tests pass.
4. The verifier is exercised on the exact deployed code revision.
5. The trust decision and evidence lineage are durably auditable.

This document specifies a boundary and enablement gate. It is not itself a
cryptographic verifier or evidence that a provider integration exists.
