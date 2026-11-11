# Independent Evidence Issuer / Verifier Boundary

## Current finding (source inspection at PR #127 HEAD)

- `core/runtime.py` defines a `ProviderAdapter` protocol and a plain `ProviderReceipt` dataclass. The receipt has provider/effect/attempt/operation/outcome/observation fields, but no authenticated issuer identity, key identifier, signature, or verifier result.
- The adapter is injected by the caller. The inspected AIOS runtime code does not establish that the adapter process, provider, or receipt transport is independently trusted.
- `core/evidence.py::verify_evidence()` checks a public, unkeyed SHA-256 digest. It detects accidental/tampered payload changes only; it cannot authenticate an issuer.
- `core/effect_authority.py::observe()` therefore rejects terminalization when no independent verifier is configured. `UNKNOWN` retry is also blocked.
- No provider-specific adapter or trust-root/key-registry implementation was found in the PR's provider boundary. The protocol alone is not an issuer.

This is a source-inspection finding, not proof about external provider infrastructure outside this repository.

## Required trust model before enabling terminal observations

The issuer must be independent of the caller that requests `observe()`. A caller-supplied public key, boolean, issuer name, digest, or signature-shaped string is not a trust anchor. Trust anchors and issuer policy must be provisioned out-of-band by an operator-controlled configuration/secret-management path, with explicit key rotation and revocation.

A signed receipt envelope should bind a canonical, versioned payload containing at least:

- schema/version and unique receipt ID;
- issuer ID, key ID, and an explicitly allow-listed signature algorithm;
- effect ID, exact attempt ID, provider ID, provider operation ID;
- terminal outcome and digest of the immutable observation payload;
- issuer issue time and any required expiry/nonce/replay fields.

The verifier must, before accepting a terminal observation:

1. Resolve the issuer/key only from operator-managed trust configuration.
2. Verify the signature over canonical bytes using a vetted cryptographic implementation; reject algorithm/key substitution.
3. Check issuer authorization for the provider and effect class, key validity window, and revocation state.
4. Match effect ID, attempt ID, provider ID, operation ID and outcome to the persisted dispatched attempt and contract.
5. Enforce receipt uniqueness/replay prevention with a durable atomic consume operation.
6. Reject stale, malformed, duplicate, mismatched, revoked, or unverifiable receipts.

A retry authorization is a separate authority decision. A provider's success/failure receipt must not implicitly authorize retry of an ambiguous side effect. Retry permits must be independently issued, bound to the exact effect and next attempt, policy/contract digest, actor/provider and expiry, and consumed once.

## Fail-closed behavior until that boundary exists

- Keep terminal `observe()` blocked.
- Keep `UNKNOWN` retry blocked.
- Convert unsigned or unverifiable provider responses to `UNKNOWN`; never infer success from adapter return, HTTP status, process exit, or caller assertions.
- Do not clear a durable execution claim after a crash or submission timeout. Recovery requires an independent reconciliation source that can establish whether the original side effect occurred; otherwise preserve the ambiguous block.
- Do not add a demo key, embedded private key, caller-configurable public key, or test fixture as a production trust root.

## Enablement gate

Implementation should be a separate change after an operator-owned trust-root provisioning contract and at least one real provider/broker issuer integration are available. Required adversarial tests: forged caller receipt; wrong effect/attempt/provider/outcome; signature tampering; unknown/revoked/expired key; issuer not authorized for provider; duplicate/replayed receipt; verifier unavailable; concurrent receipt consumption; retry authorization replay. All negative cases must leave the effect non-terminal and must not invoke the provider again.

Until those prerequisites exist, the correct status is **BLOCKED — no authenticated issuer configured**, not VERIFIED and not PASS.
