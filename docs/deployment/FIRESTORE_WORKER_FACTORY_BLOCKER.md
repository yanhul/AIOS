# Firestore worker factory: remaining authority blocker

Status: **BLOCKED — do not deploy**

## Verified code dependency

`core/firestore_execution.py` currently imports `authorize`, `load_contract`, and `load_permit` from `core.authority`. `core.authority` reads contract, permit, and attestation JSON from a local `aios_dir`; capability and policy resolution also read local repository state. Therefore a Cloud Run worker cannot be treated as stateless merely because effect/attempt/receipt state is in Firestore.

## Safe boundary

A production factory must not construct a worker that can call `execute_firestore_effect()` until all of these are supplied by a durable, independently validated authority backend:

- immutable contract record + identity recomputation;
- permit record + cryptographic verification;
- issuer attestation + pinned trust anchor and verification;
- policy record addressed by the exact contract policy digest;
- capability registry snapshot addressed by a pinned digest;
- revocation/expiry semantics and deterministic read consistency.

The existing filesystem authority implementation is not an acceptable fallback. A missing record, digest mismatch, unavailable Firestore, invalid signature, or missing trust anchor must prevent worker startup/execution.

## OCI artifact

`Dockerfile.firestore-worker` and `requirements-firestore.txt` are an initial dependency/build scaffold only. The image intentionally has no executable CMD/ENTRYPOINT because no safe durable-authority-backed worker factory exists yet. The Python base image is version-pinned but not digest-pinned, and the dependency file is not a hash lock. Thus this is **not yet a reproducible production OCI build**.

## Emulator gate

The Firestore Emulator must be started as a real emulator process and tests must use the official SDK against `FIRESTORE_EMULATOR_HOST`. In-memory transaction doubles are unit tests only. Required cases: process death after dispatch commit; restart and same-attempt reconciliation; UNKNOWN remains non-dispatchable; terminal receipt commit then lost acknowledgement; two concurrent writers racing the same revision; emulator restart with persisted data.

No live Firestore database, Cloud Run resource, IAM binding, or provider operation is authorized by this change.
