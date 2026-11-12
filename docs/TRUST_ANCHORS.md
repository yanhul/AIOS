# Deployment trust anchors (effect authority)

AIOS state under `aios_dir` is never a trust anchor: anything an agent can write there it could
also forge. Authority decisions that must resist the executing agent use deployment-supplied
HMAC-SHA256 keys, following the model of `core/attestation.py`.

| Variable | Held by | Used by | Purpose |
|---|---|---|---|
| `AIOS_RETRY_ISSUER_KEYRING` | AIOS verifier | `retry_dispatch`, `issue_retry_authorization` | Registered retry approvers: `{"<issuer>": {"secret": "...", "scopes": ["effect.retry.approve"], "revoked": false}}` |
| `AIOS_PROVIDER_KEYRING` | AIOS verifier | `observe` (via `core.runtime`) | Registered providers: `{"<provider>": {"secret": "...", "scopes": ["provider.receipt.sign"], "revoked": false}}` |
| `AIOS_PROVIDER_ED25519_KEYRING` | AIOS verifier | `observe` | Ed25519 **public** keys only: `{"<provider>": {"key_id": "ed25519:<sha256(pub)[:32]>", "public_key": "<32-byte hex>", "revoked": false}}`. Any other field is rejected. |
| `AIOS_PROVIDER_SIGNING_KEYS` | Provider side only | `ProviderReceiptSigner.from_env` | `{"<provider>": "<secret>"}`. Lives in the provider process or the AIOS adapter that supervises it. Never give it to the agent. Must **not** contain `minimind` in the AIOS process (see below). |

Secrets must be at least 16 characters long. They are never written to AIOS state. Keyring and
signer `repr()` output never includes them.

## Observation boundary (audit F-04)

* `observe()` is the only path into `OBSERVED_SUCCESS` / `OBSERVED_FAILURE`; `transition()` rejects both.
* A receipt is authoritative only if `authentication` is a signature by the **dispatched** provider's
  registered key over: effect, contract, permit, attempt, provider, provider operation id, outcome,
  SHA-256 of the exact raw observation, a random receipt id, and `issued_at`/`expires_at`
  (window ≤ 3600 s, 60 s clock skew).
* Missing/invalid/expired/mismatched → `ProviderAuthenticationError`, effect unchanged. In
  `core.runtime` the effect is recorded **UNKNOWN** with a `non-authoritative provider observation` reason.
* `SubprocessAdapter`: the provider process signs its own JSON receipt (`authentication` field).
  `KicadAdapter`, `RepositoryPatchAdapter` take an explicit `signer=`. `MiniMindAdapter` has no signer
  (see *MiniMind workload* below).
  `apply_via_aios` defaults to `ProviderReceiptSigner.from_env("repo_patch")`.
* A caller-supplied AIOS evidence record is never treated as proof of provider execution.

## MiniMind workload (audit F-04 / F-04.1, model A: provider-authenticated execution, Ed25519)

* MiniMind is **Ed25519-only** (`core.provider_ed25519.ED25519_REQUIRED_PROVIDERS`; any provider
  registered in `AIOS_PROVIDER_ED25519_KEYRING` is Ed25519-only as well). Its HMAC entries in
  `AIOS_PROVIDER_KEYRING`, if any, are ignored. There is no HMAC fallback.
* The workload holds the private key in its own secret store (e.g. a 0600 PEM file owned by the
  workload user, read with `Ed25519ReceiptSigner.from_pem_file`). The AIOS verifier holds only the
  public key, so nothing in the AIOS trust domain can produce a valid MiniMind signature. The private
  key never travels via argv, environment, stdin/stdout or logs.
* `MiniMindAdapter` never signs or re-signs. It refuses to run if the parent environment exposes a
  `minimind` HMAC signing key (or an unparseable `AIOS_PROVIDER_SIGNING_KEYS`). It withholds
  `AIOS_PROVIDER_SIGNING_KEYS`, `AIOS_PROVIDER_KEYRING`, `AIOS_PROVIDER_ED25519_KEYRING` and
  `AIOS_RETRY_ISSUER_KEYRING` from the child.
* Workload stdout: `{"minimind_receipt": {...}, "outcome": "...", "provider_operation_id":
  "minimind:<task_id>:<attempt_id>", "authentication": {"type": "PROVIDER_RECEIPT_ED25519",
  "algorithm": "Ed25519", "key_id", "receipt_id", "contract_id", "permit_id", "issued_at",
  "expires_at", "signature"}}`.
* The signature covers the canonical JSON of: type, algorithm, key_id, receipt_id, effect_id,
  contract_id, permit_id, attempt_id, provider, provider_operation_id, outcome, receipt_digest
  (SHA-256 of `{"minimind_receipt": ...}`: task_id, capability, terminal_state, artifact lineage,
  evidence), issued_at, expires_at. The verifier rebuilds every field from trusted effect state and
  the exact raw observation; nothing unsigned is used. `key_id` must equal the key registered for the
  **dispatched** provider, and the registered `key_id` must match its public key.
* Outcome: `PROMOTE` → `OBSERVED_SUCCESS`; `REJECT` / `INCONCLUSIVE` / `BLOCKED` → `OBSERVED_FAILURE`.
  Any verification, binding, schema or configuration failure (missing/malformed/revoked key,
  `cryptography` not installed) → `UNKNOWN`. Promotion itself remains a separate AIOS decision.
* Deployment requirement (not enforceable in code): the workload key file must be unreadable by the
  AIOS process user and the agent. Requires the `cryptography` package on the verifier and workload.

## Limitations

* HMAC is symmetric (all providers except Ed25519-only ones such as MiniMind). It authenticates against principals that do not hold the key, such as the
  agent. It does not authenticate against whoever holds the verifier keyring. An adapter that runs
  inside the AIOS process holds its signing key in that process. Treat it as part of the
  deployment's trusted computing base.
* Deployments that do not configure these variables fail closed. External effects stay `UNKNOWN`,
  and retries are refused.
