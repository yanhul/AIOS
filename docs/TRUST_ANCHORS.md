# Deployment trust anchors (effect authority)

AIOS state under `aios_dir` is never a trust anchor: anything an agent can write there it could
also forge. Authority decisions that must resist the executing agent use deployment-supplied
HMAC-SHA256 keys, following the model of `core/attestation.py`.

| Variable | Held by | Used by | Purpose |
|---|---|---|---|
| `AIOS_RETRY_ISSUER_KEYRING` | AIOS verifier | `retry_dispatch`, `issue_retry_authorization` | Registered retry approvers: `{"<issuer>": {"secret": "...", "scopes": ["effect.retry.approve"], "revoked": false}}` |
| `AIOS_PROVIDER_KEYRING` | AIOS verifier | `observe` (via `core.runtime`) | Registered providers: `{"<provider>": {"secret": "...", "scopes": ["provider.receipt.sign"], "revoked": false}}` |
| `AIOS_PROVIDER_SIGNING_KEYS` | Provider side only | `ProviderReceiptSigner.from_env` | `{"<provider>": "<secret>"}`. Lives in the provider process or the AIOS adapter that supervises it. Never give it to the agent. |

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
  `KicadAdapter`, `MiniMindAdapter`, `RepositoryPatchAdapter` take an explicit `signer=`.
  `apply_via_aios` defaults to `ProviderReceiptSigner.from_env("repo_patch")`.
* A caller-supplied AIOS evidence record is never treated as proof of provider execution.

## Limitations

* HMAC is symmetric. It authenticates against principals that do not hold the key, such as the
  agent. It does not authenticate against whoever holds the verifier keyring. An adapter that runs
  inside the AIOS process holds its signing key in that process. Treat it as part of the
  deployment's trusted computing base.
* Deployments that do not configure these variables fail closed. External effects stay `UNKNOWN`,
  and retries are refused.
