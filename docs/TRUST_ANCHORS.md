# Deployment trust anchors (effect authority)

AIOS state under `aios_dir` is never a trust anchor: anything an agent can write there it could
also forge. Authority decisions that must resist the executing agent use deployment-supplied
HMAC-SHA256 keys, following the model of `core/attestation.py`.

| Variable | Held by | Used by | Purpose |
|---|---|---|---|
| `AIOS_RETRY_ISSUER_KEYRING` | AIOS verifier | `retry_dispatch`, `issue_retry_authorization` | Registered retry approvers: `{"<issuer>": {"secret": "...", "scopes": ["effect.retry.approve"], "revoked": false}}` |
| `AIOS_PROVIDER_KEYRING` | AIOS verifier | `observe` (via `core.runtime`) | Registered providers: `{"<provider>": {"secret": "...", "scopes": ["provider.receipt.sign"], "revoked": false}}` |
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

## MiniMind workload (audit F-04, model A: provider-authenticated execution)

* The MiniMind workload process signs its own receipt with the `minimind` key, obtained from its own
  secret store (separate uid, container or secret mount). The AIOS parent and the agent never hold it.
* `MiniMindAdapter` never signs or re-signs. It refuses to run if the parent environment exposes a
  `minimind` signing key (or an unparseable `AIOS_PROVIDER_SIGNING_KEYS`): the effect becomes `UNKNOWN`.
* `AIOS_PROVIDER_SIGNING_KEYS`, `AIOS_PROVIDER_KEYRING` and `AIOS_RETRY_ISSUER_KEYRING` are withheld from
  the child environment. An HMAC verifier keyring would let the child forge any provider.
* Workload stdout: `{"minimind_receipt": {...}, "outcome": "...", "provider_operation_id":
  "minimind:<task_id>:<attempt_id>", "authentication": {...}}`. The signature binds effect, contract,
  permit, attempt, provider, operation id (task + attempt), outcome and the SHA-256 of
  `{"minimind_receipt": ...}` (capability, task_id, terminal_state, artifact lineage, evidence),
  receipt id, issued/expiry.
* Outcome: `PROMOTE` → `OBSERVED_SUCCESS`; `REJECT` / `INCONCLUSIVE` / `BLOCKED` → `OBSERVED_FAILURE`.
  A mismatch, a non-PROMOTE result labelled success, a wrong task/capability/operation, a schema error
  or any verification failure → `UNKNOWN`. Promotion itself remains a separate AIOS decision.
* Deployment requirement (not enforceable in code): the workload key store must be unreadable by the
  AIOS process user and the agent. If it is readable, provider authentication degrades to adapter-level
  attestation.

## Limitations

* HMAC is symmetric. It authenticates against principals that do not hold the key, such as the
  agent. It does not authenticate against whoever holds the verifier keyring. An adapter that runs
  inside the AIOS process holds its signing key in that process. Treat it as part of the
  deployment's trusted computing base.
* Deployments that do not configure these variables fail closed. External effects stay `UNKNOWN`,
  and retries are refused.
