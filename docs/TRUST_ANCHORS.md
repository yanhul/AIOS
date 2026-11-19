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
* Key isolation is enforced at runtime by `adapters/minimind/isolation.py` (see next section). Requires
  the `cryptography` package on the verifier and workload.

## MiniMind private-key isolation (deployment/runtime boundary)

**Threat model.** Attackers: the AIOS parent process (and any code it runs, including the executing
agent) and every other agent identity on the host. Goal: obtain or use the MiniMind Ed25519 private key
to forge `PROVIDER_RECEIPT_ED25519` receipts. Out of scope: root / `CAP_DAC_*` / `CAP_SYS_PTRACE`
holders, kernel compromise, the signer identity itself. The receipt command (the MiniMind workload
proper: training/evaluation code, data loaders) is **not trusted with the key**; it is in the threat model
and runs under its own UID. Mode `0600` alone is not
treated as isolation: the boundary is a distinct UID plus checks that the parent cannot cross it.

**Trust boundary.** `aios-parent` (AIOS) ─stdin request→ `sudo -n -u aios-minimind -- <signer launcher>`
→ `workload_entry.py` (signer UID, key owner, immutable root-owned code only) ─stdin request→
`sudo -n -u aios-minimind-run -- <receipt launcher>` (runner UID, **no key access**) ─stdout
`{"minimind_receipt"}`→ signer validates and signs ─stdout signed envelope→ parent. The parent holds only
the public key. A compromised receipt command can lie about the current receipt's content (that trust
belongs to the MiniMind workload) but cannot read the key or sign anything.

**Required OS properties (Linux; all checked by `WorkloadIsolation.verify()` before every launch).**

| Property | Check | On failure |
|---|---|---|
| Parent is not root, not the workload UID, not in the workload's primary group | `getuid/geteuid/getgroups`, `pwd` | `IsolationError`, no launch |
| Parent has no Linux capabilities | `/proc/self/status` `CapEff/CapPrm/CapAmb == 0` | `IsolationError` |
| `sudo` is root-owned setuid (root-owned symlink hops only); signer launcher root-owned | `lstat` walk to `/` | `IsolationError` |
| Complete executable chain derived from the signer launcher, **not** from caller `trusted_paths`: launcher must be exactly `#!/bin/sh` + `exec <python> -I -S -B <lib>/adapters/minimind/workload_entry.py <config>`; interpreter, every file of `<lib>` (recursive, no symlinks), config | `parse_signer_launcher`, `check_trusted_tree` | `IsolationError` |
| Config keys exactly `provider,key_path,runner_user,receipt_launcher,receipt_launcher_sha256,timeout,ttl` (legacy `receipt_command` rejected); `key_path` equals the caller's | `load_workload_config` | `IsolationError` |
| Receipt launcher root-owned, no g/o write on any ancestor, referenced by its real path, sha256 equals config; `runner_user` exists, non-root, ≠ signer, ≠ parent | `validate_receipt_command` | `IsolationError` |
| Parent sudo rights are **exactly** `(workload_user) NOPASSWD: <launcher> ""` (no args, no other rule, no root) | `sudo -n -l` parsed | `IsolationError` |
| Parent `open(key_path)` fails with `EACCES` (real kernel probe; `ENOENT`/`ELOOP`/success all block) | `os.open(O_NOFOLLOW)` | `IsolationError` |

Signer side (`workload_entry.py`, independent of the parent): before reading the key it re-runs the
config/receipt-chain validation, checks its own `sudo -n -l` is exactly `(runner_user) <receipt launcher> ""`,
and verifies its interpreter, its code tree, every `sys.path` import root and every loaded module file
(all imports, including `cryptography`, are done before this check; it is repeated right before the key
is read). The receipt launcher is executed via sudo as `runner_user` with a minimal env.

Key loading (`read_workload_key`): key opened with `O_NOFOLLOW`; must be a regular file, `st_nlink == 1`,
owned by the workload euid, mode `& 0o077 == 0`; key directory owned by the workload (or root) with
mode `& 0o077 == 0`; workload must not be root. The key is read only after the receipt command has
finished and is never written to stdout/stderr/argv/env.

**Adapter contract.** `MiniMindAdapter(isolation=WorkloadIsolation(...))` (`command` must be empty; the
launcher is fixed). `isolation=None` → refuses to run. `UNISOLATED_FOR_TESTS` is an explicit test-only
opt-out reported as `isolation_status == "UNISOLATED"`; it must never be used in deployment. There is
no automatic fallback to same-UID execution.

**Parent/child communication.** Child env is exactly `PATH`, `LANG` (sudo `env_reset` also applies);
`sudo` closes inherited fds > 2. Request on stdin (≤128 KiB). Child stdout: the signed envelope only
(schema above). The key path appears only in the root-owned workload config, never on argv. The receipt runner gets the
same request on stdin and returns only `{"minimind_receipt": {...}}`.

**Provisioning.** Reference: `scripts/minimind_isolation_e2e.sh` (users `aios-parent`, `aios-minimind`
(signer), `aios-minimind-run` (receipt runner), `aios-agent`; code in `/usr/lib/aios-minimind/lib`, config
`/usr/lib/aios-minimind/etc/workload.json`, signer launcher `/usr/lib/aios-minimind/bin/minimind-workload`,
receipt launcher `/usr/lib/aios-minimind/bin/receipt-launcher`, key `/var/lib/aios-minimind/keys/ed25519.pem`
(dir `0700`, file `0600`, owner `aios-minimind`), sudoers `/etc/sudoers.d/aios-minimind` `0440` with exactly
`aios-parent ALL=(aios-minimind) NOPASSWD: <signer launcher> ""` and
`aios-minimind ALL=(aios-minimind-run) NOPASSWD: <receipt launcher> ""`). Updating the receipt launcher
requires updating `receipt_launcher_sha256` in the config (root). The runner UID must have no sudo rights.
Do not install under a directory with group/other write on any ancestor (e.g. GitHub-hosted runners ship
`/opt` as `0777`; `verify()` rejects it because the parent could rename the tree).
The key is generated *as the workload user* (`O_CREAT|O_EXCL|O_NOFOLLOW`, umask 077); only the public
key leaves the workload. Validate sudoers with `visudo -cf`.

**Rotation.** As the workload user generate a new key to a new file, publish the new `public_key`
/`key_id` in `AIOS_PROVIDER_ED25519_KEYRING` (verifier), atomically switch `key_path` in the root-owned
config, then remove the old key file. To revoke, set `"revoked": true` for the old entry; receipts
signed by it become `UNKNOWN`.

**Public-key distribution.** Only `{"key_id", "public_key", "revoked"}` per provider, via the
verifier's `AIOS_PROVIDER_ED25519_KEYRING`. `key_id = key_id_for(public_key)` is re-checked on load.

**Platform coverage.**

| Platform | Status |
|---|---|
| Linux (dedicated UID via restricted sudo) | Implemented; OS-level tests in CI job `minimind-key-isolation` |
| Linux containers | Supported only if the parent runs in a separate container/user namespace *and* the above checks still hold; not separately tested → treat as UNKNOWN |
| Windows | **Not implemented → BLOCKED** (`verify()` refuses) |
| macOS / other POSIX | **Not implemented → BLOCKED** (`verify()` refuses) |

**Operational verification.** On the deployment host, as the AIOS user:
`python -c "from adapters.minimind.isolation import WorkloadIsolation as W; print(W(workload_user='aios-minimind', launcher='/usr/lib/aios-minimind/bin/minimind-workload', key_path='/var/lib/aios-minimind/keys/ed25519.pem', trusted_paths=('/usr/lib/aios-minimind/lib','/usr/lib/aios-minimind/etc/workload.json')).verify())"`
must print evidence with `key_probe: EACCES`. Also confirm `sudo -n -l` shows only the launcher rule. As the receipt-runner UID, verify that `sudo -n -l` grants no commands; the runner must have no sudo authority. The parent cannot safely infer another UID's full sudo policy from its own restricted sudo rule, so this is a deployment provisioning gate. Run `scripts/minimind_isolation_e2e.sh` on a disposable host built from the same image.

**Deployment is BLOCKED if any of:** `verify()` raises; the AIOS user is root, has capabilities or any
other sudo right; the agent runs as the workload UID; the key, launcher, workload code or config is
writable/replaceable by the parent; platform is not Linux; the adapter is configured with
`UNISOLATED_FOR_TESTS` or `isolation=None`; `cryptography` is missing on the workload; the receipt command
runs as the signer UID or any component of either launcher chain is not immutable root-owned code.

**CI semantics.** `full-suite` and `minimind-key-isolation` prove source behaviour and the boundary on a
disposable runner only. `minimind-capability-readiness (non-production)` reports the MiniMind capability
status (currently BLOCKED: required runtime surface missing) without gating; dispatching CI with
`require_minimind_production=true` turns it into a hard gate (exit 2 unless AVAILABLE). No green CI run is
evidence of MiniMind runtime or production readiness.

## Limitations

* HMAC is symmetric (all providers except Ed25519-only ones such as MiniMind). It authenticates against principals that do not hold the key, such as the
  agent. It does not authenticate against whoever holds the verifier keyring. An adapter that runs
  inside the AIOS process holds its signing key in that process. Treat it as part of the
  deployment's trusted computing base.
* Deployments that do not configure these variables fail closed. External effects stay `UNKNOWN`,
  and retries are refused.
