# AIOS — AI Operating System

AIOS is the governed control, state, evidence, capability, and orchestration layer around autonomous AI workloads.

## Mission

AIOS turns a human problem into a durable, verifiable execution process and a reusable outcome:

`Problem -> Contract -> Discover -> Plan -> Execute -> Observe -> Verify -> Reconcile -> Promote/Block -> Persist -> Reuse/Evolve`

AIOS is not a model and not a single agent. It governs agents, tools, software, devices, services, and physical-world workloads while keeping workload source independently owned.

## Architecture

- **Governance / Control Plane:** contract, authority, policy, durable state, evidence, provenance, contradiction handling, verification, gates, audit history, capability registration and promotion.
- **Capability / Workload Plane:** registered agents, tools, research, software, hardware, devices and services.
- **Capability Graph:** evidence-bound relationships between capabilities; relationships are never assumed merely because two capabilities exist.
- **Experience / Evolution:** verified task-to-capability history, negative evidence, versioned candidate capabilities and governed promotion.
- **Context:** task, identity, device/software, permissions, resources, time, location and physical state are first-class execution inputs.

See `docs/TARGET_ARCHITECTURE.md` for the normative target and `docs/ROADMAP.md` for implementation status. See `docs/HARNESS_REFERENCE.md` for the durable-harness boundary adopted by AIOS.

## Proof-of-system workloads

The workload repositories remain independently owned:

- `AIOS` — control, governance and capability plane.
- `try` — autonomous research and strategy-evaluation workload.
- `android-ai-assistant` — software/device-agent workload.
- `RX50` — hardware-engineering and physical-evidence workload.
- `jingyaogong/minimind` — model-learning substrate for pretraining, SFT, preference/RL training, tool use and agentic RL.

AIOS references and governs workloads; it does not copy, merge, or silently rewrite their source.

MiniMind is integrated only through `adapters/minimind`: AIOS authorizes the learning task and validates artifact lineage and independent evaluation evidence. Training reward is a learning signal, not promotion authority.

Initial workload registrations live in `capabilities/registry.yaml`.

## Safety / governance invariants

- No fabricated evidence, measurements, tests, or specifications.
- No silent promotion of assumptions or observations into facts or verification.
- Agents cannot modify governing policy, evidence requirements, promotion criteria, budgets, or terminal conditions.
- Autonomous retries are bounded by external policy.
- Every material state mutation is auditable and recoverable.
- Verification claims must resolve to evidence or deterministic checks appropriate to the claim.
- Digital verification and physical verification remain distinct.
- Model-learning workloads must provide immutable artifact lineage; reward scores alone cannot authorize promotion.

## Security deployment requirements

- Set `AIOS_AUTHORITY_ATTESTATION_SECRET` to a deployment-held secret of at least 16 characters. Permit creation persists an HMAC attestation when this secret is present; `authorize()` rejects execution when the secret or matching attestation is absent or invalid. Never expose this secret to agents or workload code.
- Set `AIOS_EVIDENCE_SIGNING_SECRET` to a separate deployment-held secret of at least 16 characters. Only the trusted verifier should receive it to attest evidence; promotion verifies the attestation and rejects caller-declared levels without it.
- Keep both secrets in the deployment secret manager / GitHub Actions secrets. Do not commit values to the repository, artifacts, logs, or test fixtures. Unit-test fixtures are non-production only.
- Absorption verification, runtime proof, promotion, and apply artifacts must all carry the same current `GITHUB_RUN_ID`. A missing or mismatched run ID blocks promotion and materialization.

## Current implementation

The repository contains the M1/M1.5 state and mutation foundation plus implemented authority, verification, reconciliation, contract, runtime and durable-execution components. A dependency-free governed durable loop is implemented in `core/durable_loop.py` with coverage for bounded execution, persistence, terminal gating and resume. Capability identity/registry, first-class execution context, and governed workload adapters are now established; full cross-repository training execution and promotion automation remain separate implementation work.


## Gateway protocol v5 retry trust configuration

The v5 retry path is disabled unless both trust roots are explicitly configured:

- TRY Worker: `TRY_OPERATION_RECEIPT_PRIVATE_KEY` (base64 PKCS#8 Ed25519 private key) and `TRY_OPERATION_RECEIPT_KEY_ID`. AIOS pins only the matching raw 32-byte public key (base64) under `AIOS_TRY_OPERATION_KEYRING` with scope `try.operation.receipt.verify`. HMAC receipts are rejected; the bearer token is transport authentication only.
- AIOS RetryPermit: `AIOS_GATEWAY_RETRY_PRIVATE_KEY_FILE` points to a PEM Ed25519 private key readable only by the AIOS service account (mode `0600`). AIOS derives key ID `ed25519:<first-32-hex-of-SHA256(raw-public-key)>`.
- Gateway: `AIOS_GATEWAY_RETRY_PUBLIC_KEYS` is a JSON object mapping that key ID to the 32-byte raw public key as 64 lowercase hex characters. Gateway never receives the private key.

The TRY operation HMAC key and AIOS RetryPermit Ed25519 key are separate trust domains. Rotate TRY keys by pinning the new key ID before switching the Worker. Rotate AIOS/Gateway keys by pinning the new public key before deploying the AIOS signer, then retire the old public key after outstanding permits expire.

The only current retry-eligible TRY receipt is `FAILED / NOT_SUBMITTED` for local provider configuration preflight failure before Gemini POST. HTTP errors, 429, 5xx, timeouts, malformed responses and any ambiguous post-submission failure remain `UNKNOWN` and cannot produce a RetryPermit.
