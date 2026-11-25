# Trusted-host validator provenance

## Threat boundary

`run_governed_execution` treats the Python host process as trusted deployment code. It does not claim to isolate hostile Python code running in that process. A caller that can execute arbitrary Python in-process can replace callbacks, monkeypatch imports, or alter process memory; this mechanism is not intended to stop that attacker.

## Deployment contract

When the governing policy requires execution receipts, the host integration must construct `LoopPolicy` with:

- `deployment_id`: stable deployment/environment identity;
- `deployment_digest`: canonical `sha256:<64 lowercase hex>` digest produced by the deployment/build pipeline;
- both `execution_receipt_validator` and `state_patch_validator` callbacks.

The deployment identity must come from trusted deployment configuration, not model output, policy JSON, or user-controlled request data. AIOS validates its shape but does not independently authenticate the build pipeline that supplied it; that trust is part of the declared host boundary.

## Durable audit record

Before execution, AIOS derives callback provenance from the actual callable objects: module, qualified name, source implementation digest, and source-file digest. It stores this with deployment identity in the durable state under `validator_provenance`. The field is protected from verifier state patches and is compared on resume. A changed deployment digest or callback implementation therefore blocks resume instead of silently continuing under a different validator set.

This record is audit evidence, not a signature or proof of runtime integrity. Its authenticity inherits the trusted-host assumption. Deployments requiring independent attestation must bind the deployment digest to their signed build/release manifest outside this in-process API.

## Receipt authenticity remains separate

Validator provenance does not replace provider receipt authentication. Provider receipts must still pass the existing `AIOS_PROVIDER_KEYRING` / Ed25519 verification path. Missing or invalid provider authentication remains `UNKNOWN`; provenance must never promote it to `OBSERVED`.