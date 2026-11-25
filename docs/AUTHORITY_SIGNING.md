# AIOS Authority Signing (Ed25519) — Phase 2

## Threat model
Before: one HMAC secret (`AIOS_AUTHORITY_ATTESTATION_SECRET`) both issued and verified permit
attestations. Every process that could verify (runtime, repair worker, 7 CI steps) could also
forge an attestation for any permit.

After:

| Role | Holds | Can | Cannot |
|---|---|---|---|
| Authority signer (`scripts/aios_authority_signer.py`) | Ed25519 private key file (`AIOS_AUTHORITY_SIGNING_KEY_FILE`, 0600) | attest valid permits whose contract, capabilities and policy resolve | run workloads |
| Execution verifier (`authorize()`, gateway) | public keyring (`AIOS_AUTHORITY_TRUSTED_KEYS`) | verify | sign; also refuses to authorize if signing material is configured in its process |
| GitHub Actions | public keyring only (`vars.AIOS_AUTHORITY_TRUSTED_KEYS`) | verify | sign — no private key is provisioned there |

## Attestation format (version 2)
`{attestation_type, version: 2, algorithm: "Ed25519", key_id, contract_id, permit_id, issuer, signature}`.
Signed bytes: `"AIOS-EXECUTION-PERMIT-ATTESTATION-V2\0" + canonical_json(all fields except signature)`.
The verifier re-derives the claims from the persisted contract/permit, requires exact schema,
version 2 and algorithm `Ed25519` (no negotiation; HMAC/none/other names rejected), a
well-formed `key_id = "ed25519:" + sha256(raw_pubkey)[:32]` that is active in the keyring, and a
valid 64-byte signature.

## Trusted keyring
```json
{"version": 1, "keys": {"ed25519:<32 hex>": {"public_key": "<64 hex raw key>", "status": "active|revoked"}}}
```
Each key_id must match its public key. Unknown statuses, malformed entries, an empty or missing
keyring fail closed.

## Provisioning (operator-run; nothing here is generated or deployed automatically)
1. On the authority signer host, as its service account:
   `python scripts/aios_authority_signer.py keygen --out /etc/aios/authority-signing.pem`
   (refuses to overwrite; file created 0600). It prints only the public keyring entry.
2. Put that entry into `AIOS_AUTHORITY_TRUSTED_KEYS` for runtimes and into the GitHub
   repository **variable** (not secret) `AIOS_AUTHORITY_TRUSTED_KEYS`.
3. Run the signer with `AIOS_AUTHORITY_SIGNING_KEY_FILE` set; never set it on runtimes or in CI.

## Rotation / revocation
1. Generate the new key; add it as `active` alongside the old one.
2. Re-issue outstanding permits: `sign --permit-id P --reissue` with the new key.
3. Mark the old key `revoked` (attestations by it are then rejected); later remove it.
Compromise: mark `revoked` immediately, then re-issue.

## Migration from HMAC (cutover = merge of this change)
- After cutover, `authorize()` rejects every HMAC-SHA256 / version-less attestation with
  "legacy HMAC attestation rejected after Ed25519 cutover". There is no fallback.
- Existing stores: run `migrate --aios-dir D` in the signer process. It re-issues only permits
  whose contract/capability/policy still resolve; others are reported `BLOCKED` and stay unusable.
- Remove the `AIOS_AUTHORITY_ATTESTATION_SECRET` GitHub secret after cutover.

## Known consequence
`ci-autonomous-repair.yml` creates permits inside GitHub Actions. With no private key there,
those permits stay unattested and the apply step exits `BLOCKED` until an external signer
attests them (a signing service/queue is not part of this change).

## Not established by this change
- That production runs the signer on a separate host/service account (deployment property).
- OS-level protection of the key file on Windows (mode check is POSIX-only).
- Attestation expiry/freshness (permits have no `expires_at`; revocation is key-level only).
- HSM/KMS-backed keys.
