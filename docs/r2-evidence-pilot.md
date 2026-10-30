# AIOS R2 evidence mirror pilot

This pilot mirrors the three registered-workload Product E2E receipts to Cloudflare R2.
It deliberately keeps the existing GitHub Actions artifact upload and watchdog path unchanged
until an R2-backed consumer has passed an independent recovery test.

## Required repository configuration

Configure these in `yanhul/AIOS`:

- Secret `CLOUDFLARE_API_TOKEN`: scoped to R2 object read/write for the target bucket.
- Variable `CLOUDFLARE_ACCOUNT_ID`: Cloudflare account ID.
- Variable `AIOS_R2_BUCKET`: existing R2 bucket name.

The workflow does not create buckets, change bucket lifecycle, or delete GitHub artifacts.
If configuration is absent, the mirror step is skipped and current GitHub artifact behavior remains.

## Object layout

`evidence/yanhul/AIOS/<run_id>/<commit_sha>/<receipt-name>.json`

A `manifest.json` is written last. It records schema, repository, run ID, attempt,
commit SHA, object keys, byte sizes, and SHA-256 hashes. The workflow then downloads
the manifest and all three receipts from R2 and verifies byte-for-byte integrity.

## Promotion gates

This is a mirror-only pilot. It does not reduce GitHub artifact usage yet.

Do not remove the GitHub artifact upload or change the watchdog consumer until:
1. R2 credentials and bucket are configured.
2. A real workflow run reports `AIOS_R2_EVIDENCE_MIRROR=PASS`.
3. A separate consumer/recovery test reads only the R2 objects and validates manifest,
   repository, run ID, commit SHA, exact receipt set, and hashes.
4. AIOS authority receipt integration is implemented and tested.

No authority policy or capability registry is changed by this pilot.
