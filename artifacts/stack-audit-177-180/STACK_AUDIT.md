# Stack audit #177 → #180 (yanhul/aios)

- Audited head: `140c0325258f8428ffb69f51080eae6055fce037` (PR #180). Base of stack: `main` @ `665e73a`.
- Stack: #177 `fix/l6-l3-policy-binding` (7308ed2) → #178 `feat/l6-ed25519-authority` (d8de132) → #179 `feat/l5-event-ledger` (dce15b9) → #180 `feat/l3-l5-identity-binding` (9 commits, 9480659..140c032).
- CI run 45784180164: 3/3 PASS — FACT. Not evidence of production safety.
- Local: full suite at audited head 1053 passed / 24 skipped (VERIFIED). With remediation branch: 1059 passed / 24 skipped (VERIFIED).
- Method: source reading of changed and called code, executable PoCs, repro tests. README / PR descriptions / `artifacts/pr180-remediation/*` were not used as evidence.

## Summary by workstream

| WS | Area | Result |
|---|---|---|
| 1 | L3 WAL integrity | `recovery_binding` and WAL checksums are **unkeyed integrity hashes, not authentication** (F-03, F-04 VERIFIED by PoC). A WAL writer can forge recovered state and force replay of an external effect. |
| 2 | PCB durable runners | `run_pcb_eda_durable.py` **regressed by #180** — every governed step BLOCKs (F-01 VERIFIED). Schematic runner uses intent identity correctly (FACT). No end-to-end test drives either `main()` (FACT). |
| 3 | Ed25519 signer ops | Signer/verifier split is sound at crypto level (FACT). `ci-autonomous-repair` is **structurally BLOCKED** — no permit/attest lifecycle exists (F-05). Claims lack expiry/audience (F-06); trust anchor in repo `vars` (F-07 UNKNOWN). |
| 4 | L5 durability | Roll-forward path escape → arbitrary file write (F-02 VERIFIED, fixed). Dir-fsync errors swallowed (F-11); `.staging` not fsynced (F-10 INFERRED, power-loss only); quarantine unlock unauthenticated (F-12). |
| 5 | Architecture boundary | Checker had false negatives on relative/dynamic imports (F-14 VERIFIED, fixed). After fix current tree has 0 findings in strict mode (VERIFIED) — narrow rule only. |

## WS1 — L3 WAL integrity

- FACT `core/durable_loop.py:280-287`: `_recovery_binding = sha256(canonical_json(identity + receipt + patch + verification + action_result))`. No key, no signer, stored in the same record it protects.
- FACT `core/durable_wal.py:108-109, 217-260`: each WAL record has `sha256(body)` and a `sequence`; no previous-hash chain, no MAC, no external high-water mark.
- FACT `core/effect_identity.py:45-54`: `verify_operation_identity` recomputes identity derivation — detects edits to identity fields only, and is also unkeyed.
- VERIFIED (PoC `wal_attack_poc.py`): forge `validated_state_patch`, recompute binding → `reconcile_in_flight_attempt` applies forged patch and reaches PASS.
- VERIFIED (PoC): remove `in_flight_attempt` → `run_durable_loop` re-invokes `act()` for the same logical op (2 invocations).
- FACT: residual control at recovery = `execution_receipt_validator` + `state_patch_validator` re-run (`durable_loop.py:681-696`). Their strength is workload-specific; for PCB they read artifacts in the runner output dir (INFERRED: same trust domain as WAL).
- Trust boundary: L3 treats L5 (WAL/snapshot) as trusted storage; L6 authority is not consulted on recovery except via the caller-supplied `authorizer` callback. **Anyone with write to the state directory is effectively L3/L6-equivalent.**

Remediation options (not implemented; trust-model change requires owner decision): see NEXT_ACTIONS.md N-03/N-04.

## WS2 — PCB durable runners

Call graph (FACT): `main()` → `LoopPolicy(require_execution_receipt=True, operation_identity=λ…:step-N)` → `run_durable_loop` → intent `EF-…:attempt:1` persisted → `PcbExecutor.act` → `run_kit` → `PcbExecutor.verify` builds receipt → lineage check `durable_loop.py:465` → `validate_execution_receipt` (runner) → `validate_state_patch` → RECEIPT_VALIDATED persist → apply patch.

- F-01: `run_pcb_eda_durable.py:157-158,182-183` (audited head) build receipt ids from `task_id:effect:step`; never equal to canonical intent → BLOCKED always. Schematic runner (`run_pcb_eda_schematic_durable.py:144-149`) reads `in_flight_attempt` — correct.
- Not tested end-to-end (FACT, by grep of tests/): `main()` of both runners; RECEIPT_VALIDATED crash → `reconcile_in_flight_attempt` through a PCB policy; discover_evidence → continuation → pcb.eda@1 redispatch; UNKNOWN receipt path with real kit; `JsonStateStore` WAL replay after a crash mid-run. `tests/test_pcb_eda_durable_runner.py` only covers store recovery and resume identity.
- `pcb-eda-durable.yml` is `workflow_dispatch`, checks out `yanhul/temp`, runs only `tests/test_blocked_continuation.py` then the real kit — it is not a deterministic non-production integration test. Design in NEXT_ACTIONS N-02.

## WS3 — Ed25519 signer operations

- FACT `core/attestation.py`: signer holds `Ed25519PrivateKey`; verifier takes a JSON keyring `{key_id:{public_key,status}}`; `key_id = ed25519:sha256(pub)[:32]` is checked against the key; revoked keys rejected; legacy HMAC v1 rejected; message has domain separator and claims are re-derived from stored contract/permit. Crypto layer: no defect found.
- FACT `core/authority.py:176-199`: `authorize` fails closed when attestation missing/invalid and refuses if signing env var present.
- F-05 why BLOCKED: `ci_repair_apply_attempt.py:76` requires an empty authority dir; `authority()` creates contract (binds run_id/base_sha) + permit and calls `authorize()` in the same process with no signer → missing attestation → `SystemExit("BLOCKED…")`. An external signer cannot attest a permit that does not exist before the job and lives only in `runner.temp`. This is a missing lifecycle, not a missing secret.
- F-06/F-07/F-08/F-09: see FINDINGS.json.

## WS4 — L5 durability

- Commit point (FACT `mutation.py:575-581` post-fix numbering): staged tmp files fsynced → `journal.v2.json.tmp` fsynced → atomic rename = commit → fsync(batch_dir) → per-op rename + fsync(dest dir) → unlink journal → rmtree.
- Classification (FACT): v2 present & digest ok → COMMITTED; v2 bad → CORRUPT_COMMITTED → quarantine; legacy unreadable → AMBIGUOUS_LEGACY → quarantine; none → UNCOMMITTED → discard. Staged-file digest validated before any dest is touched (FACT).
- CAS: `commit_batch(precondition=…)` runs precondition under flock after recovery (FACT). Lock is advisory `flock` on `<parent>/.aios.mutation.lock` (FACT) — cooperative only.
- F-02 fixed: ops must satisfy `realpath(tmp) ⊂ batch_dir` and `realpath(dest) ⊂ aios_dir`, else quarantine; `commit_batch` rejects absolute/escaping `rel_dest`.
- Power loss: **not proven**. Only process-crash tests exist (FACT). F-10 is INFERRED.
- WalStateStore: WAL append fsync + atomic snapshot + parent fsync (FACT); falls back to unauthenticated snapshot when WAL lacks state records (F-15).

## WS5 — Architecture boundary

- FACT: `ci.yml:53-54` runs checker report-only (exit 0 always). Scope: 5 L5 modules, rule "no execution dependency".
- F-14 fixed: relative imports resolved against package path, `from . import x` expanded, `importlib`/`__import__`/`import_module(...)` flagged, one finding per statement.
- Baseline after fix: 0 findings (VERIFIED, `test_boundary_check_current_tree_is_clean_in_strict_mode`). Enforcement plan: NEXT_ACTIONS N-08. Strict mode **not** enabled in this audit.

## Remediation branch (separate from audited PRs)

Branch `audit/stack-177-180-remediation` on top of `140c032`, draft PR targeting `feat/l3-l5-identity-binding`. Commits: repro tests → F-01 fix → F-02 fix → F-14 fix → audit docs. No key, secret, workflow trigger or production config changed.

## Decision

**NEEDS_REMEDIATION** — see bottom of NEXT_ACTIONS.md.
