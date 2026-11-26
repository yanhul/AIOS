# Remaining gaps — not verifiable in this audit

| ID | Gap | State | Why not verified | What would verify it |
|---|---|---|---|---|
| G-01 | Power-loss durability of L5 commit and WalStateStore | UNKNOWN | Only process-crash tests exist; no block-device fault injection | dm-flakey / `CrashMonkey`-style harness or LazyFS on Linux CI runner |
| G-02 | Who can edit `vars.AIOS_AUTHORITY_TRUSTED_KEYS`; whether an Environment with reviewers protects it | UNKNOWN | Repo settings not in source; REST settings not audited | Admin export of repo/org variable permissions and environment rules |
| G-03 | Whether any external authority signer exists or is planned to run | UNKNOWN | No deployment in repo; `scripts/aios_authority_signer.py` is a CLI only | Owner statement + runbook |
| G-04 | Strength of production `execution_receipt_validator`s outside PCB | UNKNOWN | Only PCB runners audited for this path | Inventory of all `LoopPolicy(require_execution_receipt=True)` callers |
| G-05 | Real Altium Audit Kit behaviour (`run_kit`) under the fixed runner | UNKNOWN | Not invoked (no production provider calls allowed); stubbed in tests | Non-production `workflow_dispatch` (NEXT_ACTIONS N-02) |
| G-06 | Whether L5 effect ledger (`core/effect_authority.py`) dedupes a replayed effect from AT-02 at provider boundary | INFERRED no (not on `run_durable_loop` path) | `effect_authority.py` (1174 lines) only partially traced | Trace + test driving gateway adapter with dropped intent |
| G-07 | Isolation of candidate code from `AIOS_PROVIDER_SIGNING_KEYS` in repair jobs | INFERRED partial | Requires runtime env inspection of jobs | Job-level env dump in a sandboxed dispatch run |
| G-08 | Windows semantics (`_fsync_dir` no-op, `msvcrt` lock spin) | UNKNOWN | Linux-only run | `windows-process-tree.yml`-style job running L5 crash tests |
| G-09 | CI result on the remediation head | PENDING | Requires CI on pushed head | Check run on `audit/stack-177-180-remediation` head |
| G-10 | Historical commits of #177/#178 individually green | UNKNOWN | Only #180 head CI given; per-PR head CI not re-checked | CI runs on 7308ed2, d8de132, dce15b9 |

Rules applied: nothing above is upgraded to VERIFIED; CI PASS is not treated as safety evidence.
