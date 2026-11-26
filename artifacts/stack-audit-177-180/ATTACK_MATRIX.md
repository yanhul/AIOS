# Threat model & attack matrix — stack #177–#180

## Assets
A1 external side effects (provider/kit invocations, repo pushes) · A2 durable L3 loop state & terminal verdict (PASS) · A3 L5 ledger/entity store · A4 L6 permits/attestations · A5 host filesystem outside the store.

## Actors / capabilities
| ID | Actor | Capability |
|---|---|---|
| T1 | Store writer | Write to state dir (`*.wal.jsonl`, snapshot, `.aios/`), e.g. compromised co-located process, malicious CI step, restored backup |
| T2 | Candidate code in CI | Code under repair executing in a job |
| T3 | Repo variable editor | Can change `vars.AIOS_AUTHORITY_TRUSTED_KEYS` |
| T4 | Power loss / kernel crash | Loses un-fsynced metadata |
| T5 | Process crash | Kills process at any instruction |

## Matrix
| # | Actor | Attack | Target code | Control present | Result | Evidence | Finding |
|---|---|---|---|---|---|---|---|
| AT-01 | T1 | Rewrite `validated_state_patch` and recompute `recovery_binding` | `durable_loop._recovery_binding`, `reconcile_in_flight_attempt` | unkeyed sha256; validators re-run | **Succeeds** (forged PASS) | VERIFIED PoC | F-03 |
| AT-02 | T1 | Remove `in_flight_attempt` (append new checksummed WAL record or truncate tail) | `durable_wal`, `run_durable_loop:400` | per-record checksum + sequence | **Succeeds** — effect replayed | VERIFIED PoC | F-04 |
| AT-03 | T1 | Edit identity fields of intent | `verify_operation_identity` | recompute derivation | Blocked unless all derived fields recomputed (trivial) | FACT | F-04 |
| AT-04 | T1 | Rewrite history receipt evidence | `_validate_loaded_state:205-213` | `execution_receipt_validator` per entry | Depends on workload validator | INFERRED | F-03 |
| AT-05 | T1 | Forge `journal.v2.json` with `dest` outside store | `mutation._recover_pending_unlocked` | unkeyed body_digest | **Succeeded** before fix; now quarantined | VERIFIED test | F-02 |
| AT-06 | T1 | Plant `tmp` outside batch dir (read-exfil/move) | same | none before fix | now quarantined | VERIFIED test | F-02 |
| AT-07 | T1 | `touch RESOLVED.json` to clear quarantine | `unresolved_quarantine` | existence only | **Succeeds** | FACT | F-12 |
| AT-08 | T1 | Delete WAL, edit snapshot | `WalStateStore.load` | none | **Succeeds** | FACT | F-15 |
| AT-09 | T1 | Write forged attestation file | `authority.authorize` | Ed25519 verify vs keyring | Blocked without private key | FACT | — |
| AT-10 | T1 | Replay old valid attestation for same permit | `attestation._claims` | none (no expiry/nonce) | Succeeds for that permit indefinitely | FACT | F-06 |
| AT-11 | T3 | Replace trusted keyring with own key | workflow env | repo settings | Likely succeeds; UNKNOWN who holds the right | UNKNOWN | F-07 |
| AT-12 | T2 | Read provider signing keys in apply job and self-sign receipts | `ci_repair_apply_attempt.py:80-81` | trusted/candidate worktree split | Depends on isolation; signer+verifier co-located | INFERRED | F-09 |
| AT-13 | T2 | Run with signing key file but no env var | `signing_material_present` | env check only | Check bypassed | FACT | F-08 |
| AT-14 | T4 | Power loss after dest renames, before `.staging` entry durable | `commit_batch` | fsync(batch_dir) only | Possible partial commit | INFERRED, untested | F-10 |
| AT-15 | T4 | fsync EIO on directory | `_fsync_dir` | swallowed | Commit reported durable | FACT | F-11 |
| AT-16 | T5 | Crash between intent persist and act | `run_durable_loop:450-453` | intent blocks replay | Blocked (fail closed) | FACT + existing tests | — |
| AT-17 | T5 | Crash after RECEIPT_VALIDATED | reconcile path | binding + validators | Recovers without replay | FACT + existing tests | — |
| AT-18 | T5 | Crash mid roll-forward | `_recover_pending_unlocked` | digest pre-check, idempotent rename | Recovers or quarantines | FACT + existing tests | — |
| AT-19 | — | Relative import of `core.effect_authority` from L5 module | `architecture_boundary_check` | — | Missed before fix; now flagged | VERIFIED test | F-14 |

## Integrity hash vs authenticated integrity
- `recovery_binding`, WAL `checksum`, journal `body_digest`, `effect_identity`: **integrity hash** — detects accidental corruption and inconsistent edits; anyone who can write the data can recompute it.
- Ed25519 attestation: **authenticated** — requires the private key; protects A4 only.
- Nothing authenticates A2/A3 at rest. Security of recovery therefore rests on filesystem ACLs (T1 excluded) — this is an ASSUMPTION the code does not state or enforce.
