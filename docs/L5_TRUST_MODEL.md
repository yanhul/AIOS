# L5 commit engine: trust model (F-03 / F-04 P0)

Scope: `core/mutation.py` (`commit_batch`, `recover_pending`, `inspect_pending`,
`unresolved_quarantine`). This document is the contract; the regression tests in
`tests/test_l5_p0_remediation.py` pin it.

## 1. Attackers

| Attacker | Status | Why |
|---|---|---|
| Different-UID process that can reach the store path | **Defended** | All protected objects are owned by the service euid, mode 0700/0600, verified on every open. Such a process cannot create, replace or read anything under `.staging`, `.quarantine` or `.l5`. If the layout is wrong (e.g. 0777 staging), L5 refuses to run. |
| "Staging writer" from the audit (foreign objects somehow present in `.staging`) | **Defended** | Nothing in `.staging` is ever executed unless the protected state names that batch *and* the SHA-256 of its journal bytes equals the digest recorded in the state *and* the batch inode matches. Untracked entries are quarantined as evidence. |
| Same-UID malicious process | **Not defended** | It can rewrite `.l5/state.json` and all store files directly. No local key changes this: a key the service can read is readable by the same uid, so a local HMAC adds nothing here. Defending this requires an OS privilege boundary (separate service account for L5 writes) or an external signer. That is a deployment/architecture decision, not implemented. |
| Compromised service process / root | **Not defended** | Same reason. |
| Untrusted, network or unusual filesystems (NFS, SMB, FUSE, case-insensitive) | **UNKNOWN** | The engine relies on POSIX `openat`/`renameat`/`fsync` semantics. Case aliases of reserved names are refused by name (casefold) and by inode identity, but those filesystems are not tested. |

ACLs and Linux capabilities are not inspected. Only owner and permission bits are checked. Deployments that grant ACL write access to the store are outside this contract.

## 2. Layout and checks

```
<parent>/.aios.mutation.lock   0600, euid, regular, nlink 1, opened O_NOFOLLOW via the parent dir FD
<store>/                      euid-owned, not group/other-writable
<store>/.staging/             0700, euid, same filesystem as the store
<store>/.l5/state.json        0600, euid, nlink 1, strict canonical JSON  (the trust anchor)
<store>/.quarantine/<id>/     0700 wrappers created by L5; evidence + QUARANTINE.json
```

- **Ancestors** of the store must be owned by root or the euid, and must not be group/other-writable unless sticky.
- **Path walking**: the store path is resolved once, then opened component by component from `/` with `O_NOFOLLOW`. Every later operation is relative to these pinned FDs.
- **Re-validation**: before the commit point, before applying, and before cleanup, the pinned FDs are checked again: name→inode binding, owner, and mode.
- **Legacy layouts**: a pre-existing euid-owned 0755 protected directory is tightened to 0700 explicitly. Group/other *write* bits are never tightened silently; they block.
- **File opens**: regular files are type-checked with `lstat` before `open()` (FIFOs and devices are never opened). They are then opened `O_NOFOLLOW|O_NONBLOCK`, and the inode is compared with the `lstat` result.

## 2a. Store path bootstrap (review fix F4a/F4b)

- The caller's path is never passed to `realpath()` or `os.makedirs()`. It is resolved from `/` one component at a time, each directory opened `O_NOFOLLOW|O_DIRECTORY` relative to an already-validated FD and checked against the ancestor rule (the final one against the store-root rule).
- A symlink is followed only if the directory containing it is already trusted and the link itself is owned by root or the euid (the `fs.protected_symlinks` rule). At most 40 hops. `..` is applied physically to the FD stack (kernel semantics), never lexically.
- A missing component is created with `mkdirat` inside the validated parent, then re-checked: it must still be a euid-owned directory. It then gets mode 0755 via `fchmod`. The standard state directories are created the same way, relative to the root FD.
- Consequence: an attacker-owned or attacker-writable component anywhere in the supplied path (including a symlink planted in such a directory) makes L5 refuse the store before anything is created or written.

## 2b. ACLs and capabilities (review F11)

| Mechanism | Behaviour | Evidence |
|---|---|---|
| Linux POSIX access ACL | For an inode with an ACL, the group permission bits report the ACL **mask**. So any *effective* named-user/group write grant shows as `g+w`, and the existing mode checks refuse it. A grant masked out (mask without `w`) is not effective. | VERIFIED (ext4, tests F11) |
| Linux POSIX default ACL | Inherited entries on objects L5 creates are neutralised: every L5-created object gets an explicit mode (0700/0600/0755/0644), which sets the mask. | VERIFIED (real uid 65534 denied) |
| NFSv4 ACLs, macOS/BSD extended ACLs (`chmod +a`), Windows ACLs, richacl | Not reflected in mode bits; not inspected | UNKNOWN |
| SELinux/AppArmor labels, immutable/append-only attributes | Not inspected | UNKNOWN |
| Processes with `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, `CAP_CHOWN`, `CAP_SYS_ADMIN`, `CAP_LINUX_IMMUTABLE` | Root-equivalent for the store | out of scope (same as root) |

L5 itself needs no capabilities. A service running as root trusts root-owned ancestors and protects nothing against other root processes.

**Known residual: the lock file lives in the store's parent directory.** When a store root sits directly in a shared sticky directory (e.g. `/tmp/<x>` created by `tempfile`), another user can pre-create `<parent>/.aios.mutation.lock`. L5 then refuses (foreign owner): denial of service, not bypass. Stores should not be placed directly in shared directories.

## 3. State machine

Each transition atomically replaces `state.json` (new inode, then fsync of the file and of `.l5`).

| Phase | Meaning | Recovery |
|---|---|---|
| IDLE | no transaction | staging must be empty; any entry is quarantined |
| PREPARED | seq allocated (never reused), batch being written | no destination was written (writes require durable APPLYING). The batch is removed only if it contains nothing but service-owned L5 artefacts; otherwise it is quarantined. |
| COMMIT_POINT | journal published + fsynced; its digest and the batch inode are recorded. **Committed.** | roll forward |
| APPLYING | destination writes may have started | roll forward: verify every op first, then CAS-apply |
| FINALIZED | all destinations durable | remove residue only; never replay |
| CLEANUP | residue removal in progress | remove residue only; never replay |
| QUARANTINED | evidence moved to a wrapper | blocked until operator resolution, then IDLE |

- **Crash between the journal rename and the batch-directory fsync**: still PREPARED, so recovery aborts. The commit point is the state file, not the journal.
- **Failure after the COMMIT_POINT rename** (for example an fsync error): raises `RecoveryIncompleteError` (ambiguous outcome). Recovery decides from what is on disk.

Crash testing (`scripts/l5_recovery_crash_sweep.py`) interrupts the k-th call of every persistence primitive in both `commit_batch()` and `recover_pending()`, using four modes:
- in-process `OSError(EIO)`;
- in-process `BaseException`;
- child `os._exit(9)`: process death without Python cleanup, **not a signal**;
- child self-delivered `SIGKILL`.

After each interruption it runs recovery repeatedly and checks an exact oracle. None of these modes drops the page cache, so **real power loss remains UNKNOWN.**

Commit-sweep oracle (`scripts/l5_commit_oracle.py`, finding F-NEW-01). The state observed right after the fault is classified against the protocol. With the store IDLE at `next_seq = N`, `last_finalized_seq = L` before the commit:

| class (pre-recovery) | phase | next_seq | lf | destination before recovery | after recovery |
|---|---|---|---|---|---|
| NOT_ALLOCATED | IDLE | N | L | OLD | OLD, next_seq N, lf L |
| PREPARED (commit point not reached) | PREPARED | N+1 | L | OLD | OLD, next_seq N+1, lf L |
| COMMIT_POINT (commit point reached) | COMMIT_POINT | N+1 | L | OLD | NEW, next_seq N+1, lf N |
| APPLYING | APPLYING | N+1 | L | each path OLD or NEW; at most one `.<dest>.<hex32>.l5tmp` (see below) | NEW, next_seq N+1, lf N |
| FINALIZED | FINALIZED | N+1 | N | NEW | NEW, next_seq N+1, lf N |
| CLEANUP (cleanup interrupted) | CLEANUP | N+1 | N | NEW | NEW, next_seq N+1, lf N |
| COMPLETED | IDLE | N+1 | N | NEW | NEW, next_seq N+1, lf N |

Non-IDLE classes also require `txn.seq == N`, no quarantine id, journal binding exactly when past PREPARED, and for COMMIT_POINT/APPLYING a staged journal whose sha256 equals the bound digest and whose seq/ops describe this commit. Any other combination fails; a QUARANTINED pre-recovery state is UNKNOWN for this sweep and counts as a failure. Independently of the class, a final OLD tree requires `lf == L` and a final NEW tree requires `lf == N`. Snapshots use `lstat` (symlinks are never followed) and record object type, permission bits, uid/gid and, for regular files, nlink, size and sha256, including directories; they intentionally exclude timestamps, inode/device numbers (new inodes by design), directory size/nlink, xattrs/ACLs/SELinux labels and inode flags. Install temps follow `_apply_op()`: a temp may exist only for a declared payload destination that still holds its prior bytes, only for the op at the crash point (earlier ops NEW, later ops OLD), at most one in total, regular, nlink 1, owned by the service euid/egid; at the created mode (`0600 & ~umask`) its bytes must be a prefix of the canonical NEW payload, at the final mode (`0644`, or prior mode `& 0755`) they must equal it exactly, since `fchmod` runs only after the digest-verified full copy. Payload files must also satisfy an engine-independent policy (regular, 0644, nlink 1, canonical content; directories 0755). `scripts/l5_commit_oracle_sensitivity.py` patches deliberate protocol faults into throw-away copies of the engine and requires the sweep to detect every one.

## 4. Recovery CAS

Each op carries `prior` (digest, or `null` = absent) and `new`. During replay:
- current == `new` → skip;
- current == `prior` → install a new inode (copy, digest-verified, fsync, rename, fsync parent);
- anything else → quarantine.

All ops are verified before any install (all-or-nothing). The check is repeated immediately before each rename. That re-check is best-effort against writers outside L5.

## 5. Quarantine resolution

An entry is resolved only when all of the following hold:
- the wrapper directory is euid-owned and not group/other-writable;
- it contains `RESOLVED.json`: a regular file, nlink 1, owned by the euid or root, not group/other-writable.

The wrapper is created 0700 by L5, so only the service uid or root can write that record. Evidence content is never trusted, executed or chowned.

Operator procedure: inspect `.quarantine/<id>/evidence` and `QUARANTINE.json`, then, as the service account, run `install -m 600 /dev/null .quarantine/<id>/RESOLVED.json`.

## 6. Destination permission policy

- A replaced file keeps its prior mode, minus group/other write and minus setuid/setgid/sticky bits.
- A new file is created 0644 and a new directory 0755, both set with `fchmod` (independent of umask).
- Destination directories must be euid-owned and not group/other-writable.
- Hard-linked destinations are refused.

## 7. Platforms

- **Linux**: tested.
- **macOS, FreeBSD, NetBSD**: untested (UNKNOWN). The required primitives exist, and `EMLINK`/`EFTYPE` are mapped.
- **Windows and any platform without POSIX `dir_fd`/`O_NOFOLLOW`/`fchmod`**: unsupported. Every L5 entry point raises `L5PlatformUnsupportedError`, and there is no path-based fallback.

## 8. Compatibility

- Journal format 3 (`journal.v3.json`); v2 and legacy journals are never executed.
- A store upgraded from the pre-P0 engine with residue in `.staging` has that residue quarantined on first use and blocks until an operator resolves it.
