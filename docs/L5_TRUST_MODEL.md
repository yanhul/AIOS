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
