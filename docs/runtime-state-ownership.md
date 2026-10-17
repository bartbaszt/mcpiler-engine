# Runtime-state root ownership

Engine keeps per-mount mutable OAuth authority (a rotated refresh secret or a cleared
tombstone) under one durable runtime-state root. Exactly one process may own that root at a
time: two owners could both read a refresh token, both rotate it at the provider, and both
commit a successor, silently discarding one of them.

This document records the exact lock behavior and the filesystem boundary the serving path
and every future mutating verb rely on.

## The lock

- One file per effective root: `.runtime-state-owner.lock`.
- Acquired with a single `FileStream` open (`FileMode.OpenOrCreate`, `FileAccess.ReadWrite`,
  `FileShare.None`). On Linux the file mode is restricted to owner read/write.
- The file is **never deleted**, by design. Unlinking a live lock file on Unix lets a second
  process create and lock a different inode at the same name, which is two owners.
- Released by disposing the handle on normal shutdown, or by the operating system when the
  process terminates - including a forced kill. A crashed owner cannot strand the lease.
- There is no PID marker, no existence test, and no takeover timeout. Ownership is the open
  handle itself, so a check-then-act race is not possible.

## Which root identity the lock protects

The root is normalized before leasing:

1. `Path.GetFullPath`, trailing separator trimmed - so `root/alias-segment/..` and `root`
   are one identity.
2. Directory created if absent.
3. Every path component is resolved through `DirectoryInfo.ResolveLinkTarget` so symlinks and
   junctions in intermediate parents are followed, not just the final segment.

Two mounts that share one physical root therefore contend for one lock; ownership is per
root, never per mount or per slot.

## Filesystem boundary

The lock and the store's atomic replace rely on local-filesystem semantics. Unsupported
locations are refused before any store access or issuer traffic:

- **Windows.** The effective path must be spelled with a local drive letter. A UNC spelling
  (`\\server\share\...`) is refused before it is probed at all. Mapped network drives under a
  letter cannot be distinguished from local drives without volume inspection, which the
  Engine architecture boundary forbids; using a mapped network drive for the runtime-state
  root is outside the supported deployment boundary. Deploy the root on a local fixed disk.
- **Linux.** The effective path's longest mount entry in `/proc/self/mountinfo` must name a
  known local filesystem type: `ext4`, `xfs`, `btrfs`, `zfs`, `f2fs`, `tmpfs` or `overlay`.
  A network mount (NFS, CIFS, ...), FUSE location, or any unrecognized type is refused.
- Any other operating system is refused.

## What this does not claim

- The lock serializes mutating owners only. Readers of committed data files do not take the
  lease and are unaffected.
- Rename-based atomic replacement of record files is a separate property proved by the
  runtime-state store's own tests; the lease proves single ownership, not storage format.
