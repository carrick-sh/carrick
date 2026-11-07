## 1722: x86: serve fd-backed MAP_PRIVATE in CPL0 through the shared MapPrivate handler and file-fault supply

https://github.com/carrick-sh/carrick/issues/1722

State when read: open.

**What fails:** on x86_64 carrick (KVM), every dynamic binary stops in the loader. glibc's `ld.so` maps `libc.so.6` with fd-backed private mappings (captured at `MSR_LSTAR`: `mmap(0, 0x13cb, PROT_READ, MAP_PRIVATE, 3, 0)` and `mmap(0, 0x212d90, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 4, 0)`), and CPL0 refuses them. `/bin/echo` reports `libc.so.6: failed to map segment from shared object`, and Python can't find `libpython3.12.so.1.0`. Found by #1718 (part of #1714), at main `bba3165192`.

**Why:** x86 CPL0 has no retained private-file source service binding, its fault entry supplies no file slots, and its physical grant handler rejects any file-backing identity. ARM serves the same calls through native host-file staging, the **shared** `MapPrivate` handler and the shared file-fault supply.

**Acceptance:** x86 serves fd-backed `MAP_PRIVATE` (read-only and later COW-written) mappings through the **same** shared handler and file-fault supply ARM uses, differing only in page-table format and fault-entry mechanics (one lane). Witness on real KVM: `/bin/echo ok` prints `ok`, and the loader maps `libc.so.6`. Any later loader calls (`readlinkat` 267, `mprotect`, ...) are tracked on #1714.

Code first (AGENTS.md): start as a draft PR whose body carries a short design note. Flag any lock order that spans crates for the independent review.

## 1756: x86: give CPL0 the same ring IPC venue as ARM (in-zone readv/writev/read/write)

https://github.com/carrick-sh/carrick/issues/1756

State when read: open.

**What:** x86 has no ring IPC venue, so calls the ring's IPC family claims for in-zone objects (pipes and other in-zone fds) can't be served on x86: `writev` stays a counted ENOSYS on x86 (main's `x86_writev_remains_counted_enosys_under_strict_ring_first` invariant), while ARM serves them in ring. #1718 had to drop x86 `writev` from the host crossing for exactly this reason. The x86 dynamic loader writes diagnostics with `writev`, and pipelines need in-zone pipe I/O.

**Acceptance (one lane, AGENTS.md):** x86 gets the **same** ring IPC venue ARM uses, through the shared `carrick-pipe-core` / `carrick-fd-core` paths, with x86 code limited to trap-frame and ISA mechanics. `read`, `write`, `readv` and `writev` on in-zone pipes are served in ring on x86, and still settle as counted ENOSYS for anything the venue doesn't own. No host crossing for in-zone objects. Witnesses on real KVM: a two-process pipe with `writev` and `readv` moves bytes exactly once; and `x86_writev_remains_counted_enosys_under_strict_ring_first` is updated, with an oracle line, so x86 `writev` on an in-zone pipe is now **served** while a non-venue fd stays counted.

Part of #1714; one-lane parity with ARM.

