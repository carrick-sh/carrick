# closure-v5 — LTP long-tail attribution

**Date:** 2026-08-18
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Artifact:** source `575c9288d`, binary
`c6e35353d915389714cdc5c5a60827eab822bdbfea444b79a67b83b205b9fb01`,
CDHash `5ba76e5055d1b86fbd5bff82af230a22c3f0b4a6`, LC_UUID
`8A340FEC-EE19-30E4-8A4E-836D8F3504E1`, entitlement and `__dof_carrick` present.

LTP phase of `closure-v5`: **110 non-match suites**, 1,463 diverging rows.
`ltp-futex_cmp_requeue01` alone is 989 of those (attributed separately in
`../2026-08-18-futex-requeue-admission/`); this report covers the remaining
**474 rows**.

Nothing here is fixed yet. Every item names the evidence it rests on. The four
items marked **verified** below were re-checked against the source and the raw
transcripts directly, because each either changes a shipped behaviour or
changes what the gate itself is allowed to claim.

## Gate-integrity items — these decide what the measurement is allowed to say

### The crash-core extractor fabricates evidence (verified)

`893be523f` appends a core summary to a suite that died on a signal. It reads
`/tmp/core` out of the shared `--fs host` scratch without checking the core
belongs to this run, so it attributes a **stale** core to whichever suite dies
next. Byte-identical summaries — `bytes: 20832256, pid: 6, comm: "python3",
signal: 11, fault_address: 24` — are appended to `ltp-mmap04`, `ltp-kill03` and
`ltp-setrlimit06`, and `kill03` did not die that way at all: it died on a Rust
panic that printed its own abort banner.

This is worse than a missing diagnostic, because it reads as a real core and
will send the next investigator into CPython. Fix by making the core path
per-run, or by refusing any core whose mtime precedes the run's start.

### Five oracle rows are load artifacts, and the cache contains its own disproof (verified)

`ltp-select02` (18 rows), `ltp-epoll_pwait03` (16), `ltp-epoll_wait02` (4),
`ltp-pselect01` (2), `ltp-pselect01_64` (2) — **42 rows** — all show
`carrick = success (every assertion passes)` against `docker = failure`, with
every oracle failure at `tst_timer_test.c:314: … slept for too long`.

The committed cache holds, for the same suite and the same declaration, rows
that both pass and fail:

| suite | passing cached row | failing row used by closure-v5 |
|---|---|---|
| `select02` | 14/14 success | closure-v3: 5/14, 9 failed |
| `epoll_pwait03` | 14/14 success | closure-v3: 6/14, 8 failed; closure-v1: 5/14, 9 failed |
| `epoll_wait02` | 7/7 success | closure-v3: 5/7, 2 failed; closure-v1: 2/7, 5 failed |
| `pselect01` | 7/7 success | closure-v1 and v3: 6/7, 1 failed |
| `pselect01_64` | 7/7 success, **and closure-v1 7/7** | closure-v3: 6/7, 1 failed |

They differ only in `parser_profile`, which is a parser determinant and cannot
manufacture a TFAIL — LTP's totals come from its own `Summary:` block. The
failure count is not even reproducible for one declaration (9 vs 8, 5 vs 2),
and `pselect01_64` passes under one profile and fails under another.

So these are Docker-side timing artifacts from a loaded box. Per AGENTS.md the
oracle is the deviant side here. **Re-measure the five rows serially on a quiet
host with `--oracle-fill` and commit the rewrite.** No carrick work.

`ltp-futex_wait05` is the counter-example and must NOT be filed with them: all
four of its cached arm64 rows are 7/7 success, so the oracle is stable and
carrick's `futex_wait` really does overshoot on 3 of 7 sampled durations.

## Guest-reachable runtime abort (verified)

`ltp-kill03` is one row and the highest-severity item in the tail. The raw
transcript carries the only abort banner in all 1,478 LTP files:

```
======== CARRICK GUEST ABORT [pid 82438] ========
attempt to negate with overflow
  at crates/carrick-runtime/src/dispatch/signal.rs:1178
carrick: FATAL — panic in syscall 129 handler on vCPU tid 5
```

`signal.rs:1178` is `ProcessGroupId::from_abi_positive(-pid)` with `pid: i32`
(`signal.rs:1163`). A guest calling `kill(i32::MIN, sig)` negates `i32::MIN` and
panics, taking the entire guest down from one unprivileged syscall. `-pid` must
be `pid.checked_neg()`, lowering the overflow to `ESRCH`.

## `process_vm_readv`/`writev` now read and write the WRONG address space (verified)

`96cd97bf6` replaced an honest blanket `EFAULT` with a foreign-mm
implementation, and the implementation resolves the remote VA against the wrong
owner. This is a regression in kind, not degree: the syscall now reports success
and moves the wrong bytes.

```
process_vm_readv02.c:56: TFAIL: child 1: expected string: test,
                                received string: … IG_DNOTIFY=y
process_vm_readv03.c:110: TPASS: process_vm_read() returned 1024
process_vm_readv03.c:133: TFAIL: child_read: 1021 incorrect bytes received
process_vm_writev02.c:62: TPASS: … process_vm_writev … returned 100000
process_vm_writev02.c:43: TFAIL: child 0: found 100000 differences
```

`IG_DNOTIFY=y` is a tail fragment of `CONFIG_DNOTIFY=y` — kconfig text living in
the **caller's own** mm. So the transfer falls back to the caller's view at the
peer's VA instead of authenticating through the peer's live stage-1 translation
and exact owner generation, which is the domain rule AGENTS.md states. 36 rows,
and a truthful `EFAULT` would be strictly better than the current lying success
until the owner keying is right.

## Clusters, ranked by rows recovered

Attributed by a read-only agent from the raw transcripts and the source; the
line citations are its own and are worth re-checking at fix time.

| # | rows | suites | root cause |
|---|---:|---|---|
| C1 | 40 | `ioctl_pidfd01-06` | `PIDFD_GET_INFO` unimplemented (no arm anywhere). The recorded oracle contradiction is resolved: the fresh oracle answers fully, and `madvise12`'s "requires kernel 6.13" TCONF corroborates a LinuxKit kernel bump. Unblocked. |
| C3 | 36 | `process_vm_*` | wrong address space, above |
| C4 | 27 | `add_key01/02`, `keyctl05`, `request_key03` | `keyring.rs:80` registers only `keyring` and `user`, so eight probed types answer ENODEV before the payload copy |
| C5 | 23 | `madvise10/12/02` | advice whitelist (`mem.rs:6367`) lacks `MADV_WIPEONFORK/KEEPONFORK` and `MADV_GUARD_INSTALL/REMOVE`; the ABI constants do not exist. `WIPEONFORK` needs real per-VMA fork semantics, not a stub |
| C6 | 20 | 7 suites | six missing `/proc/sys/**` leaves in `SYSCTL_TABLE` (`vfs/proc.rs:571`): `fs/lease-break-time`, `kernel/keys/root_maxkeys`, `kernel/printk`, `net/ipv4/conf/lo/tag`, `kernel/domainname`, `kernel/sched_rr_timeslice_ms`. Highest rows per line of code in the tail |
| C10 | 16 | `name_to_handle_at02/03` | both syscalls `Deferred`; 10 of the 16 rows are pure errno ordering |
| C11 | 16 | `timer_settime01/02`, `timer_create01` | `timer_settime(t, 0, NULL, NULL)` returns EFAULT where Linux returns EINVAL — one errno clears 12 rows |
| C8 | 12 | `sched_rr_get_interval01/02/03` | hardcoded `{0,0}` under a doc comment the oracle disproves, plus `pid < 0` validated after the existence probe |
| C12 | 13 | `bind04`, `sendto02` | no SCTP; LTP raises `EPROTONOSUPPORT` to `tst_brk(TCONF)` which aborts the 10 remaining variants |
| C14 | 10 | `fcntl31`, `fcntl31_64` | `O_ASYNC` owner state machine exists but no readiness edge ever delivers SIGIO (`fs.rs:7809` says so) |
| C15 | 10 | `clone301`, `setrlimit06` | the wait4 restart decision never consults the delivered signal's `SA_RESTART` flag — closes the last open item of `plan_cross_process_signals` |
| C9 | 8 | `clone303`, `madvise09`, `mmap22`, `process_madvise01` | cgroup `mount()` is ENOSYS; present `/sys/fs/cgroup` read-only as the oracle does rather than implementing cgroups |
| C16 | 8 | `mremap05/06` | `MREMAP_FIXED` relocation returns -1 |
| C17 | 8 | `pidfd_getfd01/02` | deliberately ENOSYS, but the stub's stated reason ("needs a host helper to reach another process's fd table") is stale under HVPatch |

Two suites report `failure` with **zero** diverging rows and are invisible to any
row-count scan: `shmctl02` and `shmget04` pass every assertion and still fail,
because a teardown `shmctl(IPC_RMID)` TWARNs EPERM — root is not overriding the
creator-uid check. `msgstress01` is the third, from `msgmni` being declared as 8
(`vfs/proc.rs:611`) against Linux's 32000.

Two same-totals/different-assertion suites were checked specifically and are
**real behaviour differences, not id-scheme artifacts**: `memfd_create04`
(carrick accepts all nine `MFD_HUGETLB` size encodings because `fs.rs:13630`
admits the whole `HUGE_BITS` field unvalidated; Linux accepts only sizes it has
an hstate for) and `read02` (unaligned `O_DIRECT` falls back to buffered I/O
where the oracle returns EINVAL). The id scheme double-counts the two sides of
one difference, so the row counts are inflated 2x — the findings are not.

## Highest-value unattributed item

`ltp-mmap04` (12 rows) is a **silent guest death**, not an empty result: stdout
is 0 bytes, stderr ends after two TPASSes with no `Summary:` and no abort
banner, having cleared both `PROT_NONE` cases and died on the first mapping with
a non-zero prot. Re-run it alone under `carrick debug lldb-run` attached to the
**carrier**, and ignore the appended core summary — it is the stale-core bug
above.
