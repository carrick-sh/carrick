# carrick syscall emulation map

Carrick traps each guest `svc #0` at EL1, decodes `x8`/`x0..x5`, and dispatches
to a Rust handler that re-expresses the Linux syscall in terms of Darwin host
primitives — there is no guest Linux kernel. This document enumerates which of
the aarch64 generic syscalls are emulated, at what fidelity, and what host
mechanism backs each category.

The authority for *which* numbers exist and their support level is the static
table `AARCH64_SYSCALLS` in
[`crates/carrick-hvf/src/syscall.rs`](../crates/carrick-hvf/src/syscall.rs) —
every assigned aarch64 number `0..=462` is listed (gaps `244..=259`,
`295..=402`, `415` are unassigned on aarch64 and intentionally absent), so
`lookup_aarch64()` can name *any* syscall a guest issues. The table is the input
to the `compat-report` reporter and to the per-syscall handler grouping.

## Support levels → quality

Each row carries a `SupportLevel`, which maps to the **Quality** column below:

| `SupportLevel` | Quality | Meaning |
|---|---|---|
| `BringUp` | **Emulated** (Full or Partial) | Routed to a real handler. *Full* = ABI-complete for the cases workloads hit; *Partial* = the common path works, edges/flags are stubbed or deferred (judged here from the handler + `compat_note`). |
| `Planned` | **Stub** | Recognized by name but routes to `ENOSYS` today. Only two: `execveat` (#281) and `clone3` (#435) — the latter is partially wired for the clone/fork modes carrick supports (`compat_note_for_aarch64`). |
| `Deferred` | **Not implemented** | `ENOSYS`, surfaced by its real name (e.g. `io_uring_register`, `userfaultfd`) so the compat report shows `userfaultfd`, not `unknown 282`. |

**~210 syscalls are actively emulated** (`BringUp`), 2 are `Planned` stubs, and
the remaining 127 table rows are `Deferred`. Counts are from the table itself
(`rg 'SupportLevel::BringUp' crates/carrick-hvf/src/syscall.rs | wc -l`).

> [!NOTE]
> "Deferred → ENOSYS" is deliberate and load-bearing: glibc/musl and most
> runtimes treat an `ENOSYS` from an optional syscall as "feature absent" and
> fall back. Returning `ENOSYS` by *name* (rather than crashing on an unknown
> trap) is what lets `userfaultfd`, `io_uring_register`, `landlock_*`, the
> `*_time64` variants, etc. degrade gracefully.

## Darwin backing at a glance

Handlers are grouped by `handler_for_aarch64()` into the `SyscallHandler`
subsystems, each dispatched through a narrow borrow of one subsystem lock on the
BKL-free `SyscallDispatcher` (`crates/carrick-runtime/src/dispatch/mod.rs:929` —
`io: IoState`, `mem: Mutex<MemState>`, `proc: Mutex<ProcState>`,
`creds: Mutex<CredState>`, `signal: Mutex<SignalState>`, `sysv: Mutex<…>`). The
host mechanism per category:

| Category | Darwin backing |
|---|---|
| File & directory I/O | Native host fds via the VFS mount table; per-fd `OpenDescription` behind an `RwLock`; `sendfile(2)`, `copy_file_range`→host copy, FIFOs via `mkfifoat` + non-blocking `HostPipe`. |
| Memory | `hv_vm_map` of a per-process aperture + a bump arena (`mmap_next`); `mprotect`/`munmap` re-permission/unmap; `brk` tracks a guest heap end. |
| Process & thread | `libc::fork` for `fork`/`clone(SIGCHLD)`; a thread-flag `clone` spawns a native `pthread` running a **fresh per-thread HVF vCPU** over the shared address space; `wait4`/`waitid` over host `waitpid` + a kqueue `EVFILT_PROC` park. |
| Scheduling / futex | PRIVATE futex → in-process `parking_lot_core` park/unpark; SHARED (cross-process, `MAP_SHARED`) futex → `os_sync_wait_on_address` (the public macOS 14.4+ physical-page-keyed primitive, successor to the private `__ulock`). |
| Signals | Real host signals + a Linux↔macOS signum translation table (`SIGNUM_XLATE` in `crates/carrick-hvf/src/host_signal.rs:47`); guest handlers entered by building a Linux sigframe, returned via the `rt_sigreturn` trampoline. |
| Time & timers | Darwin clocks (`clock_gettime_nsec_np`, `gettimeofday`); a guest vDSO `vvar` fast page seeds `__kernel_clock_gettime`; `timerfd`/`setitimer` ride a kqueue `EVFILT_TIMER`. |
| Networking & sockets | Native BSD sockets, with AF/sockaddr translation in `crates/carrick-abi` + `dispatch/net`; `AF_NETLINK` is synthesized locally (no host socket). |
| IPC | `eventfd2` userspace counter + epoll-shim wake; SysV shm/sem/msg backed by host files under `/tmp/carrick-shm`, host POSIX sems, host msg queues. |
| Multiplexing | `epoll_*` → Darwin `kqueue`; `pselect6`/`ppoll` → an internal `WaitOnFds` over kqueue; `io_uring` serviced in-process over the same kqueue readiness path. |

The rest of this document is the per-category table. Within each, **Quality** is
*Emulated (Full)* / *Emulated (Partial)* / *Stub* / *Deferred*; `nr` is the
aarch64 number. For invariant-by-invariant proof of behavior, cross-reference
[conformance-coverage.md](conformance-coverage.md) (the owned-probe gate). For
the trap/dispatch path itself, see
[architecture-overview.md](architecture-overview.md).

---

## File & directory I/O

Backed by native host file descriptors routed through the unified VFS mount
table; the rootfs is composed from OCI layers in memory (or on host APFS via
cap-std with `--fs host`). Each open file is an `OpenDescription` behind an
`RwLock` so concurrent vCPUs share it safely.

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `openat`, `close`, `read`, `write`, `lseek` | 56,57,63,64,62 | Emulated (Full) | host `openat`/`close`/`read`/`write`/`lseek` via VFS | Stdio fds 0/1/2 special-cased; `O_DIRECTORY`/`O_NOFOLLOW`/`O_DIRECT` aarch64 constants are the corrected octal values. |
| `readv`, `writev`, `pread64`, `pwrite64`, `preadv`, `pwritev` | 65–70 | Emulated (Full) | host vector/positional I/O | Zero-length ops never touch the guest buffer; access-mode validated (`read` on `O_WRONLY` → `EBADF`). |
| `openat2` | 437 | Emulated (Partial) | host `openat` + `open_how` validation | Flags/mode passed through; `RESOLVE_*` path-restriction enforcement deferred. |
| `dup`, `dup3`, `fcntl`, `close_range` | 23,24,25,436 | Emulated (Full) | host fd-table ops | `dup` allocates lowest-free fd incl. a closed 0/1/2; `F_SETFL O_NONBLOCK` propagates to the host fd; `F_GETLK`/`F_SETLEASE` recorded per-description. |
| `pipe2` | 59 | Emulated (Full) | host `pipe` + flag fix-up | `O_NONBLOCK`/`O_CLOEXEC`/`O_DIRECT` honored; `FIONREAD` forwards to the host fd. |
| `getdents64`, `getcwd`, `chdir`, `fchdir` | 61,17,49,50 | Emulated (Full) | host dir read + cwd tracking | |
| `newfstatat`, `fstat`, `statx`, `statfs`, `fstatfs` | 79,80,291,43,44 | Emulated (Full) | host `fstatat`/`fstat`/`statfs` | `fstat == fstatat(path) == statx(AT_EMPTY_PATH)` agree (apt-cache gate). |
| `mkdirat`, `unlinkat`, `symlinkat`, `linkat`, `renameat`, `renameat2`, `mknodat` | 34,35,36,37,38,276,33 | Emulated (Full) | host dir-entry ops via VFS resolve | Directory-modify DAC + sticky-bit + setgid inheritance enforced; `mknod(S_IFIFO)` makes a real FIFO. |
| `readlinkat`, `truncate`, `ftruncate`, `fallocate` | 78,45,46,47 | Emulated (Full) | host equivalents | |
| `faccessat`, `faccessat2`, `fchmod`, `fchmodat`, `fchmodat2`, `fchown`, `fchownat` | 48,439,52,53,452,55,54 | Emulated (Full) | host access/mode/owner ops | Guest file mode persisted in a `user.carrick.mode` xattr (fork-coherent); setgid-clear on unprivileged owner. |
| `setxattr`…`flistxattr`, `removexattr` family | 5–13, 14–16 | Emulated (Partial) | host xattr syscalls | get/set/list/remove round-trip; xattr **removal** is reported unsupported for bring-up on some paths (`compat_note` #14–16). |
| `fsync`, `fdatasync`, `sync`, `syncfs`, `sync_file_range`, `fadvise64`, `flock` | 82,83,81,267,84,223,32 | Emulated (Full) | host flush/advise; `flock` is real host advisory locking | `sync_file_range` validates flags/range then best-effort host flush; `flock` cross-fd/cross-process conflicts are real. |
| `sendfile`, `copy_file_range`, `splice` | 71,285,76 | Emulated (Full→Partial) | Darwin `sendfile(2)`; host read/write copy | `sendfile` access-mode validated; `splice`/`tee`/`vmsplice` are partial — `vmsplice`/`tee` are explicit bootstrap `ENOSYS` stubs (`compat_note` #75/#77). |
| `utimensat`, `inotify_init1`/`add_watch`/`rm_watch`, `ioctl` | 88,26–28,29 | Emulated (Partial) | host `utimensat`; host fd ioctls | `ioctl` covers the terminal/`FIONREAD`/sizing set workloads use, not the full ioctl surface. |
| `memfd_create`, `cachestat`, `sync_file_range` | 279,451,84 | Stub/Deferred | — | `memfd_create` (#279) and `cachestat` (#451) are `Deferred` in the table; the conformance probes exercise emulated paths added later — treat the table's `SupportLevel` as authoritative for the report. |

**Deferred in this category:** `mount`/`umount2`/`pivot_root`/`chroot`,
`quotactl`, `name_to_handle_at`/`open_by_handle_at`, the new-mount API
(`open_tree`, `move_mount`, `fsopen`/`fsconfig`/`fsmount`/`fspick`,
`mount_setattr`, `statmount`/`listmount`), `fanotify_*`, `preadv2`/`pwritev2`,
and the `*_time64` fs variants (`utimensat_time64`, `pselect6_time64`,
`ppoll_time64`). The 32-bit-time variants are unreachable from a 64-bit aarch64
guest.

## Memory

A per-process guest aperture is `hv_vm_map`'d once at boot; `mmap` carves
sub-ranges from a bump arena (`mmap_next`), with lazy zero-fill of pristine
pages (`mmap_dirty_high` guards the munmap-lowers-the-cursor reuse hazard).

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `mmap` | 222 | Emulated (Full) | bump arena over the `hv_vm_map` aperture; `MAP_SHARED` file → host `MAP_SHARED` of the real file | Multi-page `MAP_SHARED`-file alias mappings work (HV_ERROR isolation); EBADF beats EINVAL on a bad-fd file mapping. |
| `munmap`, `mremap`, `mprotect` | 215,216,226 | Emulated (Full) | unmap / grow-in-place / re-permission | `mremap`-grow preserves contents (apt DynamicMMap path); `munmap` requires page-aligned addr. |
| `brk` | 214 | Emulated (Full) | guest heap-end tracking in the aperture | |
| `madvise`, `mincore`, `msync`, `mlock`/`munlock`/`mlockall`/`munlockall` | 233,232,227,228–231 | Emulated (Partial) | advisory / host `msync` / no-op locks | `MADV_HUGEPAGE`/`NOHUGEPAGE` return 0 (advisory, never an error). |
| `fadvise64` | 223 | Emulated (Partial) | host `posix_fadvise` | Out-of-range advice → EINVAL; pipe → ESPIPE. |

**Deferred:** `swapon`/`swapoff`, `mbind`/`get_mempolicy`/`set_mempolicy`/
`migrate_pages`/`move_pages`/`set_mempolicy_home_node` (NUMA), `userfaultfd`,
`mlock2`, `pkey_*`, `remap_file_pages`, `process_madvise`, `memfd_secret`,
`map_shadow_stack`, `mseal`.

## Process & thread lifecycle

`fork` and `clone(SIGCHLD)` are `libc::fork`; a thread-creating `clone` spawns a
native `pthread` that brings up its **own** HVF vCPU over the shared guest
address space. The process tree is mirrored on the macOS host so PID/PPID,
reparent-to-init, and `wait4`/`waitid` status all match Linux semantics.

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `clone` | 220 | Emulated (Full) | `libc::fork` (process) or `pthread` + fresh per-thread vCPU (thread) | Flag-consistency validated: `CLONE_THREAD` without `CLONE_VM\|CLONE_SIGHAND` → EINVAL. |
| `clone3` | 435 | **Stub/Partial** | partially wired to `clone` modes | `Planned`; strict `args_size`/flag/stack validation, then the supported clone/fork modes proceed, else EINVAL/ENOSYS (`compat_note` #435). |
| `execve` | 221 | Emulated (Full) | re-exec the ELF loader in-process | Resets caught handlers→SIG_DFL, keeps SIG_IGN, preserves mask + pending + sigaltstack. |
| `execveat` | 281 | **Stub** | — | `Planned`; routes to `ENOSYS` today (`compat_note` #281). |
| `exit`, `exit_group` | 93,94 | Emulated (Full) | thread/process teardown | |
| `wait4`, `waitid` | 260,95 | Emulated (Full) | host `waitpid` + kqueue `EVFILT_PROC` park; SA_RESTART restart logic | Awaited-child exit never spurious-EINTRs; `waitid` fills CLD_EXITED/CLD_KILLED siginfo + WNOWAIT. |
| `getpid`/`getppid`/`gettid`, `getpgid`/`setpgid`/`getsid`/`setsid` | 172,173,178,155,154,156,157 | Emulated (Full) | host pid/pgrp accessors over the process mirror | `/proc/self/status` Pid/Tgid agree with `getpid`/`gettid`; orphan reparents to PID 1. |
| `set_tid_address`, `set_robust_list` | 96,99 | Emulated (Partial) | recorded per-thread | `set_robust_list` validates `len == 24`; no robust-futex death cleanup. |
| `prctl` | 167 | Emulated (Partial) | per-process state | `PR_SET_DUMPABLE`/`NO_NEW_PRIVS`/`KEEPCAPS`/`CHILD_SUBREAPER`/`TIMERSLACK`/comm round-trip. |
| `pidfd_open`, `pidfd_send_signal` | 434,424 | Emulated (Partial) | host pid handle + signal | `pidfd_open` sets FD_CLOEXEC. |
| `capget`/`capset`, `seccomp`, `personality`, `membarrier`, `rseq`, `ptrace` | 90,91,277,92,283,293,117 | Emulated (Partial) | per-process model / no-op-accept | `ptrace` Phase 1: guest BRK/step/HW-debug deliver SIGTRAP; `ptrace(2)` op surface itself is otherwise `ENOSYS`. `unshare`/`reboot` accepted in a degraded form. |
| `getrusage` | 165 | Emulated (Full) | Darwin `getrusage` + `task_info` | HVF guest CPU is folded in via wall-time-in-`hv_vcpu_run` (not in host rusage). |

**Deferred:** `acct`, `kexec_load`/`kexec_file_load`, `init_module`/
`finit_module`/`delete_module`, `add_key`/`request_key`/`keyctl`, `bpf`,
`perf_event_open`, `process_vm_readv`/`writev`, `kcmp`, `setns`,
`pidfd_getfd`, `process_mrelease`, `landlock_*`, `lsm_*`, `get_robust_list`
(#100 is `Deferred` in the table though the `robustlist` probe exercises an
errno-contract path).

## Scheduling & futex

PRIVATE/anonymous futexes park in-process via `parking_lot_core`
(`dispatch/mod.rs` `futex_threaded` + `unpark_requeue`); a futex on a genuine
`MAP_SHARED` page is an inter-process rendezvous and uses
`os_sync_wait_on_address` (`crates/carrick-host/src/ulock.rs`), the public macOS
14.4+ physical-page-keyed primitive that supersedes the private `__ulock`
`UL_COMPARE_AND_WAIT_SHARED` op.

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `futex` | 98 | Emulated (Full) | PRIVATE → `parking_lot_core`; SHARED → `os_sync_wait_on_address` | WAIT/WAKE/WAIT_BITSET/CMP_REQUEUE/REQUEUE; `FUTEX_WAKE(INT_MAX)` returns exactly N; shared CMP_REQUEUE degrades to wake-all (spurious-wake-tolerant). |
| `sched_getaffinity`/`sched_setaffinity`, `getcpu`, `sched_yield` | 123,122,168,124 | Emulated (Full) | Darwin `hw.ncpu`/affinity, `sched_yield` | Real cpu count + affinity. |
| `getpriority`/`setpriority`, `ioprio_get`/`ioprio_set` | 141,140,31,30 | Emulated (Partial) | per-process nice model | nice clamped to [-20,19]; non-root nice-lower → EPERM. |
| `sched_setparam`/`getparam`/`setscheduler`/`getscheduler`/`get_priority_max`/`get_priority_min`/`rr_get_interval` | 118–121,125–127 | Emulated (Partial) | constant model (`SCHED_OTHER`) | Probe-owned Linux-conformant constants, though several rows read `Deferred` in the table — the report reflects the table; behavior is exercised by `schedparam`/`schedprio`. |
| `sched_getattr` | 275 | Emulated (Partial) | zeroed `SCHED_OTHER` sched_attr | `Deferred` in table; validation path probe-owned. |

**Deferred:** `sched_setattr` (write side), `futex_waitv`, the new
`futex_wake`/`futex_wait`/`futex_requeue` (#454–456) and `futex_time64`.

## Signals

Guest signal handling rides real host signals. A Linux↔macOS signum translation
table (`SIGNUM_XLATE`, `crates/carrick-hvf/src/host_signal.rs:47`) maps numbers
in both directions; on delivery carrick builds a Linux sigframe on the guest
(alt) stack and the handler returns through the `rt_sigreturn` trampoline
(glibc-aarch64 leaves `sa_restorer=0`, so carrick supplies it).

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `sigaltstack` | 134,135,136,132 | Emulated (Full) | per-thread disposition/mask/altstack state | SIGKILL/STOP → EINVAL; per-thread sigaltstack not clobbered across threads. |
| `rt_sigreturn` | 139 | Emulated (Full) | sigframe pop / mask restore | The trampoline that unblocks the whole LTP `tst_test` framework. |
| `kill`, `tkill`, `tgkill`, `pidfd_send_signal` | 129,130,131,424 | Emulated (Full) | host signal + signum xlate + process mirror | Cross-process & cross-thread delivery; permission model (root→any, non-root cross-uid→EPERM). |
| `rt_sigqueueinfo`, `rt_sigsuspend`, `rt_sigtimedwait` | 138,133,137 | Emulated (Full) | queued siginfo + interruptible kqueue park | SA_SIGINFO `si_value` payload propagates; `rt_sigtimedwait` fills si_code(SI_QUEUE)+si_pid. |
| `signalfd4` | 74 | Emulated (Partial) | fd-flag surface + read-drain | SFD_CLOEXEC/SFD_NONBLOCK honored; `read()` drains a pending masked signal into `signalfd_siginfo`. |
| `getitimer`/`setitimer` | 102,103 | Emulated (Full) | kqueue `EVFILT_TIMER` on the signal pump → SIGALRM/SIGVTALRM/SIGPROF | Fires in busy-wait + forked child. |

**Deferred:** `restart_syscall` (#128), `rt_tgsigqueueinfo` (#240 — though the
`tgsigqueue` probe exercises an emulated path), `rt_sigtimedwait_time64`.

> [!NOTE]
> `WCOREDUMP(status)` is synthesized (the 0x80 bit) for the Linux core-dumping
> signal set even though macOS's default `RLIMIT_CORE=0` strips it from the host
> wait status. Death-by-signal maps to `WIFSIGNALED`/`WTERMSIG`.

## Time & timers

Darwin clocks back the clock family; a guest vDSO `vvar` data page seeds
`__kernel_clock_gettime` so the hot path stays in-guest (no trap). `timerfd` and
the interval timers ride a kqueue `EVFILT_TIMER`.

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `clock_gettime`, `clock_getres`, `clock_nanosleep`, `gettimeofday` | 113,114,115,169 | Emulated (Full) | Darwin clocks; vDSO `vvar` fast page for the hot read | Monotonic non-decreasing across busy-wait. |
| `nanosleep` | 101 | Emulated (Full) | interruptible host sleep | SIGALRM EINTRs the wait. |
| `times` | 153 | Emulated (Full) | Darwin process-time accounting | |
| `timerfd_create`/`settime`/`gettime` | 85,86,87 | Emulated (Full) | kqueue `EVFILT_TIMER`, pollable as an fd | |
| `clock_settime`, `settimeofday`, `clock_adjtime`, `adjtimex` | 112,170,266,171 | Emulated (Partial) | EPERM (no CAP_SYS_TIME) | Unprivileged set → EPERM, matching Linux. |
| `timer_create`/`gettime`/`settime`/`delete`/`getoverrun` | 107–111 | Emulated (Partial) | per-process timer registry + fallback delivery thread | SIGEV_SIGNAL only; SIGEV_THREAD → ENOTSUP. (Table marks these `Deferred`; the `posixtimers` probe owns the emulated path.) |

**Deferred:** every `*_time64` clock/timer variant (#403–411) — unreachable from
a 64-bit guest.

## Networking & sockets

Native BSD sockets, with address-family and `sockaddr` translation between Linux
and macOS layouts in [`crates/carrick-abi`](../crates/carrick-abi/src/lib.rs)
and `dispatch/net/support.rs` (`AF_INET6` is 10 on Linux, 30 on macOS;
`sockaddr` field order differs). `AF_NETLINK` has no host equivalent and is
synthesized locally to satisfy glibc's routing-table audits (`__check_pf`).

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `socket`, `socketpair` | 198,199 | Emulated (Full) | `libc::socket`/`socketpair`; AF/type/proto translated | AF_UNIX/INET/INET6 native; AF_NETLINK synthesized. |
| `bind`, `listen`, `connect`, `accept`, `accept4` | 200,201,203,202,242 | Emulated (Full) | native BSD socket ops + sockaddr xlate | |
| `getsockname`, `getpeername` | 204,205 | Emulated (Full) | native + reverse sockaddr xlate | Output-pointer validation (NULL → EFAULT, negative `*addrlen` → EINVAL). |
| `sendto`/`recvfrom`, `sendmsg`/`recvmsg`, `sendmmsg`/`recvmmsg` | 206,207,211,212,269,243 | Emulated (Full) | native send/recv; `MSG_DONTWAIT`/non-blocking honored | `MSG_OOB` urgent data wakes epoll as `EPOLLPRI`; `MSG_ERRQUEUE` with no queued error → EAGAIN. |
| `setsockopt`, `getsockopt` | 208,209 | Emulated (Partial) | native, with option-name/value translation | `getsockopt` reports guest-set values (SO_RCVBUF/SNDBUF doubling, SO_REUSEPORT); some option names are oracle-sensitive. |
| `shutdown` | 210 | Emulated (Full) | native `shutdown` | |
| AF_NETLINK (`socket`/`sendto`/`recvfrom` on a netlink fd) | 198 etc. | Emulated (Partial) | locally synthesized rtnetlink | `RTM_GETROUTE` dump returns ≥1 `RTM_NEWROUTE` then `NLMSG_DONE`; unprivileged ICMP ping socket works. |

**Deferred:** `recvmmsg_time64` (#417).

## IPC

`eventfd2` is a userspace 64-bit counter whose readiness change broadcasts a
wake to every epoll/poll blocked on it (`dispatch/epoll_shim.rs`). SysV objects
are backed by host files/primitives so they survive `fork` coherently: shared
memory under `/tmp/carrick-shm/<key>` (inode = shmid), semaphores via host POSIX
sems, message queues via host queues.

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `eventfd2` | 19 | Emulated (Full) | userspace counter + epoll-shim wake | Semaphore mode + poll/read/write. |
| `shmget`, `shmat`, `shmdt`, `shmctl` | 194,196,197,195 | Emulated (Full) | host file under `/tmp/carrick-shm` (`MAP_SHARED`) | Cross-process coherence after fork; `shm_nattch`/`shm_ctime` tracked; IPC_RMID/IPC_STAT/SHM_STAT/SHM_INFO. |
| `semget`, `semctl`, `semop`, `semtimedop` | 190,191,193,192 | Emulated (Partial) | host POSIX semaphores + Linux-bound validation | `nsems > SEMMSL(32000)` → EINVAL; SETVAL range [0, SEMVMX] enforced. |
| `msgget`, `msgctl`, `msgsnd`, `msgrcv` | 186,187,189,188 | Emulated (Partial) | host message queues + ipc64_perm fill | `msgctl(IPC_STAT)` fills key/mode/owner. |

**Deferred:** POSIX message queues (`mq_open`/`mq_unlink`/`mq_timedsend`/
`mq_timedreceive`/`mq_notify`/`mq_getsetattr`, #180–185) and their `*_time64`
variants.

## Multiplexing (epoll / poll / select / io_uring)

Linux readiness multiplexing maps onto Darwin `kqueue`. An `epoll` instance is a
kqueue; `epoll_ctl` registers `EVFILT_READ`/`EVFILT_WRITE`; `epoll_pwait` waits
the kqueue with an `EVFILT_USER` kick for non-host-backed fds (eventfd/timerfd).
`pselect6`/`ppoll` go through an internal `WaitOnFds`; `io_uring` is serviced
in-process over the same kqueue readiness path plus `pread`/`pwrite`.

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `epoll_create1`, `epoll_ctl`, `epoll_pwait` | 20,21,22 | Emulated (Full) | Darwin `kqueue` + `kevent` | EPOLLET/EPOLLONESHOT/EPOLLEXCLUSIVE; `close()` auto-removes interest; empty interest set sleeps interruptibly. |
| `pselect6`, `ppoll` | 72,73 | Emulated (Full) | `WaitOnFds` over kqueue + sigmask gating | `nfds < 0` / invalid timespec → EINVAL; sigmask blocks/unblocks the interrupting signal. |
| `io_uring_setup`, `io_uring_enter` | 425,426 | Emulated (Partial) | in-process ring over kqueue readiness + `pread`/`pwrite` | NOP/READ/WRITE/READV/SEND/RECV data path; `IORING_SETUP_SQPOLL` rejected (no SQ-poll worker) so libuv falls back. |

**Deferred:** `io_uring_register` (#427), `epoll_pwait2` (#441), `io_setup`/
`io_destroy`/`io_submit`/`io_cancel`/`io_getevents`/`io_pgetevents` (the older
AIO interface, #0–4/#292).

## Misc / security / sys-info

| Syscall(s) | nr | Quality | Darwin backing | Notes |
|---|---|---|---|---|
| `uname`, `sysinfo` | 160,179 | Emulated (Full) | host info + synthetic Linux fields | `uname` reports the macOS host short name as the guest hostname (`--net=host` behavior; UTS-ns groundwork). |
| `getrandom` | 278 | Emulated (Full) | Darwin RNG | |
| `getuid`/`geteuid`/`getgid`/`getegid`, `setuid`/`setgid`/`setre*`/`setres*`/`setfsuid`/`setfsgid`, `getgroups`/`setgroups`, `getresuid`/`getresgid` | 174–177,146,144,145,143,147,149,151,152,158,159,148,150 | Emulated (Partial) | per-process credential model | `setfsuid`/`setfsgid` return the previous value; cred changes published to `/tmp/carrick-cred-<pid>` for cross-process kill checks. |
| `getrlimit`/`setrlimit`/`prlimit64` | 163,164,261 | Emulated (Partial) | per-process rlimit state | `prlimit64` (#261) emulated; `getrlimit`/`setrlimit` (#163/#164) are `Deferred` in the table but exercised through the `prlimit64`/`rlimitroundtrip` paths; invalid resource (≥16) → EINVAL. |
| `umask`, `sethostname`/`setdomainname`, `vhangup` | 166,161,162,58 | Emulated (Partial) | per-process / host | `sethostname` → EPERM (correct under `--net=host`). |

**Deferred:** `syslog`, `lookup_dcookie`, the LSM/landlock surface, and the
remaining unassigned/reserved numbers.

---

## How to read this against the live table

- To name any number a guest issued: `lookup_aarch64(nr)` →
  `Syscall { name, support, handler, compat_note }`.
- To regenerate the BringUp/Planned/Deferred split from source:

  ```sh
  rg 'SupportLevel::BringUp'  crates/carrick-hvf/src/syscall.rs | wc -l
  rg 'SupportLevel::Planned'  crates/carrick-hvf/src/syscall.rs
  rg 'SupportLevel::Deferred' crates/carrick-hvf/src/syscall.rs | wc -l
  ```

- To see what a *specific workload* actually exercises (and which calls fell
  through to `ENOSYS`), run the compat reporter, which aggregates the USDT
  probes at the dispatch boundary:

  ```sh
  carrick compat-report -- /path/to/guest-binary args…
  ```

> [!IMPORTANT]
> The `SupportLevel` in the table is the source of truth for the compat report
> and for "is this ENOSYS today?". A handful of rows here are noted as `Deferred`
> in the table while a conformance probe exercises an emulated code path added
> after the table row was last set (e.g. `memfd_create`, `cachestat`, several
> `sched_*` and `timer_*` numbers). Where they disagree, the table governs what
> the *reporter* claims; the probe governs what *behavior* is gated. Treat any
> such divergence as a TODO to reconcile the `SupportLevel`.

## See also

- [../README.md](../README.md) — quickstart, the HVF trap deep-dive, and the
  crate layout.
- [architecture-overview.md](architecture-overview.md) — the `svc`→`hvc` trap
  path, stage-1 identity paging, the BKL-free dispatcher, and per-thread vCPUs.
- [conformance-coverage.md](conformance-coverage.md) — the owned-probe gate:
  one deterministic carrick-vs-Linux probe per ABI invariant.
- [conformance-testing.md](conformance-testing.md) — how to run and interpret
  the differential suites and the compile-time table guard.
- [diagnostics-and-debugging.md](diagnostics-and-debugging.md) — `carrick
  trace`, the event ring, `carrick-lldb`, and the diagnostic env vars.
