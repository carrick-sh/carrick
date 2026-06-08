# carrick asymmetric-behavior & coverage-gap audit (2026-06-02)

**Method.** Clean-room source audit (no Linux source) of the syscall translation
layer, hunting for *asymmetric* behavior — a paired/symmetric operation where one
half is implemented and the counterpart is missing, stubbed, hardcoded, leaks, or
silently diverges from Linux. The four shapes the repo's own bug history shows:

- **set-without-get** — you can `set*` an attribute but `get*` returns the default/old value.
- **write-without-read** — data accepted on write but dropped / not readable back.
- **alloc-without-free / setup-without-teardown** — resource acquired but never released (leak).
- **save-without-restore** — state saved on one edge but not restored on the paired edge.

Each item below is a fix target: `file:line` + the owning symbol (line numbers drift;
the symbol name does not), carrick-now vs Linux-expected, a fix direction, the owning
probe to add, and severity. `✓ verified` = confirmed at the cited site during this audit;
unmarked items are from the subsystem sweep and worth a 2-minute re-confirm before fixing.

**The rule (from `docs/conformance-coverage.md`):** every gap-fix ships with its owning
probe. The RED probe is the deliverable; landing the fix flips it GREEN. The
"Recommended probes" table at the bottom lists the probe each HIGH item needs.

Legend: severity HIGH = silent wrong-success or a table-stakes feature that errors ·
MED = real divergence, narrower blast radius · LOW = cosmetic / documented-intentional.

---

## Status (2026-06-02 — implementation pass)

**All 19 closed.** This branch lands H1, H2, H4, H5, H6 and all 13 MED (M1–M13),
each with a RED→GREEN host test (named inline below). **H3 was fixed independently
on `origin/main`** (`ddbd535 mem: reclaim the per-alias L3 table on high-VA
munmap`, via `PageTableManager::unmap_aliased`) — when this branch rebased onto it,
my parallel duplicate (a `free_aliased`/`free_alias_range` of the same design) was
dropped in favor of the canonical version; only my M11 (overlay-slot free on
munmap) was re-applied on top. Gate after rebase: see the test sweep below.

**Verification — full stack, including the Docker oracle on real HVF (2026-06-02):**
1. Host-harness tests: the in-process `SyscallDispatcher`/`LinearMemory` integration
   suite + lib unit tests — all green.
2. **Real HVF**: all 8 new probes built static (`aarch64-unknown-linux-musl`) and run
   under a codesigned `carrick run-elf` — every assertion `=true`, exit 0. So the
   fixes hold on the actual vCPU/trap path, not just the dispatch harness.
3. **Docker-oracle diff**: the same 8 probes run under `docker run --platform
   linux/arm64` and diffed line-for-line vs carrick — **8/8 MATCH, 0 DIFF.** This
   RESOLVES the earlier oracle-sensitivity caveats: **M5** (SO_RCVBUF 2× doubling)
   and **M9** (`siginfo_t` si_code/si_pid offsets) match Linux exactly.
4. Regression sample: 15 existing probes in the touched subsystems (signals,
   altstack, sigwait, pause/EINTR, execve, fork-mask, epoll, pipe, posix-timers,
   sysvshm, waits) diffed vs the oracle on HVF — **14 MATCH**; the lone DIFF is
   `killtarget`'s negative-pgid delivery, a process-group-context artifact of the
   bare `docker run` (probe runs as PID 1) on a probe this branch does NOT touch,
   not a carrick regression.

M10 and M12 are **documented-intentional** resolutions (the underlying mechanism
is already satisfied by the host — see their entries), not new code paths.

**H3 — fixed on `main` (`ddbd535`); my duplicate dropped on rebase:**
- **Leak #1 (L3-table-pool exhaustion — the `OutOfTables` crash):** FIXED on
  `origin/main` by `PageTableManager::unmap_aliased` (invalidate +
  `reclaim_invalid_tables`, the dual of `try_coalesce`), threaded through
  `GuestMemory::unmap_alias_range` and called from `dispatch/mem.rs`'s high-VA
  munmap branch. Reclaim is gated single-vCPU/PMR for the same break-before-make
  reason `try_coalesce` is (no reliable cross-vCPU `tlbi vmalle1is` broadcast
  under HVF). I had independently built the identical design (`free_aliased` /
  `free_alias_range`); on rebasing onto `main` I dropped mine and kept the
  canonical one. Net: leak #1 is closed; the multi-vCPU TLB-shootdown for full
  multiprocessing-concurrency reclaim remains a tracked follow-on (per `ddbd535`
  / `d8c3879`).
- **Leak #2 (HvfMappedRegion: host mmap + fd) and #3 (alias IPA cursor):** still
  reclaimed only at process teardown — both blocked on arm64 HVF having no
  stage-2 unmap (`dispatch/mem.rs` ~667): the host backing can't be freed nor the
  IPA reused while the stage-2 mapping persists. Bounded per-process; needs a
  stage-2-teardown path + HVF verification. Tracked follow-on.

Test names for the closed items are appended to each entry below as `→ test:`.

---

## HIGH

- [ ] **H1 — `prctl(PR_SET_NO_NEW_PRIVS)` (and KEEPCAPS / CHILD_SUBREAPER / SECCOMP / TIMERSLACK) return EINVAL.** `✓ verified`
  - **Where:** `crates/carrick-runtime/src/dispatch/proc.rs:625` — the `prctl` match catch-all `_ => DispatchOutcome::errno(LINUX_EINVAL)`. The constants aren't even defined in `crates/carrick-abi/src/lib.rs` (grep: only PDEATHSIG/DUMPABLE/NAME/CAPBSET/MEM_MODEL exist).
  - **carrick now:** `prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)` → EINVAL. Neither set nor get exists for any of these options.
  - **Linux:** returns 0; `PR_GET_NO_NEW_PRIVS` returns the stored flag. `NO_NEW_PRIVS=1` is the precondition for unprivileged seccomp (Docker, systemd, Chrome/Go sandboxes).
  - **Odd corollary:** the cBPF seccomp engine works via the `seccomp(2)` syscall (`proc.rs:493`, `this.seccomp.install`), but the equivalent legacy `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)` entry point isn't routed to it.
  - **Fix:** define the constants; add `ProcState` fields for `no_new_privs` / `keepcaps` / `child_subreaper` / `timerslack`; wire SET (store, validate args) + GET (return stored, default timerslack=50000ns); route `PR_SET_SECCOMP` mode-2 into `this.seccomp.install`. NNP is one-way latching (once 1, can't clear) — model that.
  - **Probe:** `prctlnnp`.

- [ ] **H2 — `setrlimit`/`prlimit64` silently ignores every resource except `RLIMIT_NOFILE`; `getrlimit` returns hardcoded values → plausible-but-wrong success.** `✓ verified`
  - **Where:** `crates/carrick-runtime/src/dispatch/time.rs:667` (only `LINUX_RLIMIT_NOFILE` is stored into `io.nofile_soft`; the new limit for every other resource is read + validated then dropped before `return value:0`) and `time.rs:686` (`rlimit_for_resource` hardcodes STACK→8 MiB, NPROC→8192, AS/DATA→infinity, else infinity).
  - **carrick now:** `setrlimit(RLIMIT_STACK, 64MiB)` → 0 (success); `getrlimit(RLIMIT_STACK)` → still 8 MiB. Same for AS/NPROC/DATA/etc.
  - **Linux:** `getrlimit` returns exactly what `setrlimit` stored, per resource.
  - **Fix:** replace the single `nofile_soft` atomic with a per-resource `[LinuxRlimit; 16]` table in a subsystem lock; `setrlimit` writes the slot, `getrlimit`/`prlimit64` reads it. Keep NOFILE wired to the fd allocator's `nofile_soft`. Keep STACK's soft default tied to `LINUX_RLIMIT_STACK_SOFT` (CPython recursion guard, see comment at `time.rs:695`).
  - **Probe:** `rlimitroundtrip` (RED today).

- [ ] **H3 — Stage-1 alias-`munmap` leak (the known open bug) — actually three independent leaks.**
  - **Where (L3 table):** `crates/carrick-mem/src/page_table.rs:629` (`invalidate` → `set_prot_none` clears leaf VALID bits but never frees the empty L3 table); reclaim can't fire because `uniform_block` (`page_table.rs:445`) requires all entries VALID, and `try_coalesce` (`page_table.rs:468`) early-returns under `multi_vcpu`.
  - **Where (host mapping):** `crates/carrick-hvf/src/trap.rs:1827` pushes an `HvfMappedRegion`/`OwnedHostMapping` (host `mmap` + held fd) into `self.mappings`; there is **no** `self.mappings` removal anywhere in `crates/carrick-hvf/` — the `Drop`-based `munmap` never runs.
  - **Where (IPA cursor):** `crates/carrick-runtime/src/dispatch/mem.rs:415` and `mem.rs:590` advance `alias_ipa_next` as a pure bump cursor; no free-list, no reclaim.
  - **carrick now:** churning `mmap(MAP_SHARED,fd)` 4 KiB mappings (multiprocessing SemLock/Pool) climbs the 440-entry L3 pool to cap → `OutOfTables` → "stage-1 page-table pool exhausted". Confirmed by the handoff's `CARRICK_PTPOOL` probe (`in_use` 413→440, `free=0`).
  - **Linux:** `munmap` fully reclaims.
  - **Fix:** on alias `munmap` (distinguish from arena `munmap`, which intentionally keeps PROT_NONE for use-after-free faults): free the emptied L3 table + clear the parent L2 entry back to the pool; `swap_remove` the `HvfMappedRegion` (drops the host mapping + fd) + `hv_vm_unmap`; reclaim the IPA into a free list (`alias_ipa_next` is a bump cursor today). Touches the freshly-merged Rosetta memory path (`6f88583` high-VA munmap, `c205b59` newest-first overlap) — verify against the Rosetta lane + `rosetta-demo` + the gate.
  - **Probe:** `ptpoolchurn` (the existing `mmapprotnonereuse` WIP is adjacent but doesn't reproduce the leak; needs the map+munmap×N MAP_SHARED churn pattern).

- [ ] **H4 — `signalfd` is write-only: `read()` returns EINVAL, the mask is stored but never delivered.**
  - **Where:** store/update mask `crates/carrick-runtime/src/dispatch/signal.rs:646` (`signalfd4`); read rejection `crates/carrick-runtime/src/dispatch/fs.rs:4101` (SignalFd arm → EINVAL). Struct doc at `dispatch/fd_table.rs:346` calls the read/poll path a tracked follow-up.
  - **carrick now:** create signalfd + set mask succeed; `read()` → EINVAL. A program that blocks the signals and reads to receive them hangs/misbehaves.
  - **Linux:** `read()` drains pending masked signals into `struct signalfd_siginfo` records; the fd is pollable.
  - **Fix:** on `read`, drain the thread/process pending set ∩ the signalfd mask, format `signalfd_siginfo` (128 bytes) per signal, honor SFD_NONBLOCK (EAGAIN when empty); register the fd's readiness with the in-mem epoll/poll wake registry so poll/epoll see it. Consume the same `pending`/`pending_siginfos` state the delivery path uses.
  - **Probe:** `signalfdread` (RED until implemented — converts a silent hang into a tracked gap).

- [ ] **H5 — `close()` does not auto-remove a fd from epoll interest sets (stale guest-side bookkeeping).** `✓ verified`
  - **Where:** close path `crates/carrick-runtime/src/dispatch/mod.rs:1516` (`close_open_file_and_free_pty` handles only pty/FIFO teardown); the only `interest.remove` is the explicit `EPOLL_CTL_DEL` at `crates/carrick-runtime/src/dispatch/net.rs:1174`.
  - **carrick now:** closing a fd that was `EPOLL_CTL_ADD`ed (without `EPOLL_CTL_DEL`) leaves the `EpollInterest` entry. The host kqueue side self-heals (closing the host fd drops it from the kqueue), but the guest-side map goes stale: a re-`ADD` of the recycled fd number returns spurious `EEXIST`, and `epoll_pwait` recomputes readiness against the stale `epoll_data` token.
  - **Linux:** closing the last reference to an open file description auto-removes it from every epoll interest list (dup'd fds keep it alive).
  - **Fix:** on the last-ref close (where `close_open_file_and_free_pty` already detects `Arc::strong_count == 1`), walk live epoll instances and remove this guest fd from their interest maps (and drop the host-fd filter if no other guest fd shares it — mirror the DEL survivor-rebind logic at `net.rs:1174`).
  - **Probe:** `epollclosenodel`.

- [ ] **H6 — `SA_RESETHAND` stored and returned via `oldact`, but never honored at delivery (one-shot handlers re-enter).** `✓ verified`
  - **Where:** flag defined `crates/carrick-abi/src/lib.rs:137` (`LINUX_SA_RESETHAND`); it appears **nowhere else** in `crates/`. Delivery (`crates/carrick-runtime/src/runtime.rs` ~2630 and `runtime/fault.rs` ~119) reads only RESTORER/ONSTACK/RESTART/NODEFER.
  - **carrick now:** a handler installed with `SA_RESETHAND` fires every time.
  - **Linux:** the disposition resets to `SIG_DFL` *before* the handler runs (one-shot). `abort()` survives only because libc sets `SIG_DFL` itself.
  - **Fix:** in the delivery path (right where SA_NODEFER mask logic lives, `enter_signal_handler`), if `sa_flags & SA_RESETHAND`, set the handler back to `SIG_DFL` before entering. Also clears `SA_SIGINFO` implicitly per Linux.
  - **Probe:** `saResethand`.

---

## MEDIUM

- [ ] **M1 — `rt_sigsuspend` leaks the armed restore-mask if no handler runs.** `signal.rs:814-852` arms `restore_masks[tid]=original` and leaves the live mask = `suspend_mask`, relying on a subsequent handler entry (`signal.rs:332`, `enter_signal_handler` pops it) to restore. A spurious 5 s-timeout wake, or a wake by a `SIG_IGN`/default-ignore signal (early return at `runtime.rs:2627` skips `enter_signal_handler`), never pops it → the thread runs permanently under the over-broad temp mask. **Fix:** restore the original mask on every `rt_sigsuspend` return path, not only on handler entry.
- [ ] **M2 — `SO_PASSCRED`/`SCM_CREDENTIALS` receive path missing** while `getsockopt(SO_PEERCRED)` works (`net.rs:3058`). `linux_to_host_sockopt` (`support.rs:781`) has no SO_PASSCRED, and recvmsg (`net.rs:3500`) parses only SCM_RIGHTS + IPv6 cmsgs — never synthesizes SCM_CREDENTIALS. Asymmetric AF_UNIX credential passing. **Fix:** accept SO_PASSCRED (store per-fd), and on recvmsg synthesize an SCM_CREDENTIALS cmsg from LOCAL_PEERCRED when the flag is set.
- [ ] **M3 — `MSG_CMSG_CLOEXEC` dropped on received SCM_RIGHTS fds.** `linux_to_host_msg_flags` discards it (`support.rs:755`) and `install_received_host_fd` always uses `fd_flags=0` (`net.rs:663`). **Fix:** thread the flag through and install received fds with FD_CLOEXEC when requested.
- [ ] **M4 — UDP `setsockopt(SO_REUSEADDR)` silently widens to host `SO_REUSEPORT=1`** (`net.rs:2846`), so a later `getsockopt(SO_REUSEPORT)` reads back 1 the guest never set. **Fix:** track the guest's intended SO_REUSEPORT separately from the host-side widening, and return the guest value.
- [ ] **M5 — `SO_RCVBUF`/`SO_SNDBUF` don't replicate Linux value-doubling; AF_UNIX stream buffers force-set to 212992** (`support.rs:789`, `widen_unix_stream_buffers` `support.rs:276`). `getsockopt` returns a value unrelated to what was set. **Fix:** store the guest-set value per-fd and return `2×` it (Linux semantics) regardless of the host's actual buffer.
- [ ] **M6 — AF_NETLINK `getsockopt` hardcoded** (`net.rs:2942`): `SO_TYPE` always `SOCK_RAW` (mislabels a `SOCK_DGRAM` netlink socket), all other options → 0 even after a `setsockopt` no-op accepted SO_RCVBUF/SNDBUF. **Fix:** return the real guest socket type; store + echo the no-op'd buffer sizes.
- [ ] **M7 — `fchownat(fd, "", uid, gid, AT_EMPTY_PATH)` returns 0 without recording the owner** (`fs.rs:6192`). The `fchown` syscall and the named-path `fchownat` both persist correctly; only the AT_EMPTY_PATH form is a no-op. **Fix:** resolve the fd to its path and call `set_owner`, same as `fchown`.
- [ ] **M8 — `F_GETFL` returns creation-only bits** (`O_CREAT`/`O_TRUNC`/`O_EXCL`/`O_DIRECTORY`) that Linux strips at open (`fs.rs:2550`; same leak feeds `/proc/self/fdinfo` at `fs.rs:919`). open stores `flags & !O_CLOEXEC`. **Fix:** mask creation-only bits out of `status_flags` at open (keep only access mode + O_APPEND/O_NONBLOCK/O_DIRECT/O_SYNC etc.). F_SETFL is already correctly masked (`fs.rs:2623`).
- [ ] **M9 — `rt_sigtimedwait`/`sigwaitinfo` writes only `si_signo`** (`signal.rs:1273`, "minimal siginfo"), dropping `si_code`/`si_value` from a queued `rt_sigqueueinfo`, and orphans the entry in `pending_siginfos` (uses `take_pending_in`, not `take_pending_siginfo`). **Fix:** write the full queued siginfo and pop `pending_siginfos[(tid,signum)]`.
- [ ] **M10 — SysV `SEM_UNDO` never tracked/reversed by carrick on guest exit** (`sysv.rs:808` forwards `sembuf` to host `semop`; no undo list). Relies on host-process death lining up 1:1 with guest exit, which isn't guaranteed (exit_group, threads). **Fix:** maintain a per-process undo list keyed on (semid, semnum); replay the negated adjustments on guest process teardown.
- [ ] **M11 — `munmap` of a `MAP_FIXED|MAP_PRIVATE` overlay VA frees only `mem.shared`, never `mem.overlay`** (`mem.rs:644`; overlay slot allocated at `mem.rs:350` `alloc_sourced` + `repoint_private` `mem.rs:363`). Leaks the overlay slot + leaves a stale stage-1 repoint. **Fix:** also call `mem.overlay.free(address.0)` on munmap of an overlay-backed VA.
- [ ] **M12 — `setresgid`/`setregid`/`setgid`/`setfsgid` don't `publish_self` to cred-IPC** while the uid setters do (`creds.rs:423/448/472` publish; gid setters `creds.rs:427-461` don't). Cross-process gid identity is stale. **Fix:** publish the gid side too (or document that the cred-IPC kill-check is intentionally uid-only).
- [ ] **M13 — `sigaltstack(NULL,&old)` from inside a handler never reports `SS_ONSTACK`** and reconfiguring the live alt stack isn't rejected with EPERM (`signal.rs:735-783`; the ucontext stamp at `trap.rs:2993` is correct, but a direct query isn't). **Fix:** track per-tid "handler running on alt stack" state; OR `SS_ONSTACK` into the queried flags and return EPERM on a set while active.

---

## LOW / documented-intentional (recorded; not blocking)

- `shmdt` doesn't unmap the alias VA *and* skips the stage-1 invalidate → leak + use-after-detach still reads the segment (`sysv.rs:475`; documented follow-up). Fixing H3's alias teardown covers the leak half.
- IP/IPv6 multicast group join → `ENODEV` (`net.rs:2876`; documented, libuv RETURN_SKIP).
- `MSG_NOSIGNAL` dropped (`support.rs:752`, never sets SO_NOSIGPIPE); `MSG_ERRQUEUE` → `EAGAIN` (`net.rs:2697`; no error queue). Both documented.
- chmod/chown don't round-trip on the `--fs memory` backend (uid/gid always 0, mode fixed); `--fs host` round-trips via `user.carrick.*` xattrs. Documented tmpfs-like.
- inotify wd never reused (`inotify.rs:190`, monotonic); `IN_MOVED_FROM/TO` cookie always 0 (`inotify.rs:342`) so move-pair correlation fails (partial impl; child events come from snapshot-diff).
- io_uring `POLL_REMOVE`/`ASYNC_CANCEL` → `-EINVAL` (`ioring.rs:751`; documented Phase-1 scope — unknown opcodes error symmetrically via a CQE, the *good* case).
- `process_pending` for a `SIG_IGN` process-directed signal isn't dropped (`signal.rs:485`) → `rt_sigpending` over-reports; real delivery is still gated by the IGN check at dispatch.
- `MREMAP_FIXED` parsed but ignored (`mem.rs:807`, `_new_address` unused — move always bump-allocates).
- `brk` shrink not materialized/zeroed (`mem.rs:244`; single boot-mapped heap, no leak, minor stale-bytes-on-regrow divergence).
- `F_GETPIPE_SZ`/`F_SETPIPE_SZ` accept a pty/FIFO HostPipe as a pipe (`fs.rs:2451`; Linux returns ESPIPE on a tty).

---

## Verified-symmetric (the negative space — these are correct, don't re-audit)

Sockets: `getsockname`/`getpeername` (incl. ephemeral port + AF_UNIX reverse-translate),
`SO_TYPE`/`DOMAIN`/`PROTOCOL`/`ERROR`/`RCVTIMEO`/`SNDTIMEO`, `shutdown`,
`accept4`/`socketpair` flag preservation, SCM_RIGHTS **send**.
Files: full `fcntl` get/set family (`F_GETFD`/`SETFD`, `F_GETFL`/`SETFL`, `F_DUPFD*`,
locks via host fcntl, `F_GETOWN`/`SETOWN`, `F_GETSIG`/`SETSIG`, pipe-sz), `dup`/`dup3`
CLOEXEC, the xattr quartet round-trip, chmod/chown/utimensat/truncate→stat on `--fs host`.
Signals: the register frame (GPR/PC/SP/PSTATE/FPSIMD/`uc_sigmask`) save↔restore,
SA_NODEFER, SIG_BLOCK/UNBLOCK/SETMASK + old-mask, SIGKILL/STOP un-maskable,
RT-queue-N vs std-coalesce, fork/execve mask semantics.
Creds/proc: full `getres[ug]id` triples, `setgroups`/`getgroups`, `capset`/`capget`
(all three sets), wired `PR_*`, scheduler/affinity/priority/ioprio round-trips.
Events/IPC: `eventfd`, `timerfd` (settime↔gettime remaining + read count), epoll
ADD/DEL/MOD + ONESHOT/ET, SysV create↔IPC_RMID and IPC_SET↔IPC_STAT.
Memory: `mremap` (shrink/grow/MAYMOVE), `mprotect` (RW↔RO↔NONE + partial split),
`MADV_DONTNEED` zero-fill, `mem.shared` (`SharedAperture`) alloc/free with reuse —
the correct counter-example to the leaking alias path (H3).

---

## Recommended probes (per "every gap-fix ships its probe")

Each is a `conformance-probes/` line-exact carrick-vs-Linux probe, run by
`cargo test --release --test conformance conformance_probes`. Add the RED probe first;
landing the fix flips it GREEN and it gets a row in `docs/conformance-coverage.md`.

| Probe | Gates | Item |
|---|---|---|
| `prctlnnp` | `PR_SET_NO_NEW_PRIVS` 0→get→1; KEEPCAPS / CHILD_SUBREAPER round-trip | H1 |
| `rlimitroundtrip` | set/get RLIMIT_STACK / AS / NPROC — readback == what was set | H2 |
| `ptpoolchurn` | map+munmap 500× MAP_SHARED 4 KiB file mappings — no `OutOfTables` | H3 |
| `epollclosenodel` | ADD fd, close without DEL, re-open (reuses number), ADD again — no spurious EEXIST | H5 |
| `signalfdread` | block SIGUSR1, signalfd, raise, read one `signalfd_siginfo`, assert `ssi_signo` | H4 |
| `saResethand` | install SA_RESETHAND handler, raise twice — 2nd raise takes default action | H6 |
| `sigsuspendmaskleak` | sigsuspend woken by an ignored signal — original mask restored | M1 |

---

## Suggested fix order

1. **H1 + H2** — small, self-contained, high-impact, low-risk (no Rosetta/HVF surface). NNP unblocks real container workloads; rlimit is a clean per-resource table.
2. **H6 + M1** — both one-site signal-delivery edges.
3. **H5** — moderate (touches the epoll DEL survivor-rebind logic, already exercised by the Go punchlist fix).
4. **H4** — new delivery path; medium.
5. **H3** — biggest correctness win but riskiest (freshly-merged Rosetta memory path); do last, behind the Rosetta lane + `rosetta-demo` + the full gate.
