# Handoff — Go runtime bring-up on carrick (2026-05-24, session 3)

## TL;DR

A real multithreaded Go HTTP program (`fixtures/go-aarch64-hello`: server
goroutine + client + graceful shutdown; exercises clone/futex/epoll-netpoller/
loopback-TCP/SIGURG-preempt) runs **completely and correctly** under carrick:

- **Single-request demo: 100%.**
- **Concurrent (`-benchmark -c N`): c≤20 solid (5/5 clean); c=32 ~4/6; c=50 ~5/6.**
  **Zero corruption/EL0 faults at any concurrency** — all remaining high-`c`
  failures are `context deadline exceeded` (a residual netpoller-wakeup miss
  under load, see "Open"), not crashes.

Root cause of the original hang (chased for 2 prior sessions as "SIGURG"): a
**lost epoll/netpoll wakeup from an interest-snapshot race**, found via
`GODEBUG=schedtrace` (now forwarded to the guest) + `carrick trace`. Fixed, plus
a chain of per-thread-signal-state and mmap bugs the investigation surfaced.

Guiding principle holds: **Darwin kernel as source of truth** (kqueue, host
pipes, `proc_pid_rusage`, `__ulock`/`os_sync`, lazy HVF IPA).

## Build & test

- **Build (ALWAYS signed — `cargo build` strips the HVF entitlement → HV_DENIED):**
  `./scripts/build-signed.sh`.
- **Unit tests:** `cargo test --release --lib -- --test-threads=1` (**205 pass**;
  run single-threaded — a pre-existing `kqueue_closes_fd_on_drop` fd-recycling
  flake under parallel runs is not a regression).
- **Conformance probes (line-exact vs Docker):** `cargo test --release --test
  conformance`. Local registry on **:5050** (NOT :5000 — ControlCenter).
  `export CARRICK_INSECURE_REGISTRIES=localhost:5050`. New probes this session:
  `netpoll`, `epollpwait`, `ppollsig`, `mmaprecl`, `altstacktid`, `selfraise`,
  `xthreadsig`. Build with `./scripts/build-probes.sh`.
- **LTP differential:** `.claude/skills/ltp-conformance/scripts/ltp-check.sh
  <test>…`. Read via `/ltp-conformance` (count-vs-assertion + Docker-jitter traps
  are real; confirm DIFFs are pre-existing by stashing before blaming a change).
- **`carrick trace` WORKS** (the prior handoff's "broken under sudo" is STALE)
  and now **outlives the spawned child** for custom `-s` scripts, so a
  fast-crashing guest's `tick`/`END` aggregation survives. New USDT probes for
  debugging: `vcpu-fault` (fatal EL0 fault: esr/elr/far/x30/sp), `signal-publish`
  (target_tid/signum/kind), `signal-deliver` (tid/drained-signum). These are
  what cracked the signal bugs. **Always kill stray guests before measuring**
  (`pkill -9 -f run-elf`) — contention produces phantom `context deadline
  exceeded` at any `c`.
- **Reproduce Go demo:** `carrick run-elf --fs host
  "$PWD/fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello"`
  (ABSOLUTE path — relative makes glibc ld.so `_dl_get_origin` assert). Add
  `-- -benchmark -c 10 -n 300` for concurrency. `GODEBUG=schedtrace=500` is
  forwarded to the guest (the differential oracle for scheduler stalls).

## What shipped this session (14 commits on `main`, since `3e1f3f5`)

1. **`fix(epoll): back each epoll instance with a persistent kqueue`** — THE core
   fix. epoll_pwait snapshotted the interest map and parked on a separate
   per-thread io_wait kqueue, so an fd `epoll_ctl(ADD)`-ed by another thread
   while the netpoller blocked was never watched (fd7 in the trace). FreeBSD
   `linux_event` model: `OpenDescription::Epoll` owns an `Arc<Kqueue>`;
   epoll_ctl→EV_ADD/EV_DELETE (EV_CLEAR for EPOLLET, guest fd in udata);
   epoll_pwait drains it + blocks on the instance kqueue's own fd via WaitOnFds.
   Go fixture 5/30 → 80/80. Dropped the buggy host-fd `last_ready` edge-mask.
2. **`fix(trace): outlive the spawned child`** + the 3 probes above.
3. **`fix(mm): satisfy Go's heap-arena reservations`** — 32 GiB lazy arena +
   relocate out-of-window PROT_NONE hints (Go reserves 256 GiB→1.5 TiB) into the
   arena. `feat(mm): reclaim munmap'd arena space` — free-list + zero-on-reuse
   (the "durably" gap). pthread_create-EAGAIN (guest mmap ENOMEM) gone.
4. **`fix(epoll_pwait)` + `fix(ppoll): apply the sigmask during the wait`** —
   `block_signals` on WaitOnFds; `has_unblocked_pending_for`. LTP epoll_pwait01
   line-38 TFAIL→TPASS.
5. **`fix(signal): per-thread sigaltstack`** — global alt stack made every
   thread's SIGURG frame land on one stack → goroutine-stack corruption (the
   c≥20 EL0 faults). Per-tid now.
6. **`fix(signal): per-thread signal mask + pending`** — global mask let one
   thread's `rt_sigprocmask` block a signal for another → cross-thread delivery
   dropped. Per-tid now (handlers stay global).
7. **`fix(epoll): wake epoll on in-memory eventfd readiness`** — Go's netpollBreak
   writes an in-memory eventfd; not host-backed, so the blocked io_wait never saw
   it (c≥32 stall). EVFILT_USER(0) broadcast from write_eventfd. c=32 2/5→4/6.

All keep `cargo test --lib` (205) and `--test conformance` green; signal/epoll/mm
LTP DIFFs verified PRE-EXISTING by stashing.

## Open (each documented in docs/superpowers/specs/2026-05-23-go-bringup-followups-design.md)

- **eventfd host-backed — DONE** (`feat(eventfd): host-back readiness with a
  pipe`): each eventfd owns a non-blocking host pipe (readable iff counter>0);
  host_fd_for_poll returns it so epoll/poll/ppoll/pselect watch it natively via
  EVFILT_READ. Removed reliance on the EVFILT_USER broadcast (kept as belt). Also
  fixes eventfd in poll/select.
- **Residual c≥32 `context deadline exceeded`** (~1–2/8 at c≥20; c=10 8/8; zero
  EL0 faults). The eventfd host-backing CHANGED the signature: it's no longer the
  original "all 10 Ps idle" lost-wakeup (that's fixed). `GODEBUG=schedtrace` now
  shows **2 Ps busy** (`idleprocs=8`, threads=15, `runqueue=0`) making NO
  progress for ~2s, then the 5s deadline + GC fire. So 2 goroutines are RUNNING
  but not progressing — `spinningthreads=0`, so they're not Go's work-stealing
  spinners; they hold a P and run a goroutine that doesn't yield/complete. This
  is a goroutine-park / netpoller-handoff / futex-spin race, **NOT** a simple
  lost wakeup. **Untraceable via `carrick trace`** (passes 4/4 under it — timing
  perturbation); use `GODEBUG=schedtrace` (in-guest). **Next:** figure out what 2
  goroutines run without progress — likely a non-blocking read/connect returning
  an errno that makes Go busy-retry instead of park, OR a netpoll-add/park race
  where a goroutine can't park and spins. Reduce to a probe (N goroutines hammer
  loopback + park/unpark) if possible. Rare + high-`c`; realistic loads (c≤20)
  are ~90%+ with zero corruption.
- **pselect6 sigmask** — ppoll done; pselect6 blocks DIRECTLY in `libc::poll`
  (not WaitOnFds), so it needs the WaitOnFds refactor (also fixes its
  dispatcher-lock starvation).
- **epoll_wait03** EFAULT on a read-only events buffer (guest-mmap-PROT-on-
  copy-out — broad blast radius, niche). **epoll_ctl05** ELOOP nested-epoll
  detection (niche). Both pre-existing.
- **Signal-delivery edge** (not Go-blocking): cross-thread signal to a
  `pthread_join`/futex-blocked thread — `xthreadsig` probe now PASSES after the
  per-thread-mask fix.

## Durable state

- Memory: `project_go_bringup.md` (full session-3 record), `project_ltp_*`,
  `MEMORY.md`.
- Spec: `docs/superpowers/specs/2026-05-23-go-bringup-followups-design.md`
  (+ plans for ppoll/pselect sigmask and mmap reclaim).
