# `wait4`/`waitid` child-exit reap races (the `go build <cgo>` wedge)

Investigation of the `go build` hang on cgo programs (`TestCoroCgoCallback`,
`go-runtime` full suite). Two distinct bugs in carrick's blocking child-wait
path were found. **Bug 1 (the hang) is FIXED.** **Bug 2 (ECHILD under a fork
storm) is FIXED.**

## TL;DR

- The Go toolchain spawns child compilers (`cgo`, `gcc`→`cc1`/`as`, `compile`,
  `link`) and `wait4`/`waitid`-s each. Carrick's blocking child-wait
  (`crates/carrick-hvf/src/io_wait.rs::wait_proc_exit`) parks on a kqueue
  `EVFILT_PROC`/`NOTE_EXIT`.
- **Bug 1 — lost `NOTE_EXIT` → wait4 hangs forever (FIXED).** If the child exits
  in the TOCTOU window between the guest `wait4`'s `waitid(WNOHANG)` pre-check
  (child still alive) and the `EVFILT_PROC` registration, the child is already a
  zombie when the knote arms, so `NOTE_EXIT` never fires for the past exit. The
  park loop's 50 ms timeout slice only re-checked *signals*, never re-polled the
  child — so the parent stranded forever on a reapable zombie. A single lost reap
  stalls the whole build (`go` then spins in its scheduler waiting on the stuck
  child); `GOMAXPROCS=1` removes the multi-thread redundancy that usually masks
  it, making it reproduce 3/3.
  **Fix:** `wait_proc_exit_kqueue` now also polls
  `waitid(P_PID, pid, WEXITED|WNOWAIT|WNOHANG)` on each slice (mirroring the
  existing `wait_proc_exit_fallback`), so a missed edge can never strand the
  parent. `NOTE_EXIT` remains the fast wake. Verified: `GOMAXPROCS=1 go build`
  of `runtime/testdata/testprogcgo` went 3/3 HANG → 3/3 OK.
- **Bug 2 — ECHILD under a `fork`→`_exit`→`wait4` storm (FIXED).** Even with bug 1
  fixed, a rapid storm made a guest blocking `waitpid(pid)` return `-1/ECHILD`
  where Linux returns the child pid. The original pump-reap hypothesis was wrong:
  a focused `carrick trace` showed the failing guest `wait4(1025, ..., 0)` returned
  ECHILD without any host `wait4`/`waitid` call. Root cause: the PID namespace
  member table had 1024 slots and never freed a child slot after terminal wait.
  `register_child` still returned a monotonic ns-pid after the table was full, but
  `wait4(ns_pid)` could not translate it back to a host pid and returned ECHILD.
  **Fix:** terminal `wait4`/`waitid` reaps now unregister the namespace member
  slot after computing the guest-visible ns-pid, and the NsSupervisor tracks the
  host pid armed per slot so reused slots get fresh `EVFILT_PROC` watches.

## How it was diagnosed (tooling that worked)

The chain that localized it, from the top symptom down — useful to repeat:

1. `ps -o pid,ppid,stat,%cpu,time` over time on the guest tree: distinguished a
   busy-spin (`go` at ~100–200% CPU, climbing `time`) from a truly parked child
   (frozen CPU time, `state=SN`). The spinner is a *consequence*; the frozen
   child is the cause.
2. Guest **`SIGQUIT` goroutine dump** (`kill -QUIT <go-host-pid>`; Go prints all
   goroutine stacks to its stderr): showed `goroutine [syscall] waitid ←
   blockUntilWaitable ← Cmd.Wait ← Builder.cgo` and `main [WaitGroup.Wait]`. The
   authoritative "what is every goroutine blocked on" view. (It also exits the
   process, so re-repro after.)
3. **carrick-lldb event ring + host backtraces** (`scripts/carrick_lldb.py`,
   `carrick eventring` + `thread backtrace all`) on the frozen child: the host
   stack `kevent ← wait_proc_exit` and a ring of just `EXEC` then
   `FORK child_pid=N` pinned it to a blocked child-wait. Zero perturbation.
4. `ps -o stat` on the awaited child pid showed **`ZN <defunct>`** — a zombie the
   parent never reaped: a *lost exit notification*, not a stuck child.
5. Differential discriminators on the real build localized the trigger:
   `-p=1` OK, `-p=4` OK, **`GOMAXPROCS=1` HANG** — i.e. a lost-wakeup race that
   multi-M Go masks, not "too much concurrency".

## Reproducers

Real build (deterministic for bug 1; run inside the go-conformance image):

```sh
CARRICK_INSECURE_REGISTRIES=localhost:5005 \
  ./target/release/carrick run --raw --fs host \
  localhost:5005/carrick-go-conformance:1.24 /bin/sh -c '
    cd /usr/local/go/src/runtime/testdata/testprogcgo
    GOMAXPROCS=1 go build -p=1 -o /tmp/x.$$ . && echo OK || echo FAIL'
```

Bug 2 — committed focused conformance probe:

```sh
scripts/build-probes.sh
scripts/run-probe.sh waitexitstorm
```

Before the fix it reliably diverged once the namespace table crossed 1024
sequential children (`reaped_ok=false ... err=10`). After the fix:

```text
MATCH waitexitstorm
  all_reaped=true
```

## Bug 2 — confirmed root cause

- The guest `wait4` handler translates positive namespace pids before host
  waiting: `crates/carrick-runtime/src/dispatch/proc.rs::wait4`.
- The failing trace showed `wait4(1025, ..., 0)` returned ECHILD before any host
  wait call, proving the failure was in namespace translation, not zombie theft.
- `crates/carrick-runtime/src/namespace/pid.rs` kept a fixed 1024-slot member
  table and never freed slots after a successful terminal wait. The monotonic
  ns-pid allocator kept producing pid 1025+, but those pids had no slot.
- Terminal `wait4`/`waitid` now call `namespace::pid::unregister_reaped()` after
  computing guest-visible results. This frees only after the zombie is consumed;
  dead-but-unreaped children remain translatable.
- `crates/carrick-runtime/src/namespace/supervisor.rs` now records the watched
  host pid per slot, not a permanent boolean, so slot reuse arms a fresh process
  exit watch.

### Don't regress

This path is shared with PID namespace process lifecycle, wait status
translation, and the cross-process signal work (`fix(signal)` kill02/10/12
cluster, `fix(proc)` `7d6a778`). Keep these green:

- `scripts/run-probe.sh waitexitstorm`
- `scripts/run-probe.sh waitidspec`
- `scripts/run-probe.sh waitrestart`
- `scripts/run-probe.sh waitsiblingsigchld`
- LTP `kill02/kill10/kill12`
- reap-heavy Go/CPython suites

## Status

- Bug 1 (hang): **FIXED** — `crates/carrick-hvf/src/io_wait.rs`
  `wait_proc_exit_kqueue` waitid backstop. Build green 3/3.
- Bug 2 (ECHILD storm): **FIXED** — namespace member slots are freed on terminal
  wait reaps; `waitexitstorm` is committed and MATCH.
- Gate-performance follow-up: **FIXED** — `waitexitstorm` still matched with a
  long timeout, but exceeded the conformance-probe gate after 60s. A focused
  trace showed the fork storm spending host kernel time recreating parent-side
  waiters (`kqueue`/wake pipes/fd churn) on every fork. Parent fork branches now
  retain their existing `ThreadWaiter`; the threaded child keeps a full waiter
  because `itimer` fork-child delivery depends on immediate signal-pump wake
  registration, while the single-thread child can use a process-only waiter
  until it blocks.
- Current validation:
  - `scripts/run-probe.sh waitexitstorm` → MATCH (`all_reaped=true`)
  - `/usr/bin/time -lp scripts/run-probe.sh waitexitstorm` → MATCH in 39.93s
    real / 37.30s sys after the waiter-lifetime fix; before this slice,
    carrick-only with a long timeout took 69.06s real / 66.20s sys.
  - `scripts/run-probe.sh itimer` → MATCH, including
    `itimer_fork_child_delivered=true`
  - `scripts/run-probe.sh waitidspec` / `waitrestart` / `waitsiblingsigchld` /
    `pidnswait` / `pidnsinitreap` / `cloneexitsig` → MATCH
  - `target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/itimer`
    and `.../waitexitstorm` → exit 0 on the single-thread path
  - `just conformance-probes` → OK (`4 passed; 0 failed`, 219.94s)
  - `.agents/skills/ltp-conformance/scripts/ltp-check.sh kill02 kill10 kill12`
    → MATCH=3 DIFF=0
  - `GOMAXPROCS=1 go build -p=1` of `runtime/testdata/testprogcgo` → OK
- Green regression guards landed for the (ruled-out but real) epoll EOF path:
  `epolletpipeeof`, `epolletblockedhup`, `epolletchildhup`, `epolletmanyhup`
  (all MATCH — pipe writer-close edges ARE delivered, including the multi-fd
  fan-out; that hypothesis was wrong, but the guards are worth keeping).
