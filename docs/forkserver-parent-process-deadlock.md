# `test_multiprocessing_forkserver.test_parent_process` deadlock

Status: **RESOLVED** (commit `12f5f65`). `test_parent_process` is 10/10 PASS
(was 10/10 hang); the full module runs to completion (run=397, was blocked at
n=96). A related CPU-spin symptom was fixed first (`73cb279`).

## Root cause + fix (`12f5f65`)

The wedged worker's stack (via the event-ring tool below + `sample`):
`run_vcpu_until_exit -> ForkCoordinator::prepare_host_fork ->
SignalPump::stop_inner -> thread::join -> __ulock_wait` (forever). When a
forkserver WORKER forks the nested forkserver SERVER B, carrick stops the
worker's signal pump (`prepare_host_fork`) by setting `running=false`, writing
the pump's wake pipe ONCE, and `join()`ing. In the nested-fork timing the
freshly-respawned pump can still be setting up its kqueue/pipe, so the single
pipe-wake races and is LOST — the pump parks in `kevent()` forever, never sees
the stop flag, and `join()` blocks the whole host fork. Server B is therefore
never forked; the worker, `main`'s `rconn.poll` (line 422), and the grandchild
all deadlock.

Fix: `SignalPump::stop` now (a) wakes via BOTH channels (the pipe AND the
EVFILT_USER NOTE_TRIGGER), retried on a short cadence; (b) waits on the pump's
real EXIT (a new `exited` flag set by an exit guard on every return path); and
(c) if the pump still hasn't exited within a bound, DETACHES rather than join
forever (a leaked daemon parked in `kevent` is harmless — the next pump's
`pump_install_pipe` EOF-wakes it). Red->green test
`vcpu_kick::tests::signal_pump_stop_is_bounded_when_wake_is_lost`.

## Durable debugging tooling (what cracked it)

The race perturbs under `eprintln`/dtrace, so two low/zero-perturbation tools
were added and are kept for future use:

- **In-memory event ring** (`crates/carrick-runtime/src/event_ring.rs`,
  `d1a2947`): always-on, hot-path-cheap (atomic index + 2 stores, ~ns) recording
  of bind/connect/listen/accept/epoll_ctl/epoll_pwait/fork/exec. It pinpointed
  the wedge — the worker `BIND`+`LISTEN`s B's listener then STOPS with no `FORK`
  (stuck before forking B) — without perturbing the race away. Optional 1 Hz
  file dump: `CARRICK_EVENTRING=<dir>` -> `<dir>/carrick-ring.<pid>`.
- **lldb plugin** (`scripts/carrick_lldb.py`, `carrick eventring`): reads the
  ring from a LIVE process or a CORE file. Repeatable workflow:

  ```sh
  # live: attach to the (guest) carrick process
  lldb -o "command script import scripts/carrick_lldb.py" \
       -o "attach <pid>" -o "carrick eventring"

  # core: small modified-memory core (dirty pages incl. the ring, NOT the
  # multi-GB guest memory), then read it with no live process
  lldb -o "attach <pid>" -o "process save-core --style modified-memory /tmp/c.core" -o detach
  lldb -c /tmp/c.core target/release/carrick \
       -o "command script import scripts/carrick_lldb.py" -o "carrick eventring"
  ```
  Note: a `carrick run` is two host processes (orchestrator parent + the guest);
  attach to the guest (the one with a non-empty ring).

---

## (Historical) investigation notes

## Reliable repro (the red test)

This is the tightest **reliable** reproducer found. It hangs ~10/10 on the
current binary; CPython's own `--timeout` watchdog dumps the stuck stack:

```sh
carrick run localhost:5050/cpython-test:3.12.13 --raw \
  /usr/local/bin/python3 -u -m test --timeout=22 -v \
  test_multiprocessing_forkserver -m test_parent_process
# -> "Timeout (0:00:22)!" with the main thread stuck at
#    _test_multiprocessing.py:422  (the first rconn.poll(LONG_TIMEOUT=300))
```

The Docker linux/arm64 oracle runs the same in ~326 ms (PASS), so this is a
carrick bug, not a test artifact.

## Mechanism (root-caused via `carrick trace` + `sample`)

The test is 3-level: `test → child p (sleeps 300) → grandchild` (all forkserver),
and `p` is terminated while the grandchild watches `p`'s death. Under carrick:

- `main` blocks at `_test_multiprocessing.py:422` — `rconn.poll(300s)` waiting
  for the grandchild's first "alive" message, which never arrives.
- The level-1 worker starts its **own** nested forkserver **server B**
  (`socket`+`bind`+`listen`, then `clone`+`exec` of `python -c forkserver.main`).
- **Server B is the deadlock:** an `io-wait-begin` trace of a hung run shows a
  process blocked in `epoll_pwait(timeout=-1)` → `WaitOnPollFds([kq_fd=16391],
  None)` → `io_wait::wait_poll` **forever**. `16391` is in carrick's
  internal/relocated-fd range (≥16384, `HOST_INTERNAL_FD_MIN`) and is the epoll
  **instance kqueue** fd (ruled OUT eventfd/pidfd/inotify/timerfd — no creation
  syscalls). I.e. B sits in `selectors.select()` and its listening AF_UNIX
  socket's readable edge is **never delivered** when the worker connects → B
  never `accept`s/serves → the worker blocks reading B's response → the
  grandchild never spawns → `main`'s poll times out.

So the bug is a **lost epoll listening-socket readiness edge across a nested
forkserver-from-forkserver spawn** — the same family as the Node EVFILT_USER
mis-count and the apt fork-storm kqueue spin. It is the documented #1 nested-fork
Heisenbug, and is intermittent (sometimes passes in ~3 s; ~10/10 hang on the
current binary).

## The CPU-spin SYMPTOM — FIXED (commit `73cb279`)

Before the fix, one process pinned a vCPU at **100 % CPU** (`sample`d stack:
`run_vcpu_until_exit → io_wait::ThreadWaiter::wait` looping `kevent`+`read`).
Root cause: `io_wait` registered the process self-pipe + per-thread wake pipe
`EV_ADD` (level-triggered). When a forked child's wake pipe sits at **EOF**
(write end closed), level-triggered `EVFILT_READ` re-fires every `kevent`, and
`drain_pending_pipe`/`drain` can't clear an EOF, so `wait_kqueue` busy-spins.
Fix: edge-trigger via `wake_pipe_read_kevent() = EV_ADD | EV_CLEAR` (matches the
signal pump's pipe). Red→green unit test `io_wait::tests::
wake_pipe_at_eof_does_not_refire`; 68/68 hvf lib tests + the conformance gate
pass. **This removed the CPU burn but NOT the hang** — the spin was a
consequence of a process being blocked, not the deadlock itself.

## Distillation attempts that did NOT reproduce (do not repeat)

The deadlock requires the full regrtest environment; none of these standalone
repros triggered it (each ran 40/40 OK, `--fs host`, registry image):

1. 3-level forkserver, module-level fn targets (`__main__`).
2. classmethod targets (class in `__main__`).
3. cross-module classmethod targets + `set_forkserver_preload`.
4. worker forced to start a brand-new forkserver (`forkserver._forkserver =
   ForkServer()`).
5. non-ASCII cwd + `TMPDIR` (regrtest uses `/tmp/test_python_worker_1æ`).
6. multi-threaded main (a `faulthandler.dump_traceback_later` watchdog thread +
   a busy daemon thread), looped 40×, with `p.terminate()`.
7. (6) + heavy `set_forkserver_preload` (unittest/asyncio/ssl/http/...).
8. (6) + 64 inheritable open fds (to shift carrick's ≥16384 internal-fd
   relocation + the kqueue/wake-pipe fd assignment).

The untested differentiators that likely matter: the target is a **dynamically
load_tests-installed classmethod on a class in an imported module**
(`test._test_multiprocessing.WithProcessesTestProcess`), so the nested
forkserver worker's unpickle pulls a heavy import; and the exact regrtest
process/scheduling. The reliable repro above remains the `-m test_parent_process`
invocation.

## Update (2026-06-02): topology pinned to nested server B; Heisenberg observability

Regression-checked the EV_CLEAR fix: **0 regressions** (469 workspace lib + 247
carrick-runtime integration + cli/nested_pipe/runtime_loop/trap_hvf/
thread_stress/wait_proc_exit_recovery + the 4-test gate all green; the 3
`syscall_process.rs` failures are pre-existing — identical at parent `ff638a0`).

Deadlock topology (clean `sample` of a hung run — all processes at **0.0 % CPU**,
i.e. a quiet deadlock, no spin):
- The **first** forkserver server A works: binds its listener, registers it on
  its epoll, sees the worker's connect (`epoll-result ready=1`), processes it,
  blocks for the next.
- The **nested** forkserver server **B fails to function** after the worker
  fork+execs it. The clean sample shows a process parked in
  `io_wait::wait_poll` (B's `epoll_pwait` on its kqueue) whose listener never
  becomes readable on the worker's connect.

**Heisenberg:** in-code gated `eprintln`s (`CARRICK_EPOLL_SPIN`) at bind/connect/
epoll_ctl/epoll_pwait perturb the timing enough that the manifestation CHANGES —
under instrumentation B doesn't even reach its select loop (its listener is
bound by the worker, but B does no `epoll_ctl(ADD)` / `epoll_pwait`), i.e. B
wedges earlier in startup. So both `dtrace` AND `eprintln` perturb this race;
the clean manifestation (B in epoll, listener never wakes) is only visible by
`sample`, which doesn't show the guest-level cause.

This is the documented **#1 HVF nested-fork Heisenbug** (a server forked+exec'd
from a forkserver-spawned worker fails to function) — same family as
`[[project_shared_file_coherence]]` (post-spawn coherence on a nested fork).
Note: B's listener + epoll are HOST objects (kqueue, host fds), so if the cause
is host-fd/kqueue state being wrong across the nested fork+exec rather than
guest-memory stage-2 TLB coherence, that's a distinct (and possibly more
tractable) bug — to be determined with non-perturbing observability.

**Next-step tooling:** the eprintln/dtrace perturbation must be eliminated to
observe the clean manifestation. Use a **lock-free in-memory event ring**
(an atomic index + fixed array, ~ns/event, no syscall/lock) that the
bind/connect/epoll_ctl/epoll_pwait/accept handlers append to, dumped
post-mortem (sample the ring memory of the hung B, or dump on a signal). Then
determine whether B's epoll registers the correct listener host fd and whether
the worker's connect makes that host fd readable on B's kqueue.

## Next steps for the real fix

Pin **why B's epoll never wakes on the worker's connect**:
- Is B's listener `EVFILT_READ` actually registered on B's epoll instance
  kqueue after the fork+exec (vs lost / a stale kqueue)? Instrument
  `epoll_ctl(ADD)` for a listening socket + the kqueue drain in B.
- When the worker connects, does the listener's `EVFILT_READ` fire on B's epoll
  kqueue, and does `wait_poll`'s `poll(kq_fd)` observe it? (A connection that
  arrived *before* the `EVFILT_READ` was armed must still be level-reported.)
- Suspect a fork/exec readiness-delivery gap specific to a nested
  forkserver-from-forkserver listener. See `crates/carrick-runtime/src/dispatch/
  net.rs` (`epoll_ctl`/`epoll_pwait`/`epoll_kq_add_changes`) +
  `crates/carrick-hvf/src/io_wait.rs` (`wait_poll`).
