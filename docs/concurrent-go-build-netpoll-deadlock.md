# Concurrent `go build` deadlock: a layered fork-path problem

**Status: RESOLVED 2026-06-03 — faithful `vfork` implemented.** The root cause
was that carrick mis-modeled Go's `clone(CLONE_VM|CLONE_VFORK)` exec-spawn as an
ordinary CoW `fork` (separate address space, parent not suspended). The fix gives
the vfork child a SHARED address space and SUSPENDS the parent until the child
`execve`/`_exit`. Validation: the N=4 concurrent `go build` reproducer now reaches
`ALL_DONE` (was a reliable hang); a new `vforkvmshare` conformance probe is GREEN;
all clone/fork/exec regression probes (incl. `forkcow`, `mtforkcorrupt`) MATCH;
CPython `test_subprocess` (341 tests, `posix_spawn`) passes; all Rust tests pass.
A 4-dimension adversarial review found 5 latent hazards, all fixed (see
"Implementation" below). The full ecosystem gate (`just conformance full`, 23
CPython/Go/Node/LTP suites) reports **no regressions**.

Note on `go-build` in the gate: it shows an intermittent hang under HEAVY
cross-guest concurrency (the 8-worker gate phase) and so renders as `CRASH`/`NEW`
(non-gating). This is **pre-existing, not a vfork regression** — an isolation
A/B under 12 concurrent single-builds gave the OLD CoW-fork binary 9/12 (3 hung)
vs the NEW vfork binary ~17/18 (the fix REDUCED the hang rate). The residual
flake is separate HVF resource pressure (system-wide vCPU-cap exhaustion when
many multithreaded guests run at once — the `TestConcurrentExec` HV_BUSY family,
[[project_go_osexec_mtfork]]), not the `CLONE_VFORK` deadlock fixed here.

## Implementation (the fix)

Files: `carrick-abi/src/lib.rs` (+`CLONE_VFORK`), `dispatch/proc.rs` (classify),
`dispatch/mod.rs` (`Fork{vfork: Option<u64>}`), `runtime.rs` (`handle_fork`
suspend + `handle_execve` release), `carrick-hvf/src/trap.rs` (`fork_vfork` /
`share_vm`, `set_guest_sp_el0`).

1. **Classify** — `clone`/`clone3` with `CLONE_VM|CLONE_VFORK` (not the full
   `THREAD_MASK`) → `DispatchOutcome::Fork{ vfork: Some(child_stack), .. }`
   (`Some` ⇒ vfork; `child_stack` = SP, 0/NULL for Go).
2. **Share guest RAM** — `HvfInner::fork(share_vm=true)` forces the existing
   `guest_shared` Borrowed-buffer branch for every region (guest RAM is already
   host-`MAP_SHARED`, so the child's writes land in the parent's pages = true
   `CLONE_VM`) — EXCEPT the stage-1 page-table backing, kept private so the
   child's own (cloned) `PageTableManager` can't corrupt the parent.
3. **Suspend the parent** — `handle_fork` blocks the parent vCPU on an inherited
   pipe until the child `execve`s (writes a byte in `handle_execve`) or exits (the
   OS closes the write end → EOF). Bounded by a 60 s timeout backstop; share and
   suspend are strictly coupled (a `pipe()` failure degrades to a plain CoW fork).
4. **Un-share on execve** — `execve_into` already rebuilds a fresh private VM, so
   the child detaches automatically.

Adversarial-review fixes: (A) gate the RAM-share on the suspend pipe existing
(never share without suspend); (B) bound the suspend read with a timeout; (C)
keep the page-table backing private for the vfork child; (D) clone3 SP =
`stack+stack_size`, not the base; (E) `FD_CLOEXEC` the pipe + drop an inherited
`vfork_release_fd` in the child arm (a grandchild can't strand the parent).

Known limitation: a vfork child that does `mmap`/`mprotect` BEFORE `execve` won't
have those edits visible to the parent (real vfork-for-exec children — Go,
`posix_spawn` — never do this; the alternative would corrupt the parent).

---

## Historical investigation (how it was found)

(Pre-fix layered framing kept below.) **Status:** core post-mortem cracked it
into TWO layers. **Layer 1 (fork-quiesce vs futex park) FIXED** (`418d13e`).
**Layer 2** was the `vfork` mis-modeling now resolved above. Found 2026-06-03.

## How it was cracked: CORE post-mortem

`sample`/`SIGQUIT` mislabeled this as a lost-wakeup (threads in futex/netpoll
waits). Taking an actual **core** of a stuck process (`lldb -p <pid> -o
"process save-core"`, then `bt all`) showed the real shape: most cond-waiting
threads were in `carrick_hvf::fork_quiesce::QuiesceBarrier::park_if_quiescing`
(the fork barrier), one in `wait_quiesced` (the forker), and **one stuck in
`FutexTable::wait_prepared_with_token`** — a vCPU that never reached the barrier.
The futex/netpoll "lost wakes" were red herrings; the earlier epoll/futex
backstop experiments failed because the quiesce livelock hung things regardless.

## Layer 1 (FIXED 418d13e): fork-quiesce vs futex park race

To fork, the forker raises `is_quiescing`, fires a ONE-SHOT wake of blocked
waiters, then `wait_quiesced` (with timeout). A futex waiter's `interrupted()`
ORs in `is_quiescing` and is checked at the wait loop top — BUT the `parking_lot`
park-VALIDATE callback only re-checked the generation. A quiesce beginning
between the loop-top check and the park (its one-shot wake fires before the
thread parks → missed) left the thread parked forever while `is_quiescing()`,
stalling `wait_quiesced` → the fork timed out → EAGAIN → the guest's `clone`
retried → fork-retry livelock. Fix: the park-validate also bails on
`interrupted()`. Confirmed via a follow-up core (barrier gone).

## Layer 2 (RESIDUAL, task #20): fork+exec child stuck pre-exec

With layer 1 fixed, a stuck process now has RUNNABLE goroutines (not "0
runnable") — it's M-starvation, not a lost wake. `SIGQUIT` (GOTRACEBACK=all)
shows the runnable goroutines are all in `syscall/exec_linux.go`
`forkAndExecInChild` — `go` forking to exec `compile`/`link` — with one
`[running]` goroutine stuck in the **post-fork child** at `runtime/os_linux.go`
(a pre-exec syscall, e.g. rt_sigprocmask). So a forked child guest, after
carrick's `libc::fork`, doesn't make progress through its pre-exec setup under
concurrency, and the parent's `forkExec` hangs. N=12 still hangs; N=3 ~4/6.
Next: core the forked CHILD (the `[running]` m) and find why its pre-exec
syscall path stalls (stage-2 coherence of the just-forked child? a signal-mask
syscall? vCPU not progressing?).

## Capture tooling (2026-06-03): safe harness + watchdog targeting fix

**N=4 reproduces** (`scripts/go-deadlock-capture.sh 4`): of 4 concurrent builds,
1 & 4 printed `BUILT`, 2 & 3 hung — exactly the Layer-2 shape.

Two tooling problems surfaced and were fixed:

1. **The naive launch fork-bombed the host.** A hung concurrent `go build` leaves
   N builds × GOMAXPROCS vCPU host-threads spinning (the Layer-2 stall is BUSY,
   not blocked) and the watchdog CORES but does not KILL, so the spin outlived the
   capture until a human noticed — all 10 cores pinned, UI starved. Fix:
   `scripts/go-deadlock-capture.sh` runs the guest under `taskpolicy -b` (darwin
   background QoS, inherited by every vCPU thread + forked child → E-cores,
   deprioritized) + `nice -n 20` (lowest priority — NOT `nice -20`, which would
   RAISE it), and a supervisor auto-SIGKILLs the whole run tree
   the instant the watchdog's core is fully written (waits for lldb "corefile
   created"/"detached" so the dump isn't truncated). An EXIT/TERM/INT trap + a
   hard wall-clock deadline + scoped `pkill -f <run-id>` guarantee no orphan
   spinner even on TaskStop.

2. **The watchdog cored the WRONG process.** The first N=4 core
   (`/tmp/deadlock-3695.core`) was NOT a stuck guest: thread #1 was
   `namespace::supervisor::run` parked in `kevent` (the ns-init reaper, which
   never dispatches → never `tick()`s) and thread #2 was the watchdog itself in
   `Command::output`/`poll` (blocked on the `sudo lldb` it spawned). Event ring
   `total=0`. The tree-global progress counter means ANY process notices the
   tree-wide stall, and the single-shot core latch was won by this non-dispatching
   waiter — spending the one capture on useless parked state while the genuinely
   stuck go-build children never cored. Fix (`deadlock_watchdog.rs`): a
   process-local `LOCAL_TICKED` flag (set in `tick()`) gates self-core eligibility
   — only a process that has actually run guest syscalls may core — and the
   single-shot latch became a bounded counter (`CARRICK_DEADLOCK_WATCHDOG_MAX_CORES`,
   default 1) so a re-run can grab the stuck `go` PARENT *and* a pre-exec CHILD
   together. With the gate, the supervisor/orchestrator can never win the latch.

### Watchdog can't self-core under throttle → external capture

A throttled re-run (`taskpolicy -b`) confirmed the eligibility-gate fix (the
supervisor logged *"never dispatched a guest syscall … deferring"*) but captured
NO guest core: the hung guests' spinning vCPU threads **starve their own
in-process watchdog thread** (all at background QoS on the E-cores), so only the
idle supervisor's watchdog runs. Lesson: the in-process self-core is unreliable
under exactly the throttle that keeps the host usable. `scripts/go-deadlock-capture-ext.sh`
captures EXTERNALLY instead — the harness runs at normal priority OUTSIDE the
throttled tree, detects the hang (no new `BUILT` for STALL_S), and `sudo lldb`
cores EVERY carrick pid in the run (tagging each with `%cpu` so the spinning
guests stand out from the idle supervisor/driver).

## Layer-2 root cause REFINED (2026-06-03): forked child busy-spins in guest code

The external capture cracked the real shape (N=4, build 1 hung). The `%cpu`
column split the run cleanly:

- **`go` driver** (`carrick:…: go`, %cpu≈0): ALL threads parked — 7 Go M's in
  `FutexTable::wait_prepared_with_token`, 1 netpoller M in `io_wait::ThreadWaiter::wait`
  (kevent). Event ring = a long tail of `EPWAIT ready=0 timeout=0` (normal Go
  netpoll history) then quiescent. It is *waiting on its children*, not stuck.
- **Two forked children** (%cpu≈92–96, single vCPU thread each): the one vCPU
  thread is pinned **inside `hv_trap` → `Hv::Vcpu::run()` → `run_until_syscall`**,
  and their **event ring is EMPTY (`total=0`)**.

So the old "child stuck in a pre-exec syscall (rt_sigprocmask)" framing is WRONG.
The truth: the child `fork()`s and then **spins in guest code, issuing ZERO
syscalls and taking ZERO faults, never reaching `execve`** (empty ring = no
`EXEC`). `run_until_syscall`'s only in-loop `continue` (the post-fork shared-alias
stage-2 re-map) is **bounded at 8 attempts**, so this is NOT a fault-remap loop —
`hv_vcpu_run` simply never returns. That is a **pure guest-side busy-wait**:
the child is spinning on a memory location whose expected cross-thread update is
not visible in its freshly-rebuilt child VM — i.e. **post-fork stage-2 memory
incoherence** (cf. [[project_go_build_mmap_coherence]] / the SHARED_FILE stage-2
coherence wall). The `go` driver then parks on the child forever → tree-wide
syscall stall → deadlock.

This also explains why the in-process watchdog's *no-tick* trigger is the right
signal (the child genuinely issues no syscalls) but its self-core can't fire from
the starved child (above).

## CONFIRMED root cause (oracle strace, 2026-06-03): `CLONE_VM|CLONE_VFORK` mis-modeled as `fork`

A real-Linux `strace -f -e clone,clone3` of Go `os/exec` (golang:1.24-bookworm,
Docker arm64 oracle) shows the exec spawn is **vfork**, not fork:

```
clone(child_stack=NULL, flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK)            = <pid>
clone(child_stack=NULL, flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK|SIGCHLD)    = <pid>
```

`CLONE_VM` = child SHARES the parent address space; `CLONE_VFORK` = parent is
SUSPENDED until the child `execve`s/exits; `child_stack=NULL` = child runs on the
parent's stack. (The `CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM` clones are normal
Go M threads — carrick handles those correctly.)

Carrick's `THREAD_MASK = VM|FS|FILES|SIGHAND|THREAD` (`carrick-abi/src/lib.rs`).
The vfork clone sets `VM` but NOT `FS|FILES|SIGHAND|THREAD`, so
`(flags & THREAD_MASK) == THREAD_MASK` is false and it falls through to
`DispatchOutcome::Fork` (`dispatch/proc.rs` clone/clone3) → a full `libc::fork`
+ separate rebuilt HVF VM. **`CLONE_VFORK` is unmodeled** (no member in
`LinuxCloneFlags`; grep-empty in the tree) and **the parent is never suspended**.

This matches the captured deadlock exactly:
- The vfork CHILD runs Go's constrained pre-exec code assuming a SHARED address
  space + suspended parent; carrick gave it a SEPARATE CoW VM, so it busy-spins
  on shared-memory coordination that can never resolve (the captured child:
  pinned in `hv_vcpu_run`, zero syscalls, empty ring).
- The PARENT (`go` driver) expects to be SUSPENDED until the child execs; instead
  it ran on and parked waiting for a child that never reports back (captured: all
  driver threads parked in futex/netpoll).
- N=1 usually races through; concurrency reliably wedges it.

This SUPERSEDES the "generic post-fork stage-2 coherence" framing above — the
specific defect is the missing `CLONE_VM`(non-thread) + `CLONE_VFORK` semantics.

**Fix direction:** model the vfork-for-exec clone faithfully — child shares the
address space (or, pragmatically, a CoW snapshot is fine since a suspended parent
won't mutate it and the child execs almost immediately) AND **suspend the parent
vCPU until the child `execve`s or `_exit`s**, then resume it. Distinguish this
`CLONE_VM`-without-`CLONE_THREAD` (+`CLONE_VFORK`) case from both a full fork and
a full thread clone in `dispatch/proc.rs`. Add `CLONE_VFORK` to `LinuxCloneFlags`.
Probe-gate with a red repro (concurrent vfork-exec) before/after.

Cores from the capture run kept at `/tmp/go-dlx-n4-18733.cores/`.

---

> **SUPERSEDED (history).** Everything below is the original "netpoll / lost
> wakeup" investigation. It is kept only for the N=12 reproducer and the
> ruled-out vCPU-cap evidence. The "lost wakeup in the futex/netpoll path" and
> "fix target: futex" conclusions are **red herrings** — the confirmed cause is
> the `CLONE_VM|CLONE_VFORK` mis-modeling above. Do not act on the fix target in
> this section.

## Symptom

A SINGLE `go build` / `go test` / cgo build works reliably. But MANY concurrent
`go build`s deadlock — some processes hang forever:

```sh
# In the go image, under carrick --fs host:
for i in $(seq 1 12); do mkdir -p b$i; cp prog.go go.mod b$i/; done
for i in $(seq 1 12); do ( cd b$i && go build -o /tmp/out$i . && echo done $i ) & done
wait   # => hangs: only ~1/12 print "done"
```

- N=2 concurrent: reliable. N=3: intermittent (~50%). N=12: reliable hang
  (~1/12 complete). It is **load-dependent** — manifests under host-CPU
  contention (the full conformance gate running 8 suites is enough), which is
  why `go-runtime` timed out there but `go build` alone is 8/8.

## Not the vCPU cap

HVF caps concurrent vCPUs per VM at 64; the `vcpu_gate` blocks sibling-thread
creation until headroom. Ruled out as the cause:

- A full thread sample of a hung `go` shows **no** thread in `vcpu_gate::acquire`
  or `vcpu_create`; no `HV_NO_RESOURCES` in stderr.
- The gate uses a 50 ms timed backstop, so it cannot wedge forever.
- `vcpu_gate` accounts vCPUs PER-PROCESS though the cap may be system-wide — a
  real latent gap, but not this deadlock.

## Root cause (characterized)

The hung `go` process is a genuine Go deadlock: `SIGQUIT` shows **0 runnable
goroutines**, everything parked for 2–4 minutes:

```
[sync.WaitGroup.Wait, 3 minutes]   <- go build main, waiting for build actions
[select, 2 minutes] x6             <- build workers (cmd/go/internal/work/exec.go:215)
[chan receive, 2 minutes] x4
[IO wait, 3–4 minutes] x2          <- netpoll: internal/poll.runtime_pollWait
[GC worker (idle)] / [finalizer wait] / [GC sweep|scavenge wait] / [force gc]
```

Host-side, the threads sit in `FutexTable::wait_prepared_with_token`
(`pthread_cond_wait`), `poll`, and `kevent`. The `[IO wait]` goroutines are
blocked in `runtime_pollWait` on fds with no subprocess present — i.e. Go's
**netpoller breaker eventfd / internal pipes**. The netpoller M (an
`epoll_wait` → carrick `kevent`) is **not waking**, so every netpoll-blocked
goroutine and every timer-driven wakeup is stranded; that cascades to the
`WaitGroup`/`chan`/`select` waiters → total deadlock. Go's own deadlock detector
does NOT fire because the parked threads look like in-syscall I/O, not "asleep".

This is a **lost wakeup in carrick under concurrency**. Host-side, the threads
of a hung process split between `FutexTable::wait` (the MAJORITY) and the
netpoller's `poll`/`kevent`. Two candidate paths:

- **futex** (most threads): Go parks idle M's on futexes; if a `FUTEX_WAKE` that
  should make a goroutine runnable is lost, everything stalls. The generation
  token protocol looks correct in isolation, so any race is subtle and
  load-specific.
- **epoll/netpoll**: an in-memory readiness change (eventfd/pipe/timerfd)
  `NOTE_TRIGGER`s `EVFILT_USER(0)` to wake a blocked `epoll_pwait`
  (`dispatch/net.rs` `epoll_pwait`, `dispatch/epoll_shim.rs`); a trigger racing a
  waiter entering the poll can be missed.

### Attempt 1 (REVERTED): epoll-wait backstop — did NOT fix it

Gave the otherwise-infinite `epoll_pwait` (`WaitOnPollFds{timeout:None}`, net.rs
~1714) a 200 ms backstop that RE-DISPATCHES (re-evaluates readiness) on expiry —
the `vcpu_gate` pattern, so a missed `EVFILT_USER` self-heals. Built clean but
**N=12 still hung (0/12)**. So the primary lost wake is NOT the infinite epoll
wait — consistent with the host sample showing most threads parked on
**futexes**, not netpoll. Reverted (an unverified defensive change).

## Fix target (next)

Re-investigate with the futex path as the primary suspect: trace `futex_route` +
the wake path under a hung N=12 to find a `FUTEX_WAIT` whose `FUTEX_WAKE` never
arrives (or targets a different address). Tools: `kill -QUIT <go-pid>` dumps
goroutine states (carrick delivers SIGQUIT); `sample <go-pid>` shows host parks;
the event ring + carrick-lldb (zero-perturbation) cracked the prior forkserver
nested-fork deadlock and suits this Heisenbug. Secondary: the epoll EVFILT_USER
readiness-recompute race (a generation/seq re-check after `kevent` returns 0).

## Reproducer + probes

- N=12 loop above (reliable). `sample <go-pid>` shows the parked threads;
  `kill -QUIT <go-pid>` dumps goroutines (carrick delivers SIGQUIT).
- The full runtime suite hits this via the many subtests that build+run helpers;
  it is why the smoke `go-runtime` suite was reduced to a pure-runtime subset.
