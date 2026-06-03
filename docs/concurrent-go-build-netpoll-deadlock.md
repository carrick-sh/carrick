# Concurrent `go build` deadlock: lost-wakeup under load

**Status:** characterized (clean reproducer), NOT fixed; one fix attempt
(epoll-wait backstop) reverted as ineffective. Found 2026-06-03 following up the
go-build fix. Separate from the go-build crash (fixed) and from cgo support.

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
