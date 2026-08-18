# Load sensitivity in the HVPatch fork/vCPU-lease path (2026-08-18)

Load sensitivity here is an architectural defect, not a measurement artifact.
This report records what was measured, the one hold-and-wait it closed, and the
larger stall it did **not** close.

## Why this was opened

Five suites regressed between the two closure runs. Attribution first, per
AGENTS.md — none of the five is caused by the merged code:

| suite | closure verdict | standalone, quiet host |
|---|---|---|
| `cpython-asyncio` | `none` (crash), 1,872 diverging rows | SUCCESS, 2,572 tests |
| `ltp-mq_timedsend01` | 1 failed of 34 | 34/34 passed |
| `go-net_http` | `truncated`, 540 s, 665 rows | completes, 28-54 s |
| `go-go_internal_srcimporter` | `none`, `TestCgo` | not re-run |
| `ltp-nice05` | 1 extra `TBROK` row | reproduces — a real 1-row gap |

Three of the five only fail *under gate load*. That is the finding, not an
excuse: a suite that passes alone and crashes at eight workers is a race that
only opens under contention.

## The controlled measurement

`go-net_http`, canonical host (4 P + 6 E cores), nothing else running,
`CARRICK_RUN_ID`-scoped reaping between trials:

| concurrent guests | wall | vs N=1 |
|---|---|---|
| 1 | 51 s | 1.0x |
| 2 | 75 s | 1.5x |
| 4 | **1017 s** | **20x** |

Linear starvation on a 10-core host would be ~2-3x. Twenty times is a
serialization collapse. `ps` during the N=4 stall showed the carriers at
**0.0-0.6% CPU** — idle-blocked, not burning host or macOS-kernel CPU, which
rules out "carrick is pathologically loading the kernel" for this stall.

## Root cause of the observed stall

`lldb -p <carrier> -o "bt all"` on an **unmodified** binary mid-stall, 35
threads:

- 21 in `complete_futex_wait_with_value` (guest futex waits),
- 4 queued in `HostCondvarScheduler::acquire_timeout` for a vCPU lease,
- 8 parked in `park_if_fork_quiescing`,
- 4 concurrently inside `try_begin_hvpatch_process_fork`, one of them in
  **unbounded `Condvar::wait` inside `reserve_hvpatch_process_vcpu_lease`**.

That last frame is the defect. `try_begin_hvpatch_process_fork` won the quiesce
barrier and *then* called the blocking `scheduler.acquire()` for its child's
slot. Winning the barrier parks every other guest thread — and those siblings
are the only threads that can release a slot. The coordinator waits on supply
it has itself frozen: hold-and-wait, all four Coffman conditions present.

It is invisible whenever a slot happens to be spare, which is why a single
guest with few threads never showed it. The HVF budget is
`min(hv_vm_get_max_vcpu_count, physical cores)` = 10 here, so any guest holding
ten live threads at fork time can hit it.

## The fix, and two shapes that failed first

Both failures are recorded because each looked correct and measured worse:

1. **Bound the wait only** — time out, `end_fork()`, retry. Converts deadlock
   into *livelock*: the coordinator re-stops the world every retry, so siblings
   never run far enough to release anything. Measured 199% CPU and no progress
   at four guests.
2. **Reserve before the barrier** — every competing forker then holds one slot
   while asking for a second. Deadlocks outright once as many threads fork as
   the pool has slots; wedged even a single guest.

What shipped: consult `has_spare_capacity()` *before* touching the barrier, and
only then take a bounded reservation, with a 1 ms backoff so the caller's retry
loop is not a spin. The world is never stopped without capacity already in
sight.

## What this does NOT fix — stated plainly

`go-os_exec` still fails. Its abort is `sibling materialization start gate
timed out` from `threads.rs:1019` — the **clone** materialization gate, a
different site from the fork reservation patched here.

`TestConcurrentExec`, 3 trials each, 180 s cap:

| build | result |
|---|---|
| baseline | 7 passes + abort; 7 passes + abort; 180 s hang |
| with fix | 38 passes, 0 gate timeouts; 7 passes + abort; 7 passes + abort |

One trial in three improved. That is not a fix, and the suite is not closed.
The fork hold-and-wait is real and evidenced by the live backtrace above, so
removing it stands on its own; it is not claimed to close any suite.

## Fixture caveat, recorded so it is not re-learned

`go-net_http` is **confounded** as a concurrency fixture: it wedges
intermittently at `TestSOCKS5Proxy` even at N=1 on unmodified binaries (600 s
and 300 s stalls observed pre-change). `TestSOCKS5Proxy` alone passes in under a
second, so the wedge needs the ~428 preceding tests. Any single N=1 net_http
timing is a coin flip — use repeated trials, or a different fixture.

The reducer in `reducers/fork-under-thread-pressure.py` does **not**
discriminate (green on both builds): CPython's GIL makes its threads release
their leases while blocked, so the pool never saturates. A discriminating
reducer needs genuinely parallel guest threads (Go, not CPython). Kept because
the negative result is the useful part.

## Second defect, found after the first: the admission budget itself

The fork fix above did not close `go-os_exec`, so the clone side was traced
properly rather than guessed at. Three hypotheses were killed by measurement
before the real one, and each is recorded so it is not retried:

1. *Parent holds its slot while its child queues.* Moving the parent's reclaim
   ahead of the spawn (its own comment says that is the intent) changed
   nothing: 4/4 still aborted.
2. *Blocking waits keep their leases and never re-evaluate.* Forcing
   `should_keep_vcpu_for_blocking_wait` to always release changed nothing:
   3/3 still aborted. Held leases were not the cause.
3. *Scheduler unfairness alone.* Making admission FIFO changed nothing on its
   own: 4/4 still aborted.

Temporary markers in the child materializer gave the actual funnel: **23 clone
children passed the HVF vCPU gate, only 17 ever got a scheduler slot**, and the
6 that never did are exactly the tids whose parents' start gate expired into
`std::process::abort()`. The shipped hatch `CARRICK_HVF_VCPU_RECLAIM=0` — which
removes the bound by admitting one live HVF vCPU per guest thread — passed the
same test in **under a second, 2/2**. That localized the defect to the bound
itself, not to reclaim, the guest, or the futex layer.

The bound is one line: `budget_from_limits` clamped the pool to the host's
**physical core count** (10) against an HVF ceiling of **63**. carrick binds one
vCPU per guest thread, so that number is how many guest threads may be
simultaneously admitted — a correctness quantity that was being set by a
throughput heuristic. Above it, slots are held by threads that only release
once some other thread progresses, and the thread that would progress is the
one queued for a slot.

Budgeting by the hypervisor ceiling instead:

| fixture | baseline | fixed |
|---|---|---|
| `TestConcurrentExec` | 4/4 abort at 10 s | **4/4 PASS in <1 s** |
| full `os_exec` suite | `none`, 30 assertions | **86 assertions, all PASS — exactly the oracle's 86** |
| `net_http` N=1 | 51 s | 53 s, 0 gate timeouts (unchanged) |

Two supporting changes landed with it: admission is now FIFO (`release` used to
push an id and `notify_one`, letting any running thread barge, and
`acquire_preferring` barged by design), and a clone child now waits for its slot
in 250 ms slices rather than 10 ms — every `acquire_timeout` call takes a *fresh*
place in line, so a child re-entering the queue every few milliseconds sent
itself to the back forever.

Reclaim still matters above the ceiling: guests do exceed it (CPython
`test_queue.test_many_threads` spawns 100 threads). This raises the bound, it
does not remove it.

### What the raised budget did to the rest of the cluster

Re-measured serially on a quiet host, same signed artifact:

| suite | baseline | after |
|---|---|---|
| `go-os_exec` | `none`, 30 assertions | **86/86, matches the oracle exactly** |
| `cpython-threading` | 300 s timeout, 141 of 193 | **26 s, `Result: SUCCESS`, 208 tests** |
| `cpython-multiprocessing_fork` | 600 s timeout, 69 of 317 | still times out (620 s) |
| `cpython-multiprocessing_forkserver` | 600 s timeout, 140 of 323 | still times out (621 s) |

So the admission bound was the whole story for `os_exec` and `threading`, and
is NOT the story for the multiprocessing pair: those now stall at
`WithProcessesTestPoolWorkerLifetime.test_pool_worker_lifetime` after 86 tests,
which is a Pool worker-recycle wait, not an admission starve. They keep their
own root cause and their own entry in the queue below.

### Still not closed

- `os_exec` hit a second, unrelated intermittent hang at
  `TestWaitInterrupt/SIGQUIT` in one trial of two, so the suite is not yet
  reliably green.
- `net_http` at N=4 is now dominated by the pre-existing `TestSOCKS5Proxy`
  wedge: 2 of 4 guests ran to completion and a third reached the last test,
  while the fourth sat in the documented SOCKS5 stall. The N=4 wall figure is
  therefore not a clean measure of admission any more — which is progress, but
  means that fixture needs the SOCKS5 bug fixed before it can be re-quoted.

## Open, ranked

1. `cpython-multiprocessing_fork` / `forkserver` (526 rows): NOT admission.
   Both now stall at `test_pool_worker_lifetime`, a Pool worker-recycle wait.
   Reduce that test directly. `cpython-asyncio` (1,872 rows) is still to be
   re-measured against the raised budget.
2. `TestWaitInterrupt/SIGQUIT` and `TestSOCKS5Proxy`, the two intermittent
   hangs now visible underneath the admission bug.
3. Per-process vCPU budget is a per-process view of a host-global resource:
   every carrick process independently sizes to the whole machine, so four
   guests admit 4x the host's cores. The code already knows the resource is
   host-global ("a slot freed by a DIFFERENT process's teardown can't reach
   this process's condvar").
3. The `TestSOCKS5Proxy` intermittent wedge.
