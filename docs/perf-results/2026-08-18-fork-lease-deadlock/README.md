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

## Open, ranked

1. The clone materialization gate (`threads.rs:1019`) — the live blocker for
   `go-os_exec`, and the likely shared cause with `cpython-multiprocessing_fork`
   / `forkserver` (600 s timeouts) and `cpython-threading`.
2. Per-process vCPU budget is a per-process view of a host-global resource:
   every carrick process independently sizes to the whole machine, so four
   guests admit 4x the host's cores. The code already knows the resource is
   host-global ("a slot freed by a DIFFERENT process's teardown can't reach
   this process's condvar").
3. The `TestSOCKS5Proxy` intermittent wedge.
