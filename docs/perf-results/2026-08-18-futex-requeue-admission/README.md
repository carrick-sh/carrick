# `ltp-futex_cmp_requeue01` — the 989-row cluster is admission, not requeue

**Date:** 2026-08-18
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Artifact:** source `575c9288d`, binary
`c6e35353d915389714cdc5c5a60827eab822bdbfea444b79a67b83b205b9fb01`,
CDHash `5ba76e5055d1b86fbd5bff82af230a22c3f0b4a6`, LC_UUID
`8A340FEC-EE19-30E4-8A4E-836D8F3504E1`, hypervisor entitlement and
`__TEXT,__dof_carrick` present.

On the `closure-v5` measurement this one suite is **989 of LTP's 1,463
diverging assertion rows — 67.6%**, against an oracle that does all seven
cases in 1.007 s.

## What the transcript actually says (run `conf-41741-c398`)

```
Test 0: waiters:   10, wakes:  3, requeues:  7  -> returned  10   TPASS
Test 1: waiters:   10, wakes:  0, requeues: 10  -> returned  10   TPASS
Test 2: waiters:   10, wakes:  2, requeues:  6  -> returned   8   TPASS
Test 3: waiters:  100, wakes: 50, requeues: 50  -> returned 100   TPASS
Test 4: waiters:  100, wakes:  0, requeues: 70  -> returned   0   <-- collapse
```

then 986 × `futex_cmp_requeue01.c:69: TFAIL: process N wasn't woken up:
ETIMEDOUT`.

**Test 3 and test 4 have the SAME waiter count and opposite outcomes.** Size is
therefore not the variable; cumulative load is. And the requeue IS reached and
IS truthful: it reports 0 because by the time it runs, no waiter is still
parked.

This corrects two readings carried in `handoff.md`:

- not "~200 wakes lost in the requeue chain / needs exact waiter accounting" —
  at 10 and 100 waiters the wake accounting is exact, and at the failure point
  the requeue has nothing to count;
- not "blocked on fork fan-out throughput" either — fork was de-quadraticized
  in `f1fc82c04`/`309c6a694` to a measured 1.2 s per 1,000 forks, which cannot
  produce this wall on its own.

## Why the waiters are gone before the requeue

LTP's parent will not requeue until **every** child reads `S` in
`/proc/<pid>/stat` (`TST_PROCESS_STATE_WAIT(pid,'S',0)` — a 1 ms poll with **no
timeout**), while each child's own wait deadline is 5000 ms. So the pre-requeue
phase has a hard 5 s budget, and two structural costs blow it.

### 1. A shared-futex wait keeps its HVF vCPU lease

`vcpu_loop/threads.rs:490` parks the shared wait through
`park_vcpu_for_blocking_wait`, i.e. with `force_reclaim = false`, so
`should_keep_vcpu_for_blocking_wait` (`vcpu_loop/mod.rs:137`) returns *keep*
whenever `has_spare_capacity && !has_waiters`.

The **private** futex path does the opposite unconditionally
(`threads.rs:263`), and its comment already describes this exact workload:

> Reclaim every genuine futex block on reclaiming backends: tests and real
> runtimes commonly spawn a set of waiters and then poll until all are asleep,
> so early waiters must not keep scarce HVF slots merely because capacity was
> still spare at the instant they parked.

`futex_cmp_requeue01` uses `MAP_SHARED` futexes with `opflags = 0`, so it takes
the arm that kept the lease. The first waiters strand the pool and the fork
loop then serializes on the slots that trickle back.

The whole-VM release that used to cover this is dead under HVPatch:
`single_threaded_process` requires `process_fork_barrier.is_none()`
(`mod.rs:2380`) and that barrier is `Some` for every HVPatch process.

This is the population-vs-liveness confusion `docs/identity-and-scope-domains.md`
names: *"is a slot free right now?"* is a population snapshot standing in for
*"will anyone need this slot later?"*. For a futex wait the answer is knowable
statically — the wake is vCPU-less by construction — which is why the private
path can decide it without asking.

**The same predicate silently no-ops a second reclaim.** `threads.rs:740` is the
clone parent's release-before-spawn, whose comment states its entire purpose is
that "every parent holds a slot, every child waits for one" must not happen — and
it too calls the conditional form. That reframes a hypothesis
`2026-08-18-fork-lease-deadlock/README.md` recorded as refuted ("moving the
parent's reclaim ahead of the spawn changed nothing: 4/4 still aborted"): moving
a reclaim that no-ops whenever capacity looks spare would indeed change nothing.
What was refuted is the *move*, not the *release*.

### 2. `/proc/<pid>/stat` is a whole-carrier census, per read

Every synthetic `/proc` open rebuilds the full context:
`Kernel::live_processes()` (`kernel/core.rs:1095`) allocates a `Vec` over every
task, cloning a `String` and a `Vec<u32>` each; `oom_score_adj_by_pid()`
(`kernel/core.rs:1116`) walks them all again into a `BTreeMap`. The pid is then
found by linear scan (`vfs/proc.rs:3403`).

Both carry the doc comment *"the live-task count is small"* — true under the
retired one-process-per-guest model, false under HVPatch where every Linux
process is a thread of one carrier. LTP issues ≥N of these reads over N
processes, so the readiness barrier alone is Θ(N²) allocations under two global
locks.

## Measured, and it overturns the diagnosis above

The reducer was built to separate the two pre-requeue phases. It did — and then
refuted the mechanism this report opened with.

`reducers/shared-futex-fork-ladder.py`, carrick vs the native-arm64 Docker
oracle, run serially on signed binaries:

| n | Docker fork/child | carrick fork/child | carrick scan |
|---|---|---|---|
| 32 | 0.12 ms | 7.93 ms | 10 ms |
| 64 | 0.12 ms | 9.87 ms | **20 s (bound hit)** |
| 128 | 0.11 ms | 14.97 ms | **20 s** |
| 256 | 0.13 ms | **25.29 ms** | **20 s** |

### The vCPU-lease hypothesis is REFUTED

Forcing the shared-futex park to reclaim its lease unconditionally — the change
proposed above, matching the private path — produced **identical numbers**: the
same stuck pids (36 / 100 / 228) and the same per-child fork cost. It was
reverted rather than shipped; a speculative no-op is not worth the risk.

### What is actually happening

`wake_to_reap_ms` is the discriminator. When the scan gives up on a "stuck"
child, one `FUTEX_WAKE` releases the **entire cohort** and every child is reaped
in ~150 ms — the same as a healthy round. **The children were parked correctly
the whole time.** Nothing was starved for admission, and the futex layer is
fine.

The defect is that `/proc/<pid>/stat` reports `R` for a process that is parked.
A settled one-second pass makes it unambiguous:

```
settled_states={'R': 64} non_S_indices=[0, 1, 2, ...] non_S_count=64
```

**All 64 children read `R`, in every round.** Rounds only looked healthy because
a scan that polls immediately catches the brief window after
`publish_wait_enrolled` publishes `S`; add a one-second settle and every child
has reverted to `R`.

That is the whole 989-row cluster. LTP will not requeue until every child reads
`S` (`TST_PROCESS_STATE_WAIT(pid,'S',0)`, 1 ms poll, no timeout), so it waits
forever on a state that gets retracted; the children then hit their own 5 s
deadline and the requeue truthfully reports 0. It also explains the puzzle that
opened this investigation — test 3 passing and test 4 failing at the SAME 100
waiters is just whether the scan sampled inside the `S` window.

### Where to look next

`shared_wait` publishes `Blocked`/`S` at enrollment, and the vCPU loop publishes
`Running`/`R` when a thread resumes guest code at the run-loop top. A parked
waiter whose vCPU is reclaimed and later re-acquired therefore republishes `R`
without ever leaving the futex. The run state a parked shared-futex waiter
publishes is not stable, and stability is exactly what the guest-visible
contract requires.

This is an M:N-layer defect, not a futex or admission one. The fork cost above
— 8-25 ms per child against Docker's flat 0.12 ms, growing with the number of
live parked children — is a separate, real problem in the same layer and is NOT
explained by the publication bug.

## Reducer

`reducers/shared-futex-fork-ladder.py` reproduces the two pre-requeue phases and
issues **no requeue at all**, so a collapse cannot be futex semantics. It reports
`fork_ms`, a settled state histogram, `scan_ms`, and `wake_to_reap_ms`. The
histogram and the wake latency are the two readings that matter; `stuck_state`
alone is misleading, because a scan that samples early sees the transient `S`.

## Status

Root cause localized and measured; **not yet fixed**. The lease change is
reverted. Next: make a parked waiter's published run state stable across vCPU
reclaim/re-acquire, then re-run this ladder and `ltp-futex_cmp_requeue01`.
