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

## Reducer

`reducers/shared-futex-fork-ladder.c` reproduces the two pre-requeue phases at
n = 32/64/128/256 and prints `fork_ms` and `scan_ms` separately. It issues **no
requeue at all**, so a collapse cannot be futex semantics. RED is a `fork_ms`
knee near the vCPU budget and/or a super-linear `scan_ms`; Docker is the
control.

## Status

Mechanism attributed and verified in source; **not yet fixed and not yet
measured** — the reducer has not been run, because an authoritative closure
measurement owned the host. Run it red-first before changing either site.
