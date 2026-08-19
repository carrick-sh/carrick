# Where guest fork actually spends its time

**Date:** 2026-08-19
**Artifact:** source `2cf018d33`, binary
`670f5be0715156c2491d0e6404f865374f4cecf6dd92d327d4ca4215daf9e366`,
CDHash `a97e63ae55179c9a6184906432fe15ef9dcacd08`.
**Instrument:** `carrick trace -s scripts/dtrace/hvpatch-phase4-fork-runtime-stages.d`
(in-process libdtrace; the script is a durable artifact and its header declares
the provider ABI). Both arms captured under the SAME instrument, which is the
only comparison that script's header permits; capture receipts are clean on both
(`phase_errors=0 empty=0 bounded=0 errors=0`, all ten phases present).

## Why this matters

Everything forks. Under HVPatch there is no host `fork` at all — a guest fork
should be a kernel-graph task plus a stage-1/stage-2 mapping transaction, with
no address-space copy, no host process creation and no second scheduler. The
measured cost does not look like that.

Untraced, from `reducers/shared-futex-fork-ladder.py`:

| live children | carrick per fork | Docker per fork |
|---:|---:|---:|
| 32 | 7.93 ms | 0.12 ms |
| 64 | 9.87 ms | 0.12 ms |
| 128 | 14.97 ms | 0.11 ms |
| 256 | **25.29 ms** | 0.13 ms |

66x to 200x, and **super-linear where Docker is flat**. A growing-vs-flat curve
is an algorithmic defect, not a constant-factor tax.

## Per-fork phase ledger

n=32 (34 forks) against n=256 (258 forks), microseconds per fork:

| phase | n=32 | n=256 | growth |
|---|---:|---:|---:|
| 0 Quiesce | 0.0 | 0.1 | — |
| 1 ProcessAllocate | 482.6 | 120.1 | **0.2x** |
| 2 PidfdParent | 0.0 | 0.0 | — |
| **3 ProcessSpec** | 553.0 | **1922.6** | **3.5x** |
| 4 DispatcherClone | 6.8 | 8.5 | 1.2x |
| 5 RuntimeState | 1.4 | 1.9 | 1.4x |
| 6 ThreadSpawn | 10.9 | 13.7 | 1.3x |
| **7 ChildReady** | 251.4 | **3081.8** | **12.3x** |
| 8 Publication | 15.1 | 20.9 | 1.4x |
| 9 TOTAL (0..8) | 1416.9 | 5276.7 | 3.7x |

### Three findings, two of them negative

**Quiesce is free.** The stop-the-world barrier costs 0.1 us per fork at 256
live children. The obvious suspect is exonerated — do not spend effort there.

**ThreadSpawn is free.** Host pthread creation is 14 us. The cost is NOT "one
host thread per guest process".

**ChildReady dominates and grows 12.3x**, reaching 3.08 ms per fork and 58% of
the instrumented path at n=256. That phase is the parent waiting for the child
to signal readiness. A wait that scales with live-process count is ADMISSION:
the child cannot signal ready until it wins a vCPU lease, and the queue grows
with the population. `ProcessSpec` growing 3.5x is the second term and has the
shape of a per-fork scan.

`ProcessAllocate` per fork actually SHRINKS 4x with scale (483 us -> 120 us), so
it is amortizing, not leaking — notable because it is the largest single phase
at n=32 and would be the wrong thing to attack.

### The ledger is not the whole bill

Phase 9 encloses phases 0..8 and is the parent's critical path. It accounts for
only **17% of observed fork wall at n=32 and 26% at n=256** (1.42 ms of 8.21;
5.28 ms of 20.44). Three quarters of fork's cost is outside every phase
currently instrumented.

So the next measurement is not a deeper look at these phases — it is finding
where the other 74-83% goes. Candidates, untested: the guest-side syscall
entry/exit around the fork trap, the child's own pre-ready startup before its
first phase fires, and time the parent spends between phases rather than inside
them.

## Status

Attributed, not fixed. Nothing here has been changed. The two named terms
(`ChildReady` admission, `ProcessSpec` scan) and the uninstrumented majority are
the three things to attack, in that order of evidence.

Note the traced walls (8.21 / 20.44 ms) are perturbed by eleven USDT firings per
fork; the untraced ladder (7.93 / 25.29 ms) remains the gate figure, and only
same-instrument growth ratios from this capture are citable.

---

# Follow-up: the cost is mostly NOT in fork

The phase ledger above says the named phases cover **98% of the fork handler**,
while the handler is only ~26% of guest-observed fork wall. So three quarters of
the cost is outside the fork implementation entirely, and tuning `ChildReady`
would address ~15% of the bill.

## Decomposition: syscall vs everything around it

`reducers/fork-decompose.py`, 200 forks, children `_exit` immediately. Docker
and carrick run serially.

| | Docker | carrick | ratio |
|---|---:|---:|---:|
| `os.fork` (CPython bookkeeping included) | 0.152 ms | 7.986 ms | **52.5x** |
| `libc.fork` (raw syscall) | 0.093 ms | 2.758 ms | **29.7x** |
| bookkeeping delta | 0.059 ms | **5.228 ms** | **89x** |

CPython's `PyOS_BeforeFork`/`AfterFork` — import lock, threading reinit, atfork
handlers — are just MORE GUEST SYSCALLS. On Linux they are noise. Under carrick
they cost nearly twice what the fork itself costs. **The per-syscall floor, not
fork, is what makes the observed operation 52x.**

Note the fixture difference against the ladder above: children that `_exit`
immediately give 2.76 ms/fork, while children that stay PARKED give 7.9-25.3
ms/fork. Live population is a large multiplier on top of the floor, which is
what `ChildReady` and `ProcessSpec` measure.

## The floor, and the fast path that already beats Linux

`reducers/syscall-floor.py`, 20,000 raw `syscall()` calls each:

| syscall | Docker | carrick | ratio |
|---|---:|---:|---:|
| `getpid` | 238 ns | **137 ns** | **0.58x** |
| `gettid` | 240 ns | 1,526 ns | 6.4x |
| `clock_gettime` | 321 ns | 2,086 ns | 6.5x |

**carrick answers `getpid` faster than native Linux.** The ~1.5 us floor is
therefore not architectural — the same process, on the same path, demonstrates
137 ns. Two trivial integer-returning syscalls differ by **11x within carrick
itself**.

The reason is exact. `container_policy::IDENTITY_FAST_PATH_SYSCALLS` gates seven
syscalls as safe for the EL1 identity shim — 172 `getpid`, 173 `getppid`,
174 `getuid`, 175 `geteuid`, 176 `getgid`, 177 `getegid`, 178 `gettid` — but the
shim's dispatch table has exactly one entry:

```rust
pub const IDENTITY_SYSCALLS: &[(u16, u64)] = &[(172, IDENTITY_OFF_PID)];
```

and `stamp_identity_values` writes only the pid and the enable flag. The other
six are gated as fast-path-safe and then take the full trap.

### What extending it costs, honestly

The page is 16 KiB with three fields used, so space is not the constraint;
INVALIDATION is. Each addition carries a distinct obligation:

- `getppid` — re-stamp on re-parenting (subreaper adoption, parent death).
- `getuid`/`geteuid`/`getgid`/`getegid` — re-stamp on every credential
  mutation (`setuid` family, `execve` with setuid bits, capability changes).
  Carrick already tracks these per `Task`; the stamp has to hang off the same
  authority or it will go stale, and a stale credential answer is a security
  bug, not a performance one.
- `gettid` — the hard one and the reason it is absent. The identity page is
  per-MM, and the tid is per-THREAD, so a single page cannot carry it. It needs
  a per-thread slot the shim can index without a trap.

So the cheap, safe subset is the four credential syscalls plus `getppid`,
provided the re-stamp hangs off the existing credential/parent authority rather
than a second copy.

## Caveat on these numbers

The floor benchmark calls `syscall()` directly, bypassing the vDSO. That is a
fair carrick-vs-Docker comparison of the SYSCALL path — both sides measured the
same way — but real programs reach `clock_gettime` through libc and the vDSO, so
the 6.5x there is not what a normal workload pays. `getpid`/`gettid` have no
vDSO entry on aarch64 Linux, so those two are what programs actually pay.

## Where this leaves the fork question

Ranked by evidence:

1. **The per-syscall floor** — 6.4x on every trapping syscall, multiplied by
   every workload. The identity shim proves the floor can be ~137 ns; six of the
   seven syscalls it is allowed to answer are not wired up.
2. **Live-population scaling** — `ChildReady` 12.3x and `ProcessSpec` 3.5x from
   32 to 256 live children, on top of the floor.
3. **The raw fork syscall** — 2.76 ms against 0.093 ms with children that exit
   immediately, i.e. 30x before any population effect.
