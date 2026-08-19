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

### `gettid` has a fast path that never fires

Correcting my own first reading: `gettid` is NOT missing a fast path. It has a
dedicated one — the EL1 vector reads `CONTEXTIDR_EL1`, which
`Aarch64Vcpu::stamp_guest_thread_id` writes per vCPU
(`hvf_aarch64_engine.rs:299`), with the handler emitted at `memory.rs:3015` and
its opcodes asserted by unit tests at `memory.rs:5053-5132`.

It does not fire. Measured against a control group that definitely traps —
`getppid`, `getuid` and `geteuid` are gated fast-path-safe but have no handler
at all:

| syscall | ns/call | serviced |
|---|---:|---|
| `getpid` | 125-137 | EL1, identity page |
| `gettid` | 1,395-1,426 | **traps** |
| `getppid` | 1,697-1,699 | traps (no handler) |
| `getuid` | 1,677-1,691 | traps (no handler) |
| `geteuid` | 1,681-1,696 | traps (no handler) |
| `clock_gettime` | 1,986-1,994 | traps |

`gettid` sits with the trapping group, not with `getpid`. It is ~16% below the
control group, which is consistent with exiting the `cmp` chain earlier rather
than with being serviced at EL1.

Not a fork-inheritance problem: the numbers above are identical whether the
benchmark runs as a forked child of `/bin/sh` or directly as pid 1, so the
per-vCPU stamp is not simply being lost across fork.

The handler degrades deliberately when `CONTEXTIDR_EL1` reads 0 (`cbz`, since a
tid is never 0) and traps normally.

Two things have since been checked, and both narrow it:

- **The stamp itself works.** `CARRICK_TIDSTAMP_DEBUG=1` reads the sysreg back
  immediately after writing it: `set CONTEXTIDR_EL1=1 -> readback=Ok(1)`. So
  `set_sys_reg` is not silently failing, and the degrade must happen LATER — on
  a trap round-trip, a resume path that restores a sysreg snapshot without
  CONTEXTIDR, or the M:N scheduler destroying and recreating the vCPU (which
  re-stamps only via `stamp_guest_tid` at loop start).
- **The `IDENTITY_OFF_SHIM_SYSCALLS` counter does NOT settle it**, contrary to
  what an earlier draft of this file said. The handler increments the counter
  BEFORE the `CONTEXTIDR` read — its own comment notes the degrade path "still
  traps to the host AFTER counting" — so the counter cannot distinguish a hit
  from a degrade. It can only distinguish "handler reached" from "cmp/enabled
  check failed", which is still worth one run.

**CONTEXTIDR_EL1 survives.** A read-back after every `hv_vcpu_run`
(`CARRICK_TIDSTAMP_DEBUG=1`) reports `after run: CONTEXTIDR_EL1=Ok(1)` for the
whole workload. So the sysreg is set, persists across traps, and the shim is
installed (getpid is 128 ns, impossible for a trapping syscall). The handler
still does not return the tid.

## The reason it was never caught: the EL1 shim test suite is vacuous

`crates/carrick-runtime/tests/trap_hvf.rs` contains exactly the right test —
`el1_shim_services_gettid_from_tpidr_el1` asserts the FIRST host-visible trap is
`exit_group` (94), not `gettid` (178), which is a direct behavioural check that
the fast path fired. It has never run.

    test el1_shim_services_gettid_from_tpidr_el1 ... ok
    12 tests ... finished in 0.00s

Twelve tests in 0.00 s is the silent-skip signature. `shim_engine_or_skip`
returns `None` when the engine cannot be built and the test `return`s, reporting
`ok`. Worse, it discarded the error (`Err(_)`), so the skip could not say why.

Two layers, found by making it talk:

1. The skip reason is **not** a missing hypervisor entitlement, which is what
   the comment guesses. Signing the test binary changes nothing. It is
   `AArch64 syscall mailbox slot 0 at 0x2d001e8000 is not mapped` — the fixture
   never calls `with_syscall_mailbox_arena()`.
2. Adding the arena gets the engine built and the guest executing, and the test
   then fails on a second fixture gap: `syscall HVC arrived without a published
   mailbox request`. So the fixture also needs the mailbox request protocol,
   not just the mapping.

That second failure does NOT yet discriminate — an HVC arrived, but the harness
cannot say whether it was the `gettid` or the trailing `exit_group`. Finishing
the fixture is the task that turns the production benchmark into a real
regression test.

Shipped from this: the skip now prints its error. The fixture change is NOT
shipped, because a red test in `just ci` would block everyone before the harness
work is done. The suite is still vacuous — that is now recorded rather than
hidden, which is the point.

This is worth more than the raw 11x it represents: a designed, emitted,
unit-tested fast path that silently degrades is exactly the shape that stays
broken, because every test that checks the RESULT still passes — the trap path
returns the same tid.

### What extending the identity page costs, honestly

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

**And the credential subset is not available at all.** The page layout comment
is explicit that credentials are deliberately absent: "Linux credentials may
diverge per thread, while this page is shared by every vCPU in the process",
and `IDENTITY_SYSCALLS`' own comment says "Per-thread credentials must trap
through the captured KernelContext dispatch path." Putting `getuid`/`geteuid`/
`getgid`/`getegid` on this page would be WRONG, not merely risky — I had
planned to do exactly that before reading the layout.

That leaves `getppid` as the only page-eligible addition, and the real win is
repairing the `gettid` path that already exists.

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
