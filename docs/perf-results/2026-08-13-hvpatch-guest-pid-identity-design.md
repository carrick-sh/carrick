# Guest pid identity on the kernel lane: why the one-line fix is not one line

**Recorded 2026-08-13.** The kernel lane's largest conformance cluster reduces
to one root cause: the kernel's task-id registry is seeded from the HOST
process id, so a forked guest process reports `getpid()` = 55234 where Docker
reports 6
([evidence](2026-08-13-hvpatch-first-probe-gate.md)). The obvious fix is to
seed the id space at 1, as Linux does.

Two designs were produced and each attacked by three independent skeptics.
**Both were refuted**, one fatally. This document is why, so the next attempt
starts from the objections rather than rediscovering them.

## What the survey established (and it is encouraging)

Inside the kernel the change really is nearly free:

- `TaskId`, `LinuxTid`, `ProcessGroupId`, `SessionId` are value-agnostic
  newtypes; the macro rejects only 0 and negatives
  (`kernel/ids.rs:12-32`).
- pgid, sid and the leader tid are copied verbatim from the root task id
  (`ids.rs:118-132`), so reseeding the root to 1 makes all three 1 — which is
  what Linux does.
- `IdRegistry` already spans `1..=i32::MAX` with a cursor that wraps to 1
  (`registry.rs:24, 152-155, 188-194`). There is **no floor and no
  host-pid non-collision invariant**, and `reserve_exact_task` has zero
  callers.
- The host pid is **convenient, not load-bearing**, on native/vmm: `virtual_pid`
  stays `None` there, so `getpid`/`getppid` answer from `self_ns_pid()`/host and
  never observe the `TaskId` at all.

There are exactly three sites that turn a host pid into a root `TaskId`
(`kernel/core.rs:222` plus two independent recomputations at
`threaded_loop.rs:291-300` and `native_darwin.rs:5495-5509`).

## The four objections, in the order they should be answered

### 1. FATAL — native and vmm run TWO id allocators that agree only by coincidence

The reference lanes have both the kernel's `IdRegistry` cursor (seeded at
`root.raw()+1`, root = host pid) **and** a second live allocator for thread
identity. Today those two agree **because both derive from the host pid**.
Reseeding the kernel one to 1 moves only that allocator, and the agreement — on
which thread identity depends — silently breaks on both lanes that the
controlling plan says must not regress.

This is the objection that kills the change as designed. Any next attempt must
either move both allocators together or prove the second one is not identity-
bearing.

### 2. MAJOR — `LINUX_BOOTSTRAP_PID` is a DEAD alias today and reseeding wakes it up

Six live comparators treat a target of `1` as "self" unconditionally, with no
liveness or namespace gate: `dispatch/abi_args.rs:62`, `creds.rs:415`,
`creds.rs:459`, `signal.rs:1193`, `signal.rs:1934`, `signal.rs:2223`.

Today that is harmless on the kernel lane **precisely because no task ever
holds id 1** — the root is the host pid and children count upward from it. Seed
the root at 1 and the alias becomes live: every one of those six now says "the
caller is the target" whenever anything names pid 1. Both designs proposed
*keeping* that arm, which is exactly the collision.

### 3. MAJOR — it would not actually fix `kill(getpid())`

`kill` gates a positive pid through PID-namespace translation **before** the
self-target test: `signal.rs:1172-1180` returns `ESRCH` on a non-member
*before* `signal_target_names_self` at `:1193` is ever reached. So the
`getpid()` half of the claim survives scrutiny and the `kill(getpid())` half —
the one the failing probes actually exercise — does not. The design's own list
of probes expected to flip was misattributed.

### 4. HOST SAFETY — the change converts a benign wrong answer into an active one

This one is not a correctness objection, it is a hazard, and it dictates
ordering.

Today a kernel-lane guest pid that leaks into a host call is `host_pid + k` —
it matches nothing and fails with `ESRCH`. **Seeded at 1..N, the same leak
names real host processes**, and pid 1 on macOS is `launchd`. The unconverted
fall-through paths are known: `libc::kill` at `signal.rs:2326`, four
`kill(pid, 0)` liveness probes (`proc.rs:2483`, `proc.rs:1871`,
`time.rs:814`, `proc.rs:3585`), and `cred_ipc::read_target`
(`signal.rs:2269`).

**So the comparators must be closed FIRST, as their own commit.** They are
correct at either seed, which is what makes that ordering safe; reseeding on
top of them is what makes it dangerous.

## The sequence this implies

1. **Route every host-pid comparator through the guest identity** — the six
   `LINUX_BOOTSTRAP_PID` aliases and the six host-call fall-throughs above.
   Correct at either seed, and it removes the hazard.
2. **Fix the two recomputation sites** to read `binding.task_id()` instead of
   recomputing from `std::process::id()`. Mechanical, one line each, correct at
   either seed.
3. **Resolve the two-allocator problem on native/vmm** — the fatal objection.
   Until this is answered, step 4 cannot land.
4. **Then reseed** the root at 1.
5. Separately: `/proc` needs its own per-task authority. The reseed does
   **not** fix `/proc/self`, which is host-pid keyed end to end
   (`vfs/proc.rs:695`, `:916`, `:1729`, `:2849`).

## What this cost, and what it bought

Two designs and six adversarial reviews, none of which produced a landable
patch. That is the correct outcome: the change looked like one line, and
shipping it would have broken thread identity on both reference lanes and
turned a harmless `ESRCH` into a signal aimed at `launchd`. The four objections
above are each concrete, each cite `file:line`, and each is checkable — which
is a better starting point than a patch that passes tests for the wrong reason.
