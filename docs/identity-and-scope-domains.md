# Identity and scope domains

Why one class of bug keeps recurring in the HVPatch runtime, why the test lane
cannot see it, and what to build so it stops.

Written 2026-08-16 from four read-only audits of the runtime-side crates. Every
claim below carries a `file:line` or a measurement; where something is inferred
rather than verified it says so.

---

## The shape

The typed-domain migration ([`typed-interfaces-audit.md`](typed-interfaces-audit.md))
made **scalars** safe: `HostPid`/`NsPid`, `Fd`/`HostFd`, `GuestVa`/`Gpa`/`HostVa`,
`Signal`, `LinuxErrno`. That work was correct and it holds.

Every defect in this document is in a category it does not cover. There are four,
and they are distinct — a fix for one does not help the others.

**Populations.** `kicker.count()` and `task().threads().len()` are both `usize`.
Nothing prevents substituting one for the other, and they genuinely differ: a
thread parked in a futex has already released its vCPU lease. There are not two
such sets but **eight** (host pthreads; `ThreadRegistry` entries; the kicker
handle set; the kicker `in_guest` map; `vcpu_sched` leases; kernel
`task().threads()`; barrier participants; and `process_vcpu_live` vs the
carrier-wide `trap::VCPU_LIVE`). Several retire at *different instants* from one
another.

**Lifecycle.** There is no vocabulary for "alive" versus "can still reach a safe
point". Worse, "can reach a safe point" is not one predicate: a thread parked at
the fork barrier will *park* but will not *publish crash registers*, and a thread
waiting on a vCPU lease will do neither. The question must be asked per-purpose.

**Ownership.** No type distinguishes "the current `mm`" from "another process's
`mm`". `GuestMemory::read_bytes(&self, address: u64, …)` takes a bare `u64` in an
address space determined by the receiver, so any `u64` type-checks against any
engine. **"Which mm" is not a value at all — it is `self`.**

**Scope.** A `static` is just a `static`. Nothing marks whether it describes the
carrier or one Linux process.

---

## Why they all appeared at once

Under the retired one-process-per-guest model, all of these were **true
statements**:

- a process-global `static` *was* per-Linux-process state
- `getpid()` *was* the Linux pid
- "the current address space" *was* the only one
- live vCPUs *were* the live threads

HVPatch falsified all four simultaneously. Not one produced a compile error.

The code did not rot. The ground moved under correct code, which is why three of
the defects carry doc comments that *justify* the wrong behaviour:

> `namespace/process.rs:135` — "inherited by fork descendants (address-space
> copy) … exactly the per-process semantic Linux gives"

> `dispatch/creds.rs:83` — "A process-global static is correct: nice is a
> per-process attribute and carrick's fork creates a fresh address space."

> `carrick-host/src/host_proc.rs:1` — "the guest pid IS the host pid (the trees
> mirror)"

There is no address-space copy under HVPatch. Each comment was accurate when
written and is now an active instruction to leave a bug in place.

---

## Why the gate cannot catch it

Every host-identity finding is **correct while exactly one Linux process exists
in the carrier, and wrong the instant a second appears.** Not one is wrong in the
single-process case.

The smoke lane is a single `run-elf` process where the carrier pid, the root task
id and `getpid()` all coincide *numerically*. All three domains are the same
integer, so every conflation reads as correct.

This is the load-bearing observation in this document. It means the defect count
is a function of how long the model has been wrong, not of how carefully anyone
reviewed — and that adding tests in the existing shape will not find the rest.

**A conformance case that exercises two live guest processes is worth more than
any number of single-process cases** for this class.

---

## What the audits found

| domain | defects | worst |
|---|---|---|
| carrier-global state | 11 of 197 statics | caps + user namespace shared by every guest |
| thread populations | 9 sites | `in_guest` decay — *measured* at ~1 in 3 |
| host identity | 18 sites | `/proc/<B>/fd/N` returns a dup of **A's** fd |
| address space | 4 sites + 1 missing capability | `/proc/<pid>/mem` returned the caller's memory |

The carrier-global row is re-counted per static for the embed program in
[`identity-and-scope-domains-embed-census.md`](identity-and-scope-domains-embed-census.md):
every `static`/`OnceLock`/`std::env::var` in `carrick-runtime` and
`carrick-kernel`, classified container-state versus carrier-infra, each with
its Phase-B destination.

Two are worth stating in full because they are not "wrong errno" bugs.

**The `in_guest` decay** (fixed 2026-08-16). `unregister` dropped a thread from
both the handle map and the `in_guest` map; `register` restored only the handle;
`register_in_guest` had one call site, at thread creation. So after a thread's
first futex park, `any_other_in_guest()` returned false for it forever, and the
page-table pause drained instantly while it executed guest code. Measured via the
`pt-pause-begin` probe (whose `arg1` *is* `any_other_in_guest`): pauses that saw
a sibling in-guest went **0/1596 → 705/1585 (44.5%)**. Roughly one in three
stage-1 edits had been running under a live vCPU, silently.

**Capability leakage.** One `CapabilitySet` for the whole carrier. Guest A's
`PR_CAPBSET_DROP` is visible to guest B, monotonically. `tst_test`'s own setup
drops capabilities in helper processes, so this can perturb any LTP run.

---

## What to build

Ranked by leverage, not by effort.

### 1. Populations become identity sets; lifecycle becomes explicit

Delete `VcpuRegistry::count() -> usize`. Replace it with a witness type that has
no `usize`, no `Sub`, and no `PartialOrd<usize>`, so every `count() > 1` and
`count().saturating_sub(1)` must be rewritten and each author must decide which
population they actually mean.

The explicit run-state requirement is already satisfied by the scheduler-owned
`ThreadExecutionState` on kernel `Thread`. Keep it as the sole lifecycle
authority; adding a second run-state enum would duplicate transitions and
recreate drift. Mint **per-purpose** participant sets from the `Task` — not one
"safe-point-reachable" set, since that conflation is precisely the
`exit_group01` bug.

The pattern already exists and works: `kernel/crash_capture.rs` (2026-08-16)
replaced a three-population predicate with a **quorum value** plus a
`CrashSafePointParticipation` RAII guard held for exactly the vCPU loop's
lifetime. Every exit path releases it; a loop that never starts never claims it.
That guard caught two over-count cases neither the audit nor the author had
identified. **Copy this shape rather than inventing a second one.**

### 2. `CurrentMm` versus `ForeignMm` as types

Make the address space a value carried by the address: an `MmToken` proving a
live, authenticated mm, mintable only from the kernel graph and carrying the
snapshot revision; a VA that is meaningless without one. Split `GuestMemory` into
a current-mm trait and a foreign-mm trait with **no blanket impl** for the current
engine.

Three features — `process_vm_readv/writev`, `ptrace` PEEK/POKE, and
`/proc/<pid>/mem` — each independently invented a workaround for the missing
capability rather than one of them building it. Under this typing all three would
have been compile errors instead of an `EFAULT`, an `ENOSYS` Linux never returns,
and a silent wrong answer.

A foreign **write** additionally needs a `CowBroken` witness bound to the same
token: `ensure_frame_cow_write` is `&mut self` and VA-keyed on the current engine,
so writing into a forked child's stack would split the *parent's* frame — leaving
the child unchanged and silently rewriting the parent. The fork tid copyout
(`vcpu_loop/quiesce.rs:1595`) already does this correctly by convention; the type
makes it mandatory.

### 3 and 4. Mechanical gates — cheapest, do first

Both classes are pure pattern-matching and `just lint-domains` already exists.

- A mutable `static` or process-global environment source in a runtime crate is
  an error unless it is present in the reviewed monotone global-state ledger.
  Every accepted row names its scope, owner and migration destination; additions
  and stale rows fail closed.
- `std::process::id()` / `getpid` / `proc_listallpids` are errors in
  Linux-semantics paths; a legitimately carrier-scoped call says so by calling a
  named `carrier_pid()`.

Neither is landable as a flat ban — 197 statics exist and ~165 are legitimate. Use
a **monotonic baseline**: fail on any finding not in the baseline, *and* fail when
a baseline entry stops matching, so fixing one forces deleting its entry and the
file can only shrink. "We will clean it up later" becomes inexpressible.

### Accepted scope implementation — 2026-08-28

The reviewed `carrick-embed` census plus the monotone
`runtime-global-state.json` gate supersedes the proposed `CarrierGlobal<T>` /
`CarrierScope` wrapper. Container state is carried by `Container` and
`LaunchContext`; accepted carrier infrastructure remains explicit ledger debt.
Do not build both mechanisms.

### Identity-aware vCPU lease drain — 2026-08-28

`VcpuRegistry::count() -> usize` is deleted. Fork and crash protected work now
requires a unique identity-aware `VcpuLeaseDrainGuard`; the same registry
atomically denies non-owner registration until barrier release. Membership and
thaw wakes are one-shot, registry-owned publications, and production admission
preserves census-before-registry ordering plus the existing logical phase.

This was the first half of population/lifecycle item 1 (runtime-audit Part 2
item 3). The participant-witness milestone completed the other half: the
pre-existing `ThreadExecutionState` remains the sole run-state authority, and
purpose-specific Task witness types retain exact identities through every
fork/crash/core consumer. No second lifecycle enum was introduced.

The closing verification applies to code head `a6579a511`; `209522268` adds only
this receipt. The HAL registry (13 tests), runtime lease drain (7), process fork
(17), core publication (9), fork quiesce (10), and observability ABI (76) all
passed. `just clippy`, `just deny`, `just check-matrix`,
`just check --workspace`, `just doc`, `just test`, and unrestricted
`just test-integration` exited zero; the runtime unit arm alone ran 2,050 tests,
and the runtime integration arm ran 302. `just lint-domains` passed its
global-state, abort-ledger, and source-policy checks, then its mandatory compiler
host-authority census exited 2 on the documented position-only inventory drift:
`changed=[]`. Consequently `just ci` stopped at that same stage; every recipe it
could not reach was run explicitly as listed above. The exact abort ledger
closes at 405 sites: 355 carrier-invariant aborts and 50 typed-error debts.

### Typed participant population closure — 2026-08-28

Code head `7a2af1aee` closes the raw population-authority half of item 1.
`ForkBarrierParticipants`, `CrashBarrierParticipants`,
`ThreadExitParticipants`, `CrashCaptureParticipants`, and
`CoreNoteParticipants` are minted from `Task`; owner-sensitive witnesses
authenticate an exact `ThreadKey` under the Task membership lock.
`GuestExecutorCensus` now owns exact thread or anonymous executor identities,
rejects duplicates and exhaustion transactionally, and couples its membership
to generation-stamped `CrashSafePointParticipationId` RAII. A stale crash guard
cannot clear its successor, and unwind releases crash participation before the
executor census identity.

Fork and crash barrier control uses only `requires_quiesce()`. Numeric
cardinality survives solely in explicitly suffixed `_for_probe` projections at
the existing fixed-width USDT boundaries. `CrashQuorum` refreshes its
Task-minted capture roster on every poll, so retirement between polls cannot
strand collection. Non-final thread exit requires an exact survivor witness.

The monotone source checker's 14 negative and 14 positive fixtures pass, and its
production scan covers 162 Rust leaves with zero findings. The remaining five
raw-search `threads().len()` matches are test-only assertions. Focused
executor-census (8), stale-owner (1), crash-quorum (3), process-fork (17), core
publication (9), fork-quiesce (10), and observability (76) tests pass.
`just clippy`, `just doc`, `just deny`, `just check-matrix`, `just check
--workspace`, the authoritative `just test` rerun (including 2,062 runtime
tests), and unrestricted `just test-integration` (302 runtime integration
tests) pass. One load-sensitive ptrace-stop unit failed in the first broad run,
then passed three exact serial reruns and the complete authoritative rerun.
`just lint-domains` and `just ci` stop only at the mandatory compiler
host-authority positional inventory check with `changed=[]`; that inventory was
not rebaselined. The exact abort ledger now closes at 407 sites: 357
carrier-invariant aborts and 50 typed-error debts.

The Antigravity fork worker `task-participant-fork` (conversation
`353b580d-2a8a-4e8a-bb35-679894e54923`) required three turns: Codex rejected a
boolean projection that would have lied in the existing sibling-count probe,
and the same conversation repaired it before integration. Worker commits
`4ccd570a2` and `d99f5c06f` became canonical commits `eaf216c95` and
`d23f37022`. The crash/core worker `task-participant-crash` (conversation
`a86ce8bd-f883-4e1a-a6b2-7d38522ef847`) completed in one turn; worker commit
`d035366b2` became canonical commit `c02fc50f3`. Codex re-ran every bounded gate
and independent reviewers approved both consumer migrations.

This receipt closes populations and lifecycle only. `MmToken` plus structural
`CurrentMm`/`ForeignMm` authority and the mintable page-table/host-alias lock
order remain open; the full runtime abstraction audit is not complete here.

### 5. Lock order made structural

The page-table pause and the host-alias phase must be taken in one order. The
inversion has already wedged a carrier at 0% CPU once, and a second self-deadlock
(the alias cleanup path re-entering a non-reentrant topology lock) turned an
intended `ENOMEM` into an unkillable hang. Prefer a token only the outer
acquisition can mint over discipline.

---

## Sequencing

3 and 4 stop the bleeding and are days, not weeks. 1 fixes live bugs. 2 unblocks
three stalled syscall families.

1 and 2 are also the prerequisite for the N:M guest-thread decoupling. That change
is frightening *today* precisely because the populations are conflated — it
multiplies register/unregister traffic, which is exactly what triggered the
`in_guest` decay. Once "how many threads exist" and "how many can respond" are
distinct types, decoupling becomes a mechanical refactor rather than a rewrite
without a safety net.

---

## The rule to carry forward

When the execution model changes, the dangerous code is not the code that breaks.
It is the code that keeps compiling, keeps passing, and keeps explaining itself in
terms of a model that no longer exists.
