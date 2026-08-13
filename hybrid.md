# Carrick as a Kernel

**Revision date:** 2026-08-13 (supersedes the 2026-08-09 kernel-first
revision, which superseded the original HvPatch prototype plan).

**Status:** This file is the controlling plan. Where any other document
conflicts with it, this file wins. Prior revisions are recoverable from git
history; the durable measurements they produced live under
[`docs/perf-results/`](docs/perf-results/) and remain authoritative as
evidence.

---

## The goal, in one sentence

**Carrick is a Linux-compatible kernel that runs in one host process and one
HVF VM, and expresses every Linux operation as the smallest correct modern
Darwin primitive.** Mach, HVF and Darwin's VFS are execution, physical-memory
and storage HALs. They are not the source of Carrick's process, address-space,
path, fork, exec, scheduler, fd, signal or crash-dump semantics.

**Shipped proof — RE-AIMED 2026-08-13, on direction:** *finish the kernel*.
The criterion is **correctness and completeness**, not the CPU bar:

1. every Linux semantic the kernel lane owns is sourced from carrick's own
   kernel objects rather than from the host process it happens to run in;
2. `baseline.hvpatch.jsonl` blessed, with the kernel lane's conformance gaps
   closed rather than excused;
3. CPython, Node.js and Rust workloads **run correctly** — Node currently
   aborts in V8 startup, which is a completeness bug, not a slow one.

**Performance is explicitly NOT the gate.** The 2.3 CPU-s target and the
`native`-lane comparison are retained below as historical context and as a
regression floor — work must not make the build dramatically worse — but no
phase is scheduled, ranked or retained on a CPU number any more. A phase whose
only claim is speed is off the critical path until the kernel is finished.

## What changed in this revision, and why

Three things, all forced by measurement or by direction.

**1. The backend question is settled: `hvpatch` is the kernel.** Earlier
revisions kept `native` and `vmm` as co-equal fallbacks and required parity
with them. They are now **reference lanes**: `vmm` is the mature correctness
oracle whose conformance results we still trust, `native` is the historical
shipped default we still measure against. Neither is a parity obligation for
the kernel lane, and neither gets new investment. Work that only improves
`native` or `vmm` is out of scope. The 10x→2x native-DSR plan
(`proposed-plan.md`) is retired by this decision; its per-workstream analysis
is superseded by the amplification ledger below, which measures the kernel
lane directly.

**2. The phases are renamed for the capability they deliver, not numbered.**
The K0…K6 sequence encoded an ordering the evidence has since refuted, and
"doing K5 work during K2" is not a thing a reader can follow. Mapping:

| Old | New | Status |
|---|---|---|
| K0 — HAL probes | — | **GO**, `docs/perf-results/2026-08-08-hvpatch-phase0-decisive-probes.md` |
| K1 — object model + observability | — | **GO** at `7b808b6cf` |
| K2 — frames and address spaces | **KM — kernel memory** + **KF — kernel page lifecycle** | re-ranked below |
| K3 — fork/clone/wait | **KL — kernel lifecycle** | partly landed |
| K4 — transactional exec | **KX — kernel exec** | not started |
| K5 — scheduler, sync, lowering | **KS — kernel scheduler** + **KN — kernel namei** | KN partial; KS designed |
| K6 — cores, conformance, proof | **KD — kernel diagnostics** + **KP — shipped proof** | both partial |

See the **phase status table** below for what each one has actually landed and
what unblocks it next.

**3. The ranking is inverted: path resolution and scheduling come first,
memory second.** This is the substantive change, and it is measured, not
argued. See below.

---

## Where we actually are

Measured at and after the K1 boundary, all on the signed binary, never
concurrent with Docker.

| Quantity | at K1 boundary | **now** | Source |
|---|---:|---:|---|
| Carrick host CPU, cold `go build` | 4.29 s | **3.803 s** | [KF ceiling](docs/perf-results/2026-08-13-hvpatch-kf-scrub-ceiling.md) |
| Workload window | 2,129 ms | **1,828 ms** | same |
| Docker guest-intrinsic CPU, same build | 2.32 s | 2.32 s | [guest-vs-host](docs/perf-results/2026-08-13-hvpatch-guest-vs-host-cost.md) |
| Overhead ratio | 1.85x | **~1.64x** | derived |
| Overhead still to remove | ~1.97 CPU-s | **~1.5 CPU-s** | derived |

For scale: the historical `native` default was 10.1806x on this workload. The
kernel lane is already several times better than the backend Carrick ships
today. **Roughly a quarter of the overhead the goal must remove has been
removed**, by KN and KF's first step; the rest is not yet designed.

**The bar is approximately 1.01x the workload's own intrinsic cost.** Docker
needs 2.32 CPU-s of guest work to do this build and the bar is 2.3 CPU-s
total. "Below 2.3 CPU-s" therefore does not mean "reduce overhead
substantially" — it means **overhead must approach zero**. Every phase below
is judged against that.

### Where the overhead is

One cold build, `dtrace -Z`, proportions only (the capture perturbs heavily):
**76,503 guest Linux syscalls became 360,002 host macOS syscalls — 4.71x.**
([ledger](docs/perf-results/2026-08-13-hvpatch-build-amplification-ledger.md))

| bucket | share of host syscalls |
|---|---:|
| **path resolution** (`openat`+`newfstatat`+`mkdirat`+`unlinkat`) | **55.4%** |
| **`carrick-only`** — issued with no guest work in flight | **30.1%** |
| everything else, none above 3% | 14.5% |

Per guest call: `openat` **32.78x**, `newfstatat` **13.84x**, `mkdirat`
**90.96x**. `read` and `fcntl` are 1.07x and are not a problem.

> [!CAUTION]
> **Host-syscall COUNT is not CPU, and this table overstates its own lever.**
> KN removed a large share of the path-resolution calls and bought **12.7% of
> system time and 3.1% of total CPU**
> ([evidence](docs/perf-results/2026-08-13-hvpatch-kernel-namei.md)). The
> arithmetic says why: 1.864 s of `sys` over ~360,000 host syscalls would be
> 5.2 µs per call, far above what a macOS syscall costs — so **`sys` is not
> mostly syscalls.** Under HVF the guest runs inside `hv_vcpu_run`, a kernel
> call, and faults and VM work land in `sys` too. Driving every remaining
> path-resolution syscall to zero is worth single digits, not a multiple.
>
> **Rank by measured CPU, never by syscall count.** A count-based ledger says
> where the calls are, not where the time is. This table keeps its place
> because it correctly identifies *mechanisms* worth replacing; it does not
> size them.

And the fork memory path — the entire remit of the old K2 — is **109.61 ms
across all 68 forks** ([fork stage
split](docs/perf-results/2026-08-13-hvpatch-fork-stage-split.md)), of which
`PrivateSnapshot` is 70.6%. Even taking that traced number at face value
against a 4.29 CPU-s build, replacing the fork memory model cannot remove
1.97 CPU-s. It is necessary structural work. It is not the lever.

### Where the overhead REALLY is — measured 2026-08-13, and it is faults

The first AMP1 census ever taken of the kernel lane
([ledger](docs/perf-results/2026-08-13-hvpatch-kernel-lane-amp-ledger.md);
AMP1 previously refused any target that was not `--exec-backend native`, which
is why this had never been measured) puts the build at **279,987 `as_fault`
and 230,298 `zfod`**. At the 6.42 µs per-fault cost this tree measured on
2026-08-01, that is **~1.8 CPU-s — the entire overhead the goal must remove.**

| serviced guest op | guest calls | host syscalls | `zfod` |
|---|---:|---:|---:|
| **`mmap`** | 1,966 | 2,045 (**1.04x**) | **150,749** |
| **`execve`** | 68 | 8,306 | **45,430** |
| `carrick-only` | — | 28,890 | 30,896 |
| `brk` + `mremap` + `madvise` | 387 | 20 | **29** |

`mmap`'s *syscall* side is already essentially perfect. Its cost is **76.7
zero-fill faults per guest call — 2.36 GiB of pages touched per build**, inside
the service window, which is Carrick's own host-side work and not the guest
running. The native lane fixed exactly this shape on 2026-08-07 (in-window
`zfod` 553k → ~723); **that work was never carried to the kernel lane**, and it
does not port directly because the arena is `hv_vm_map`'d into stage-2.

**Both of those numbers have since moved and the mechanism is named.** The
scrub was the arena watermark being raised on ALLOCATION rather than on
writability; fixing that (KF step C, `3d45b1a98`) took whole-build `zfod` to
**86,721** and in-window `zfod` to **2,858**. The table above is retained as
the census that found the term, not as the current state — see KF below.

### The one-sentence diagnosis

Ranked by host syscall *count*, both dominant buckets are Carrick declining to
be a kernel. Ranked by CPU, the fault term dwarfs both. Both readings are
useful and they answer different questions:

- Path resolution is 55% of host syscalls because Carrick delegates `namei`
  to cap-std, whose containment walk opens *every component of every path on
  every call* with no reuse — 47.5% of all host opens arrive through a single
  function, `cap_primitives::fs::manually::open::Context::normal`, reached
  from five separate Carrick call sites. In a `go build` nearly every path
  shares a long prefix, and none of it is retained.
- The `carrick-only` bucket is `kevent`, `ulock_wake`, `ulock_wait2` and
  `psynch_cvwait`: Carrick delegating thread scheduling to Darwin and then
  arbitrating the result through a ten-slot vCPU pool. (AMP1 sizes it at 11.9%
  of host calls on the kernel lane, not the 30.1% a different program
  reported, and most of its CPU is one-time `clonefileat` container setup.)
- **And the fault term, which is larger than either**: Carrick touching 2.36 GiB
  of pages per build while servicing the guest's `mmap` calls, on a lane whose
  `mmap` already costs 1.04 host syscalls.

A kernel owns its dcache, its run queue, and — above all — its page
lifecycle. That is the work, in that order of size.

---

## Non-negotiable invariants

Unchanged from the kernel-first revision except where noted.

1. **One VM, not one VM per Linux process.** One `hv_vm_create`; Linux
   processes and threads are Carrick kernel objects.
2. **Linux semantics are authoritative.** Fork COW, shared mappings,
   open-file descriptions and offsets, close-on-exec, signals, waits, process
   groups, credentials, futexes, faults, path resolution and core contents
   match Linux observation.
3. **HVF is a HAL.** It owns vCPU execution and stage-2 mappings. It does not
   define task or address-space structure.
4. **Stage-2 represents physical frames, not process banks.** A frame gets a
   stable global IPA while live and is mapped into stage-2 once; multiple
   address spaces map it through their own stage-1 tables.
5. **Isolation lives in stage-1 plus kernel ownership.** ASIDs tag TLB
   entries; per-mm mappings and frame permissions prevent cross-process
   access.
6. **Writable fork state is real COW.** Parent and child initially share
   frames read-only; a permission fault copies only the affected compound
   frame and leaves the peer byte-identical.
7. **No global lifecycle serialization by default.** Any broader lock needs a
   written invariant and a measured necessity.
8. **Prepare then commit.** Address-space replacement is built off to the
   side; the visible transition is short, atomic and rollback-safe.
9. **Correctness precedes fast paths.** No shortcut may approximate Linux
   blocking, memory ordering, signals, synchronous errors, fd offsets, wake
   semantics — or **path containment**. A resolution cache is only sound if a
   guest cannot reach a byte outside its root through it, under rename, under
   symlink, and under concurrency.
10. **Observability is a kernel ABI.** Typed events carry Linux PID, TID,
    ASID/mm identity, operation, phase and outcome. Empty or incomplete
    captures fail closed.
11. **Crash artifacts describe the guest kernel view.** Linux ELF cores with
    guest threads, registers, mappings, auxv, siginfo and file-map notes.
12. **Measured performance authority remains clean.** DTrace/LLDB attribute;
    untraced same-binary ABBA decides retention.
13. **NEW — every Darwin call Carrick makes is Carrick's own.** A third-party
    crate may not sit on a hot kernel path and dictate the host syscall shape.
    We bind `openat`/`fstatat`/`mkdirat`/`unlinkat`/`renameat`/`mmap`/
    `__ulock_*`/`kevent` ourselves, because the amplification factor of a
    guest operation is a property of that lowering and cannot be tuned from
    outside it.

---

## Kernel object model

Converging on explicit, independently testable objects rather than one large
dispatcher clone. `Task`, `Thread`, `Mm`, `VmObject`, `FrameTable`,
`PageTable`, `FileTable`/`FileDescription`, `SignalState`, `Scheduler` — as
specified in
[`docs/superpowers/specs/2026-08-09-hvpatch-k1-kernel-object-model.md`](docs/superpowers/specs/2026-08-09-hvpatch-k1-kernel-object-model.md),
which K1 delivered.

This revision adds two:

- **`Namei`** — Carrick's own path resolver, and the `DirCache` behind it:
  containment-proven directory fds keyed by guest path, with explicit
  invalidation on the operations that can move a directory. Every path-taking
  syscall resolves through it; nothing else opens a guest path.
- **`Executor`** — a persistent `(host thread, HVF vCPU)` pair. Guest threads
  are data that migrate between executors. Design decided in
  [`docs/superpowers/specs/2026-08-13-mn-scheduler-design.md`](docs/superpowers/specs/2026-08-13-mn-scheduler-design.md).

The syscall layer takes a `KernelContext` naming the current task, thread, mm,
files, credentials and cancellation/signal state.

---

## Phase status at a glance

**Updated 2026-08-13, re-ranked for KERNEL COMPLETENESS.** Performance is no
longer a scheduling criterion, so the phases split into a critical path and a
parked set. Every row names the ONE thing that unblocks its next step.

### The critical path — finishing the kernel

| phase | status | landed | next concrete step |
|---|---|---|---|
| **KI** kernel identity *(new)* | **in progress; mechanism SETTLED by measurement** | `guest_pid_is_live` routes 3 of 4 liveness probes to the task registry; duplicate root-tid derivation removed | close the remaining comparators, then seed the root at 1 in `hvpatch/mod.rs:626` — the FATAL objection does not apply to a lane-scoped reseed |
| **KP** conformance proof | **started** | kernel lane added to the harness; first gate: **304 PASS / 90 FAIL**, 26 kernel-lane-specific | bless `baseline.hvpatch.jsonl`; close the 26, largest cluster first |
| **KD** diagnostics | **partial** | ELF core writer + validator; crash reports as signal death, oracle-matched | build a `CoreDump` from live state — a correct first slice needs NO memory plumbing |
| **KL** lifecycle | **partial** | per-task user AND system CPU, oracle-matched; `CLONE_PIDFD` scoping; concurrent sibling fork | `ru_maxrss`/`ru_majflt` still host-sourced; per-task `/proc` authority |
| **KX** kernel exec | **partly built** | Kernel two-phase exec transaction LIVE; three image caches default-on | **correctness half only**: does exec failure leave the old image valid? |

### Parked — performance-only, off the critical path

| phase | why parked |
|---|---|
| **KM** kernel memory | RE-CLASSIFIED as performance: `forkcow`/`forkshared` PASS on this lane; no probe shows a COW divergence |
| **KF** page lifecycle residue | step C landed; the remainder is fault-count reduction, i.e. pure CPU |
| **KN** namei ratio gate | the dcache landed and is correct; driving `openat` 17.75x → ≤2.0 is a CPU claim |
| **KS** scheduler | its correctness argument (slot-starvation deadlock) is real, so it re-enters the path if that deadlock recurs; its CPU argument does not schedule it |

**KI is new and is not a renaming.** The identity work was spread across KL, KP
and the signal cluster, and treating it as one phase is what made its ordering
constraint visible: the host-pid comparators must close BEFORE the id space is
reseeded, because they are correct at either seed while the reverse order
points a signal at `launchd`.

**Where completeness stands.** The kernel lane fails **90** of 394 line-exact
probes, **26** of them kernel-lane-specific, and has **no blessed baseline**.
Node.js does not run at all. Those are the numbers that schedule work now.

**Performance, for context only:** cold `go build` is **3.803 CPU-s** / **1,828
ms** (from 4.223 / 2,051 at the K1 boundary). It is recorded as a regression
floor — do not make it dramatically worse — and is no longer a gate.

**Next, in order, and both serve kernel completeness rather than speed.**

1. **Guest pid identity — and it is NOT the one-line fix it looks like.**
   The kernel's id space is seeded from the host pid
   (`dispatch/mod.rs:2475`, `kernel/core.rs:222`, `kernel/registry.rs:31`), so
   guest processes get 55233, 55234, 55235 where Linux gives 1, 2, 3.
   Two designs for reseeding at 1 were built and **both refuted**
   ([evidence](docs/perf-results/2026-08-13-hvpatch-guest-pid-identity-design.md)):
   - **FATAL** — native and vmm run TWO id allocators that agree today only
     because both derive from the host pid; reseeding moves one and silently
     breaks thread identity on both must-not-regress lanes.
   - **MAJOR** — `LINUX_BOOTSTRAP_PID` (1) is an unconditional self-alias in
     six live comparators, harmless today only because no task ever holds id 1.
   - **MAJOR** — it would not even fix `kill(getpid())`: `kill` returns ESRCH
     from the ns translation at `signal.rs:1172-1180` before the self-target
     test at `:1193` is reached.
   - **HAZARD, which fixes the ORDER** — today a leaked guest pid matches
     nothing and ESRCHs; at 1..N it names real host processes, and pid 1 on
     macOS is `launchd`. **Close the host-pid comparators FIRST**, as their own
     commit: they are correct at either seed, which is what makes that ordering
     safe.

   **The mechanism is now SETTLED by measurement, not inference**
   ([evidence](docs/perf-results/2026-08-13-hvpatch-id-mechanism-settled.md)).
   `carrick debug hvpatch-kernel` on a live run with a forked child says the
   root task id IS the host pid (70828, `hvpatch-root`), children are allocated
   at root+1 (70829, 70830), and a child's `getpid()` is EXACTLY its task id —
   so there is one authority per child and the number is wrong because the ID
   is wrong. The root alone is mapped to 1, which is why a parent and its child
   answer from different schemes. `process_group` and `session` are 70828 for
   every task, and the guest sees it: a child's `/proc/self/stat` reports
   `pgrp=70954 sid=70954` where Docker reports `1` and `1` — so job control is
   broken too, which is what the `waitpgid`/`setpgidparentgroup` failures are.

   **This retires the FATAL objection for a LANE-SCOPED reseed.**
   `initialize_root_process` returns early for non-hvpatch lanes
   (`hvpatch/mod.rs:619-621`), so seeding the root at 1 THERE cannot reach
   native or vmm, which bootstrap through `bootstrap_one_task_binding`
   instead. The two MAJOR objections survive and are still the work.

   **Step 1 started (`f6bf85701`).** Three of the four `kill(pid, 0)` liveness
   probes now ask carrick's kernel through `guest_pid_is_live`, which returns
   `None` on lanes with no task registry so the reference lanes keep their host
   probe unchanged. The fourth probes a process GROUP and needs a group
   authority the kernel does not expose yet. `threaded_loop.rs`'s duplicate
   derivation of the root leader tid from `std::process::id()` is gone.
   **Still open in step 1:** the six `LINUX_BOOTSTRAP_PID` self-aliases
   (`abi_args.rs:62`, `creds.rs:415`, `:459`, `signal.rs:1193`, `:1934`,
   `:2223`), `libc::kill` at `signal.rs:2326`, `cred_ipc::read_target` at
   `signal.rs:2269`, and the group probe at `proc.rs:3585`.
2. **The per-thread register file** — step 1 of KD (a core with wrong
   registers is worse than none) and step 2 of KS. Two phases converge on it.
   Note the KD spec calls this "the one genuinely missing input" and that is no
   longer true: `Aarch64VcpuSnapshot` already carries GPRs, PC, PSTATE, SP_EL0,
   TPIDR_EL0, V0–V31 and FPSR/FPCR, and the fork path proves it correct. What
   is missing is that nothing BUILDS a `CoreDump` from live state — the writer
   has no callers outside its own module.

---

## Phases

Ordered by measured leverage. Each phase publishes a durable evidence
document at its boundary (see the protocol at the end) and each gate is
stated so it can fail.

### KF — kernel page lifecycle  ·  *first step landed and retained; residue remains*

> **Status 2026-08-13:** step C landed at `3d45b1a98`. The arena watermark is
> raised by **writability** rather than by allocation, at all three points where
> a range can become guest-writable. Measured, five samples per arm, untraced:
> **−6.9% CPU, −12.2% system, −5.7% window, non-overlapping distributions.**
> Faults: in-window `zfod` **148,758 → 2,858** (−98.1%), whole-build `zfod`
> **230,298 → 86,721** (−62.3%).
> `just ci` green (3,886 tests); probe-gate failure set byte-identical to
> baseline; every memory-invariant probe passes
> ([evidence](docs/perf-results/2026-08-13-hvpatch-kf-scrub-ceiling.md)).
>
> Both standing predictions held: faults DID partly move to the guest's own
> first touch (in-window −98% but whole-build −62%), and most of them genuinely
> disappeared, landing in the band the oracle predicted. **Mechanisms A and B
> below are still available for the residue** — re-census first, because the 66
> large mappings are no longer the population they were.

**Remit:** stop Carrick touching pages it does not need to touch. One cold
build takes 279,987 `as_fault` and 230,298 `zfod`; 150,749 of those land inside
`mmap` service windows at **76.7 zero-fill faults per guest `mmap`**, while
`mmap`'s host-syscall amplification is already 1.04x. At this tree's measured
per-fault cost that term is on the order of the whole ~1.97 CPU-s the goal must
remove. Nothing else measured on this lane is that size.

**The mechanism is named, and the gap is one sentence.** Bucketing every guest
`mmap` by shape shows **99.1% of the faults are ANONYMOUS / private /
read-write mappings** — 1,261 calls, 3.11 GB, 145,453 faults. All file mappings
together contribute ~1,350. PROT_NONE reserves are already correctly lazy: 525
calls reserving 83.7 GB take *four* faults between them. The chain is

```text
mmap → GuestMemory::zero_anonymous_reuse   (DEFAULT impl, memset)
     → zero_backing → HvfVmState::zero_guest_backing → __bzero
```

and `zero_anonymous_reuse` is a trait method the **native lane overrides**
(`carrick-dsr-aarch64/src/mapped_memory.rs:4252`, the 2026-08-07 remap that
took its in-window `zfod` 553k → ~723) and the **HVF lane does not override at
all**. The kernel lane takes the memset default and pays 145,453 faults for it.

> [!WARNING]
> **An earlier revision of this section blamed the file-mapping eager buffer
> and the `!PROT_EXEC` lowering guard. That was code reading, and measurement
> refuted it** — it would have aimed a whole phase at 0.9% of the term. The
> record is corrected in
> [the ledger](docs/perf-results/2026-08-13-hvpatch-kernel-lane-amp-ledger.md).
> Two rules earned this the hard way, in one afternoon: *verify diagnoses
> empirically*, and *rank by measured CPU, never by inference.*

**Two traps already found, so KF does not re-pay them:**

- Removing the zero-then-overwrite double-write removes **no** faults. The page
  faults on first touch either way; skipping the `bzero` moves the fault, it
  does not delete it.
- The native fix does not port as-is: the kernel lane's arena is `hv_vm_map`'d
  into stage-2, so replacing host pages under a live IPA may leave the guest
  reading the old ones. Whether HVF actually behaves that way is the phase's
  first thing to establish, not assume.

**And the per-call shape makes KF small.** Faults per individual `mmap` are
extremely skewed: 272 of 1,274 anonymous RW calls are already free (the arena's
high-water bump path working), most of the rest cost a handful of pages, and
**66 calls carry ~90% of the whole term** at ~1,500–2,000 faults each — single
16–32 MB mappings memset whole, the Go runtime's heap-arena commits. So this is
not "redesign the arena": a whole-range replacement applied only to LARGE
reused scrubs turns one syscall into ~1,500 avoided faults, and a conservative
size threshold captures most of the term while leaving the many small scrubs
and their correctness surface alone.

**The ceiling is measured, from the oracle.** Docker's Linux already does what
KF proposes — demand-zero on first touch, nothing pre-scrubbed — so its
minor-fault count IS the memory the workload genuinely needs: **55,126 faults ×
4 KiB = ~226 MB**, against the **~2.38 GB carrick scrubs**. carrick touches
**~10.5x more memory than the guest needs**, so the standing objection that
"removing the scrub just moves the fault to first touch" is quantitatively
wrong here. Ceiling: **62–90% of the term, ~15–20% of the build**
([evidence](docs/perf-results/2026-08-13-hvpatch-kf-scrub-ceiling.md)).

**Three designs were built and all three adversarially refuted** — the
`MAP_FIXED|MAP_ANON` port (fatal: destroys the host VM entry `hv_vm_map`
registered, which `carrick-mem/src/memory.rs:549-566` forbids because revoking
it needs EL2-only `TLBI IPAS2E1`), `madvise(MADV_ZERO)` (fatal: two unverified
XNU properties, plus a concrete stale-read sequence), and a provenance ledger
(fatal twice: `MADV_DONTNEED` clears it over still-writable ranges with no store
hook, and `CLONE_VFORK`'s `VM_INHERIT_SHARE` breaks per-process marks). Read
those before proposing a fourth.

**Two mechanisms survive, both already shipped in this tree:**

- **`hv_vm_unmap` then `hv_vm_map` at the same IPA** is not hypothetical — the
  hvpatch `execve` path does it 67 times per build inside a live VM on a
  running vCPU (`trap.rs:6612`, `:7044-7053`), and at ~7 µs per call against
  ~6.42 µs per avoided fault, one pair replacing a 1,500-fault scrub is a
  ~1000x trade. Blocked on two checkable things: no precedent for unmapping a
  SUB-RANGE of the single 32 GiB arena extent, and no evidence the swap is
  coherent for other live vCPUs.
- **Stage-1 re-pointing to a fresh IPA** (`repoint_private`-style) avoids
  stage-2 entirely, using the EL1 TLBI carrick already owns. Its finite
  alias-IPA budget makes it a fit for exactly the 66 large mappings and not the
  long tail — which is the shape the measurement found.

**Do the smallest safe step first:** `mmap_dirty_high` is a bug on its own
terms — a watermark named "dirty" raised on ALLOCATION rather than on
writability (`dispatch/mem.rs:1649`, `:1680`, `:3803`), so a `PROT_NONE`
reserve the guest can never store to poisons it. Fixing what it measures needs
no Darwin primitive and no HVF qualification. Then re-measure, then take the
large tail. **Invariant 9 is binding throughout:** anonymous `mmap` returning
zeroed pages is not tradeable, so the lever must remove the work, not the
guarantee.

**Gate:** in-window `zfod` on the cold build **below 10,000** (from 150,749);
total `as_fault` **below 60,000** (from 279,987); the anonymous-zero guarantee
proved by differential probe, not by argument; `just ci` and `conformance-quick`
green; a retained untraced ABBA. This is the phase that must move the ratio —
if it lands and the ratio does not move, the goal's arithmetic is wrong and
that finding is the deliverable.

### KN — kernel namei  ·  *landed partial; retained win, gate not met*

> **Status 2026-08-13:** landed at `8d6696a94`. Measured **−3.1% CPU, −5.1%
> workload window, −12.7% system time**, non-overlapping distributions, five
> samples per arm
> ([evidence](docs/perf-results/2026-08-13-hvpatch-kernel-namei.md)). Retained.
> It also closed a shipped cross-process staleness bug in the stat cache and
> removed cap-std from the hot path, which invariant 13 requires.
>
> **The syscall-ratio gate was measured and NOT met.** `openat` 32.78 →
> **17.75**, `newfstatat` 13.84 → **7.07**, `mkdirat` 90.96 → **45.18**,
> overall 4.71x → **3.28x** — roughly halved, against a gate of ≤ 2.0
> ([ledger](docs/perf-results/2026-08-13-hvpatch-kernel-lane-amp-ledger.md)).
> The dominant host call inside every path-op window is still `openat`, so
> something is still walking: the leaf, the fallback cases, or a prefix the
> cache could not serve. Finishing it is real work, honestly sized at **under
> 8%** of the build (all path ops together are 384 ms of 1,014 ms of
> host-syscall CPU).
>
> This phase is what forced the CAUTION above: it was ranked first on syscall
> count and is worth single digits of CPU.

**Remit:** Carrick owns path resolution. A `DirCache` of containment-proven
directory fds turns every path operation into *at most one* host `*at` call on
an already-resolved parent, amortising directory resolution across the calls
that share a prefix. cap-std leaves the hot path.

The building block already exists and is proven: `HostFsBackend`'s
`parent_fds` interned anchors plus `fd_contained_under` (`F_GETPATH` under the
sandbox prefix). Today it is private to `stat_cache_get_or_fill`, holds only
`Weak` references, and the other five cap-std entry points
(`RootFsVfs::lookup_nofollow`, `path_stat_record`, `FsBackend::is_deleted`,
`resolve_at_path`, `open_at_path_string`) each pay a full walk. KN promotes it
to a kernel object and routes everything through it.

**Correctness is the hard part, not speed.** A cached dirfd names an *inode*,
not a path: if the guest renames the directory, the entry must die. The
invalidation obligations are rename, exchange, rmdir/unlink-of-directory, and
the fast-path errno rule this tree already ships (only `ENOENT` is
authoritative on a contained fast path; errnos Carrick synthesises from its
own flags must fall back). Symlinked intermediates and absolute symlink
targets keep the manual re-rooting path.

**Gate:**
- host-syscall amplification for `openat`, `newfstatat`, `mkdirat` and
  `unlinkat` each **≤ 2.0**, from the same ledger instrument that measured
  32.78 / 13.84 / 90.96;
- overall host/guest syscall amplification **≤ 2.0x** (from 4.71x);
- red-first differential probes against the Docker oracle for: symlink
  escape via `..` and via absolute target, rename-out-from-under a resolved
  directory, `ENOENT` vs `ENOTDIR` vs `ELOOP` on every path syscall, and
  `O_NOFOLLOW` leaf behaviour;
- `just ci` green; `conformance-quick` green;
- an untraced same-binary ABBA on the cold build showing a retained win.

### KS — kernel scheduler  ·  *the second bucket, 30% of host syscalls*

**Remit:** replace welded thread-per-guest-thread plus the ten-slot vCPU pool
with N persistent executors and a real run queue. Blocking releases the
executor immediately and holds nothing, which removes the slot-starvation
deadlock class by construction rather than by rationing. Futex wait queues,
timekeeping and signal delivery become kernel queues rather than host
primitives.

Design is decided; this phase implements it. The independent reasons to do it
are correctness (the start-gate wedge was slot starvation), determinism, and
that it is the only thing that touches the `carrick-only` bucket.

**Gate:** `carrick-only` host syscalls **below 10%** of the run; host thread
count on the cold build proportional to cores, not to the 69 guest processes;
no vCPU destroy/recreate on the steady path; two concurrent cold builds run
without deadlock; `just ci` and `conformance-quick` green; retained ABBA.

### KM — kernel memory  ·  *structural, not a CPU lever*

**Remit:** the old K2, honestly re-scoped. Global IPA-backed frames, VM
objects, persistent VMA roots, COW stage-1 table paths, demand allocation,
immutable file/image sharing, scoped TLB maintenance, deferred reclamation.
Today there is **no guest-visible COW at all** — the child's stage-1 leaves
are built read-write for every writable mapping, so no guest store ever takes
a COW fault. Building that is this phase's core work.

Measurement has already ruled two levers out of scope: `PageTablesRebase`
(1.3% of fork) and `ParentPageTablesClone` (4.4%, and its removal changed
nothing measurable at `ba26307a5`). Inside fork, attack `PrivateSnapshot` —
the per-mapping `mach_vm_remap(copy=TRUE)` whose size argument names a 32 GiB
arena — and nothing else.

> [!IMPORTANT]
> **RE-CLASSIFIED 2026-08-13: KM is a PERFORMANCE-and-STRUCTURE phase, not a
> correctness phase.** The observation above — that the child's stage-1 leaves
> are built read-write and the parent's tables are never write-protected —
> remains factually true at `trap.rs:6312-6317`. The inference drawn from it
> did not: fork isolation is provided instead by `mach_vm_remap(copy=TRUE)`
> (`carrick-host/src/host_mapping.rs:96-137`), invoked per private mapping by
> carrick itself — and NOT by Darwin's fork COW, because the kernel lane never
> `libc::fork`s for a guest fork; it spawns a thread (`quiesce.rs:1270-1276`).
> **It works:** `forkcow` and `forkshared` both PASS on this lane, on musl and
> gnu, while the native lane FAILs `forkcow`. No probe in the gate shows a
> COW-semantics divergence.
>
> So KM must be justified as **cost and structure**, and retained on a **CPU**
> gate with correctness held constant — not sold as fixing a correctness bug it
> does not have. The cost is real: `PrivateSnapshot` is 70.6% of fork's
> process-spec work and still passes a literal 32 GiB `size` argument
> (`trap.rs:6265-6267`), plus an unmeasured 34 GiB child-side `hv_vm_map`.

**Gate:** differential probes for anonymous/file/private/shared mappings,
fork-write divergence, truncation/SIGBUS, `mprotect`, `munmap`, `brk`,
concurrent faults must all stay green (they are green today — this phase must
not lose them). Fork work scales with writable table paths and touched frames,
not virtual span. No whole-span remap remains in the fork path. **Retention is
a measured CPU win on the cold build**, since correctness is already held.

### KL — kernel lifecycle

**Remit:** fork/clone/vfork task creation on the new objects — file-description
sharing, signal and credential rules, pidfds, parent/TID stores, exit, wait,
groups, sessions — and per-task accounting. Replace stop-the-world polling
with a minimal generation/permission barrier whose scope is proven by tests.

Partly landed: per-task CPU ledgers source `times`/`getrusage` from `Task`
rather than from the host process
([evidence](docs/perf-results/2026-08-13-hvpatch-per-task-cpu-ledgers.md)),
`CLONE_PIDFD` installs are scoped to the forking parent, and sibling threads
fork concurrently.

**Per-task SYSTEM time landed at `f850336c5`** and closed the gap this section
used to record as open. The vCPU exec slots only see time inside
`hv_vcpu_run` — the guest running its own instructions, i.e. USER time — so
the CPU carrick spends SERVICING syscalls was counted nowhere and `stime` read
zero. `Thread` now charges it at the dispatch boundary from
`CLOCK_THREAD_CPUTIME_ID`, so a task blocked in `wait4` accrues none, as on
Linux. Red-first against the oracle, and it cost nothing measurable (−0.2%,
within noise).

**Known open:** `ru_maxrss` and `ru_majflt` remain host-sourced — they
describe the address space, which is not yet accounted per task.

**Gate:** Docker-oracle probes and relevant LTP cases match; the canonical
build retains 68 forks / 67 execs / 69 processes; mean fork critical path
below 0.5 ms, p95 below 1 ms; no work proportional to sparse virtual extent;
per-task user *and* system time both correct against the oracle.

### KX — kernel exec

> **Status 2026-08-13: "not started" was wrong — two of the five remit clauses
> are already built.** The Kernel-object two-phase exec transaction is LIVE
> (`kernel/exec.rs:159` prepare, `:267` commit, reached from
> `hvpatch/mod.rs:299`), and all three image caches exist and are default-on.
> What is genuinely absent is the **address-space half**: build outside the
> lock, atomic commit, deferred teardown, and independent concurrent
> preparation.
>
> **Do this first, before any KX measurement:** the exec runtime-stage
> instrument is broken and fails closed.
> `carrick-observability/src/probes.rs:734` declares `CloseCloexec = 1` but
> nothing has emitted it since `78bfa986c`, so
> `scripts/dtrace/hvpatch-phase4-exec-runtime-stages.d:102`'s
> `events == completes * 6` assertion can never hold. Either re-emit it around
> `exec.rs:436-438` or delete the ordinal and renumber. Nothing else in this
> phase can be judged until that reports.

**Remit:** build replacement address spaces outside lifecycle locks, cache
immutable image objects and patch manifests by authenticated provenance,
commit the new `Mm` atomically, defer teardown, allow concurrent execs in
disjoint tasks to prepare independently.

**Gate:** exec failure leaves the old image valid; multithreaded exec,
CLOEXEC, signals, credentials, interpreter chains, `/proc/self/exe` and
dynamic ELF behaviour match Docker; commit critical section below 0.1 ms p95;
post-load replacement below 1 ms mean on the cold-build fixture.

### KD — kernel diagnostics

**Remit:** Linux-style ELF cores with `PT_LOAD` memory, per-thread register
notes, `NT_SIGINFO`, `NT_AUXV`, process identity and file-mapping notes;
`carrick debug core` to validate and summarise them; LLDB tooling that
navigates guest tasks, threads, mappings, frames, fds, signals and the event
ring from live state or a core without treating host pointers as guest virtual
addresses.

The writer and validator are landed (`96dcc3179`, `b26187d93`) and externally
validated; the wiring spec is
[`docs/superpowers/specs/2026-08-13-core-dump-wiring.md`](docs/superpowers/specs/2026-08-13-core-dump-wiring.md).

**A worse divergence than that spec assumed was found and fixed
(`1aa5db553`).** The spec expected `core_dumped_si_code` to set `CLD_DUMPED`
without producing a file. In fact a guest that dereferenced NULL was not
reported as signal-terminated AT ALL — `RunResult.exit_code` carried both "the
guest called exit(N)" and "a signal killed it" folded into `128 + signum`,
which is byte-identical to a real `exit(139)`. That was harmless while a Linux
process was a host process (the host child genuinely died of the signal); under
the kernel lane it is a thread, so the distinction had to be in the value and
was not. `RunResult` now carries `terminating_signal` and owns the encoding in
one place. `child_was_signaled`, `child_exited_normally` and
`child_died_of_sigsegv` now all match the oracle.

**Known open, and deliberately left red:** `wcoredump_set` still diverges —
carrick writes no core. `conformance-probes/src/bin/coredumpfile.rs` is the
gate. **The blocker is the per-thread register file**, which is also KS's step
1; see the status table.

**Gate:** a guest that faults produces a core that `carrick debug core`
validates and LLDB navigates, from the crash path and not only on demand;
every capture fails closed on missing identity or events.

### KP — shipped proof

> **Status 2026-08-13:** the line-exact probe gate had **never been run on
> this lane** — `conformance.rs` reads `CARRICK_EXEC_BACKEND` and, unset, uses
> the shipped `native` default, so every probe receipt in this tree's history
> is a NATIVE-lane receipt. Run against `hvpatch` for the first time it gives
> **304 PASS / 90 FAIL** on `arm64:musl`, where the native lane fails 124 at
> the same commit. 64 failures are shared with native (dispatcher-level), 60
> are native-only and out of scope, and **26 are kernel-lane specific** — the
> KP work list. Ten of those 26 are one cluster: signal delivery and its
> targeting identity, which is the same one-host-process identity problem the
> per-task accounting fixes solved twice
> ([evidence](docs/perf-results/2026-08-13-hvpatch-first-probe-gate.md)).

**Remit:** establish `baseline.hvpatch.jsonl`, close the gaps that the kernel
lane's own conformance run exposes, and **make `hvpatch` the default
backend** — the reference lanes stay available and stop being parity
obligations. Validate the shipped claims on the shipped signed binary.

**Known blocker, already found:** Node.js does not run — every `node:22-slim`
start aborts in V8 startup-snapshot deserialization, which points at Carrick's
`mmap` hint/reserve/commit lowering rather than anything Node-specific
([evidence](docs/perf-results/2026-08-13-hvpatch-node-blocker.md)). This is a
KM/lowering item and it gates KP.

**Gate — the goal completes only when all of these are measured on the exact
shipped binary:**
- cold `go build` **below 2.3 CPU-s** against serialized native-arm64 Docker;
- CPython, Node.js and Rust workloads **within 2x** Docker;
- conformance gates green on the kernel lane, with its own blessed baseline;
- one-VM topology, isolation stress, bounded failure and crash-tool recovery
  demonstrated.

Green CI, a projected speedup, or an intermediate prototype is not completion.

---

## Evidence and progress protocol

At every phase boundary publish a durable evidence document containing:

- exact commit, signed binary hash and `LC_UUID`, host/OS/HVF provenance,
  image digest, fixture argv and environment, raw artifact hashes, scoped
  `CARRICK_RUN_ID`;
- measured results separated from projections, and traced attribution
  separated from clean untraced authority;
- Linux/Docker differential results, relevant conformance cases, concurrency,
  isolation, rollback and bounded-failure results;
- task/thread/mm/ASID/frame populations and any missing or ambiguous events;
- performance totals, distributions, opportunity arithmetic, ABBA order and a
  perturbation declaration;
- GO/KILL/RED/GREEN, retained commits, rejected experiments, risks, and the
  next architectural question.

Never run Carrick and Docker concurrently. Build and sign through the
repository recipes. Preserve durable D/LLDB/core artifacts. Require a scoped
`CARRICK_RUN_ID`. Run `just ci` before committing an accepted phase. The
perf fixture records its `exec_backend`, so two arms can never be compared
across backends by accident.

## Historical decisions carried forward

| Prototype phase | Decision |
|---|---|
| Phase 0 | GO — exit-free branch/island and compute assumptions proved; `TPIDR_EL0` patching rejected because native reads do not trap. |
| Phase 1 | Complete — distinct signed `hvpatch` backend runs static and dynamic ELF images. |
| Phase 2 | Closed no-go — 4.55 CPU-s passed, but the listed fast paths could not reduce 68,276 exits below 20K. |
| Phase 3 | Closed no-go — mapped read/write batching was semantically invalid or arithmetically short of the exit gate. |
| Phase 4 prototype | One VM, correct 68/67/69 lifecycle and output; ~4.27 CPU-s and 2.728 ms post-load exec remained RED. |
| K0 / K1 | GO. See `docs/perf-results/2026-08-08-hvpatch-phase0-decisive-probes.md` and the K1 evidence set. |

Rejected mechanisms and stale projections from those phases are **not**
inherited; their receipts under [`docs/perf-results/`](docs/perf-results/) are.
The full text of both prior plan revisions is in git history.
