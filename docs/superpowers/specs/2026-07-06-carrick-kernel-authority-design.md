# Carrick kernel authority design

Date: 2026-07-06 (rev 2, 2026-07-07)

Rev 2 rewrites the architecture half of this design. Rev 1 proposed a separate
`carrick-kernel` authority *process* fronting five services over RPC. Rev 2
keeps rev 1's goals, typed domains, generation discipline, admission classes,
and migration/validation staging, but changes the mechanism: **the authority is
a shared data structure plus the host kernel, not a daemon.** The reasons are
recorded in "Why not an authority process" below.

## Context

Carrick's macOS/HVF path keeps a load-bearing invariant: one Linux process is
one real macOS process. That gives Carrick host-visible PIDs, host scheduling,
`fork(2)`/`wait4(2)` integration, and real process boundaries without a guest
Linux kernel. The point of the project is to *remove* the VM-plus-guest-kernel
abstraction and emulate Linux directly with host-level semantics, using the VMM
only for instruction execution. Any new architecture must be judged against
that: does it add an abstraction layer, or remove one?

Empirical anchors from the 2026-07-07 bless campaign:

- The conformance bless does not converge because the measurement is
  load-coupled: the raw fork primitive costs ~3.3–3.5 ms p50 (Docker ~48 µs;
  50–75x) with a fixed HVF VM teardown/rebuild floor, so fork-heavy suites run
  10–40x long and push co-scheduled timing tests past their thresholds. An
  ad-hoc exclusive-lane list (openat03, inotify09, execve05, select02,
  go-net_http) is accumulating in the harness to compensate.
- Cross-process registration races (parent-vs-child slot registration clobbering
  `ptrace_stop_signal`/`parent_pid`) cost a day of ptrace06 debugging; the root
  cause is *post-fork* racy registration into the fork-shared child table.
- `futex_cmp_requeue01` is a known-gap because Carrick approximates
  `FUTEX_CMP_REQUEUE` with wake/requeue credits instead of an atomic move; two
  credit-tweak patches were tried and rejected under load.
- `semget05` fails because SysV semaphores are forwarded to Darwin's finite
  host-global pool while Carrick advertises Linux tunables.
- The run-state table shipped with 510 usable slots and silently fell back to
  host scheduler state when full, recreating the exact false-`S` race it was
  built to fix, for the minority of 1000-fanout waiters.

Carrick already has separate design tracks that point in the same direction:
vCPU multiplexing, the atomic HVF admission work (landed: `SharedPermitTable` +
`vcpu_permit_reaper`), SysV IPC kernel objects, and the socket network
namespace provider. This design unifies them.

## Goals

- Preserve the invariant that each Linux process is one real macOS process.
- **Hot paths pay nothing new.** Fork, syscall dispatch, block, and wake add no
  IPC round trips and at most a few shared-memory atomics. Budgets below.
- Bound live HVF VM and vCPU usage by leasing scarce VMM resources, without
  building a userspace scheduler: the host kernel schedules; Carrick only
  bounds *materialized VMM state*.
- Provide a single run-scope source of truth for Linux-visible identity,
  namespace state, and shared kernel objects — as one coherent shared region
  instead of today's ten independent ad-hoc tables.
- Make death, exec, and PID-reuse handling generation-checked and observable.
- Keep host-specific mechanics behind the existing capability boundaries so the
  same Linux-visible model serves macOS, Linux, FreeBSD, and NetBSD backends.

## Non-goals

- Do not move guest execution anywhere. The process runtime owns its guest
  memory, trap engine, and vCPU run loop.
- Do not introduce a long-lived daemon on any guest datapath, and do not build
  a userspace runnable-queue scheduler that shadows the host scheduler.
- Do not proxy syscalls. Ordinary file, socket, memory, and process-local work
  stays in-process, exactly as today.
- Do not hide incomplete Linux behavior behind test-shaping knobs.
- Do not read Linux kernel source. Behavior comes from man pages, standards,
  Linux ABI documentation, and Docker-oracle evidence.
- Nothing here is shared between unrelated Carrick runs. All state is per-run.

## Why not an authority process

Rev 1's five services (`ProcessRegistry`, `ResourceScheduler`,
`NamespaceRegistry`, `KernelObjectRegistry`, `ProviderRegistry`) are the right
*taxonomy* of cross-process state. But fronting them with a daemon and typed
RPC fails the project's own test three ways:

1. **It duplicates the host kernel.** Because one Linux process is one macOS
   process, Darwin already implements process existence, exit, zombies,
   reaping, scheduling, and wake ordering. A registry process that mirrors
   parent/child relationships and wait queues re-implements, in userspace RPC,
   exactly the kernel state we get for free — the same trap as running a guest
   Linux kernel, one layer up.
2. **It puts IPC on the fork path.** Rev 1's fork flow had the child register
   with the authority and request residency before returning from `fork` — two
   round trips through a Unix socket added to a primitive we need to take from
   3.5 ms toward the host kernel's tens-of-microseconds fork floor.
3. **The codebase already voted.** Ten subsystems independently converged on
   the same no-daemon pattern: a `MAP_SHARED | MAP_ANON` region mapped before
   the first guest fork, inherited by every descendant, synchronized with
   atomics, woken with `os_sync_wait_on_address(_SHARED)`:
   run-state table (`carrick-runtime/src/run_state.rs`), fork-shared child
   table (`carrick-host/src/guest_cpu.rs`), ulock waiter table
   (`carrick-host/src/ulock.rs`), xsignal ring
   (`carrick-signal-core/src/xsig.rs`), atomic vCPU permit table + reaper
   (`carrick-vmm-hvf/src/trap.rs`, `vcpu_permit_reaper.rs`), PID-namespace
   member region (`carrick-runtime/src/namespace/pid.rs` — already file-backed
   for late attach), eventfd counter slab, deadlock-watchdog word,
   fs-resolve-cache generation word, and fd-table pipe-capacity words.
   The permit table proves the full lifecycle at production quality: CAS
   acquire, generation-stamped slots, `EVFILT_PROC`/`NOTE_EXIT` death reclaim
   with pid-reuse gates, and a poll backstop.

What that convergence lacks is coherence: ten layouts, ten capacities (256,
1024, 4096, 8192, 65536…), ten staleness rules, and no shared lock or exhaustion
discipline. The failure modes we hit (child-table registration races, run-state
slot exhaustion, waiter keys derived from unstable guest VAs) are all symptoms
of per-subsystem improvisation, not of missing central compute. So the fix is
to promote the pattern into one designed artifact — not to replace it with RPC.

A separate process earns its existence only when something must *outlive* the
guest tree or hold host resources on its behalf. Carrick already has that
process: the per-run **NsSupervisor** (`namespace/supervisor.rs`), the parent
half of the runtime fork, which watches members via kqueue, harvests exit
statuses, reparents orphans, and tears the run down. Rev 2 extends it instead
of adding a second control plane.

## Core boundary

Three tiers, replacing rev 1's process/RPC split:

```text
Tier 0 — the Darwin kernel: process existence, exit, zombies, reaping,
  scheduling, signal carriers, file/socket/memory syscalls, futex-class
  wait/wake (os_sync_wait_on_address), death notification (EVFILT_PROC).
  If Darwin has the primitive, Darwin is the authority.

Tier 1 — the kernel arena: ONE file-backed MAP_SHARED region per run,
  mapped before the first guest fork, inherited by every descendant.
  It holds only the Linux-visible DELTA the host kernel cannot express,
  plus leases on scarce resources. No process owns it; all processes
  operate on it with atomics and robust bucket locks.

Tier 2 — the run supervisor (existing NsSupervisor, extended): the
  cold-path janitor and broker. Death-watch reclaim sweeps, provider
  fd brokering (published ports, PTYs), run teardown. Never on a
  syscall, fork, block, or wake path.
```

The per-process runtime remains the code that maps and owns guest memory,
drives vCPUs while holding a lease, decodes syscall frames, executes local
handlers, injects signal frames, and owns local fd tables and register state.

## The kernel arena

### Region mechanics

- Created by the root runtime before any VM exists, as an unlinked file-backed
  `MAP_SHARED` mapping (the PID-namespace region already does this so
  `carrick exec` can attach; file backing also lets diagnostics attach live and
  lets cores carry the full arena). The fd is inherited across fork; the path
  (under the run's temp root) allows late attach by run id.
- Fixed layout: a header (magic, layout version, run id, capacity map) followed
  by fixed-capacity typed sections. Layout changes bump the version; attach
  fails closed on mismatch.
- **Capacity is a contract.** Sections are sized for the known worst real
  fanout (LTP drives 1000+ children; the eventfd slab already sizes 65536) and
  exhaustion is LOUD: the operation fails with a diagnostic and a probe fires.
  No silent per-process fallback — the run-state 510-slot silent fallback is
  the counterexample that motivates this rule.
- The arena is plain shared memory + atomics on every supported host. Only the
  wait/wake primitive is per-host (`os_sync_wait_on_address` on macOS, futex on
  Linux, `_umtx_op` on FreeBSD, ...), already abstracted behind `PlatformFutex`.
  This makes Tier 1 *more* portable than a macOS daemon, and it is the shared
  layer the bhyve/KVM/NVMM backends reuse (high code leverage).

### Concurrency discipline

- Default operation is single-word: one `AtomicU64` slot published with a
  single release store (the run-state table's id+state packing is the model),
  claimed with `compare_exchange`.
- Multi-word records use the claim-sentinel protocol the xsig ring and
  PID-member table already use: claim → fill → publish-last.
- Operations that must be atomic across *multiple* records (futex requeue,
  SysV semop over multiple sems, wait-queue handoff) take per-bucket **robust
  locks**: a lock word holding (owner host pid, owner generation), acquired by
  CAS, waited on via the platform futex. Lock order is by ascending bucket
  key; both-bucket operations lock low key first. A holder that dies is
  detected exactly like a dead permit owner (`EVFILT_PROC` + liveness
  re-check) and the supervisor's sweep breaks the lock and marks the bucket
  for consistency repair. Buckets are small enough that repair is "rebuild the
  bucket's freelist," not a journal.
- Every slot that names a process carries (host pid, process generation);
  every lease additionally carries a lease generation. Stale releases and
  delayed death events must not free a slot now owned by a different process
  (kept verbatim from rev 1).

### Hot-path budget

These are design constraints, not aspirations; the validation section makes
them gates.

- `fork()`: the parent pre-fills the child's arena slots *before* `libc::fork`
  (one CAS + a handful of stores). The child inherits the mapping; it performs
  **zero** registration IPC and zero arena allocation on the fork path. Permit
  acquisition is one CAS (park on exhaustion, below).
- Ordinary syscalls: zero arena traffic unless the syscall semantically touches
  cross-process state (kill, wait, setpgid, SysV, shared futex, /proc of a
  sibling) — the same set that touches the ad-hoc tables today.
- Block/unblock: at most one run-state store, one permit release CAS (policy
  below), and one platform-futex wait. Wake: one CAS + one futex wake.
- Supervisor RPC: only run boot/teardown, provider setup (publish port, PTY
  create), and post-death sweeps. Never per-syscall, never per-fork.

## Services, mapped onto the tiers

Rev 1's five services survive as arena *sections* and supervisor duties.

### 1. Process identity and lifecycle

- **Tier 0 owns:** existence, exit collection, zombie/reap mechanics
  (`waitpid`, `EVFILT_PROC`), stopped/continued states, scheduling.
- **Arena owns the Linux delta**, consolidating today's three overlapping
  tables (PID-member region, fork-shared child table, run-state table) into
  one process section: host pid ↔ Linux ns-pid/tid with generations; parent /
  adopted-parent / subreaper links; process group, session, controlling-TTY
  ownership; `execed` promoted to an exec *generation* counter (rev 1's image
  generation, needed so late lease releases from a pre-exec image can't apply
  post-exec); ptrace-stop markers; Linux-visible exit metadata `wait4` needs
  that Darwin drops (guest rusage rollup, `CLD_DUMPED` synthesis); run-state
  (`R`/`S`) publication; pidfd identity.
- **Registration is pre-fork.** The parent claims and fully populates the
  child's record (ancestry, ns-pid, ptrace links) before `libc::fork`; the
  child publishes only its own liveness bit. This structurally removes the
  parent-vs-child registration races that broke ptrace06 — there is no longer
  a post-fork window where two processes race to initialize one record.
- Wait queues stay host-native: `wait*` keeps `waitpid`/kqueue as the blocking
  mechanism (including the landed wait-any kqueue fan-out), reading Linux-only
  fields from the arena after the host kernel says a child changed state.

### 2. VMM residency and vCPU leases (the resource scheduler, descoped)

The landed atomic permit table *is* rev 1's `ResourceScheduler` lease
mechanism; this design generalizes it instead of wrapping it in RPC:

- `VmResidencyLease` and `VcpuLease` become permit classes in one arena permit
  section (today's `SharedPermitTable`, moved into the arena, budget still
  sourced from the measured ceiling with `HV_NO_RESOURCES` backpressure as the
  hard floor).
- Admission classes are kept from rev 1 verbatim: `InitialExec`,
  `ForkChildBootstrap`, `CloneThreadRun`, `ExecveRebuild`,
  `WakeFromBlockingSyscall`. Class policy is data in the arena header; backend
  crates own materialization mechanics after a lease is granted.
- **Parking is a futex, not a queue.** A process that cannot get a permit
  publishes `Blocked`, then waits on a permit-availability word with the
  platform futex; each release CASes and wakes. FIFO fairness beyond futex
  wake order is explicitly not a goal — Linux doesn't promise fork fairness
  either, and the host scheduler owns who runs. Rev 1's runnable queues and
  preemption engine are **cut**; if profiling ever proves starvation, a ticket
  word can be added to the permit section without changing the architecture.
- Residency release while blocked already exists (`shared_wait_park` /
  `shared_wait_resume` destroy and rebuild the whole VM around long shared
  futex waits; the short-timed-wait keep-the-vCPU policy landed 2026-07-07).
  The lease model makes that a first-class, class-checked transition rather
  than a special case.
- Death reclaim: the permit reaper stays exactly as landed (kqueue
  `NOTE_EXIT`, generation re-check, poll backstop), extended from "permit
  slots" to "every arena lease owned by the dead pid" and re-homed under the
  supervisor (Tier 2), which already watches every member for exit anyway —
  one watcher instead of two.

### 3. Namespaces

- The PID-namespace member section is part of the process section above. UTS
  (single `guest_hostname()` today) and network namespace membership, bridge
  ids, published-port leases, and DNS aliases are arena sections; socket
  operations resolve an endpoint through the arena and then run entirely on
  Tier 0 sockets.
- Namespace-scoped `/proc`, `/proc/sys`, `/proc/net`, `/proc/sysvipc` read
  directly from the arena — a read is a scan of shared memory, not an RPC
  snapshot. (The `/proc/<pid>/stat` R-vs-S path already works this way.)

### 4. Shared kernel objects

- **SysV semaphores stop being Darwin semaphores.** Sets live in the arena
  (values, semadj, waiter buckets), waits use the platform futex, and Linux
  tunables (`/proc/sys/kernel/sem`) are honestly enforced against arena
  capacity — closing the `semget05` class without fake tunables. SysV msg
  queues likewise move from per-key files to arena rings with futex-woken
  waiter buckets (today's file-per-queue under `/tmp/carrick-shm` keeps
  working for shm, whose file backing is exactly right and stays).
- **Futex requeue becomes an atomic move.** The ulock waiter side table joins
  the arena keyed by stable (backing file identity, offset) — the keying fix
  that already landed — and `FUTEX_CMP_REQUEUE` takes both bucket robust locks
  and *moves waiter records*, so source dequeue, destination enrollment, and
  wake accounting are one critical section. This replaces the rejected
  credit approximation and is the mechanism `futex_cmp_requeue01` is
  known-gapped on. Plain wait/wake keep their current lock-free path.
- Timer ownership, process-group wake routing, and inotify-like registries
  move here only if per-process state proves non-coherent (unchanged from
  rev 1's second wave).

### 5. Providers

- Provider *state* (leases, published ports, PTY/session records, cleanup
  handles for temp roots and service regions) lives in the arena. Provider
  *resources that are host fds* (listening sockets, PTY masters) are brokered
  by the supervisor over the existing control channel, upgraded from a pipe to
  a socketpair for `SCM_RIGHTS` fd passing. These are cold operations
  (container publish, interactive session setup) — RPC is fine here and only
  here.
- Provider names do not imply semantics; capabilities define what a provider
  satisfies (kept from rev 1).

## Runtime flows

### Initial run

1. CLI/engine resolves the `RunSpec`.
2. The root runtime creates the arena, seeds its own process record, and forks
   the supervisor (as today), which inherits the arena and the watch role.
3. The root claims `InitialExec` residency + a vCPU permit (CAS), materializes
   HVF state, and enters the guest.

### Fork

1. The parent reaches the existing fork quiesce point.
2. The parent claims a child process record and fills it completely (ns-pid,
   ancestry, ptrace links, run-state `Booting`), and pre-claims the child's
   `ForkChildBootstrap` residency permit if one is free.
3. `libc::fork`. The child inherits the arena mapping, its record, and (if
   pre-claimed) its permit; it re-stamps owner pid/generation with one CAS.
4. If no permit was free, the child parks on the permit futex *before*
   materializing any VMM state — a fork storm creates host processes and Linux
   PIDs at Darwin fork speed but only `budget` live VMs.
5. The child rebuilds VMM state under its lease and returns 0 from guest fork.

No socket, no registration message, no post-fork race window.

### Clone thread

Unchanged from rev 1 in shape: the host thread and Linux TID are created and
registered (arena stores), the thread parks with saved register state until a
`CloneThreadRun` vCPU permit CAS succeeds, and it never pretends to the guest
that execution already happened. This composes with vCPU multiplexing: more
guest threads than vCPU slots, only leased threads run.

### Blocking syscall

1. The handler publishes the wait (run-state `Blocked`, plus a waiter record
   only if the wakeup is Linux-semantic — futex, SysV, checkpoint).
2. Lease policy runs locally: short finite waits keep the vCPU (landed
   policy); long/indefinite waits release the vCPU permit and, for the classes
   that qualify, VM residency (`shared_wait_park`).
3. The host wait itself stays whatever host primitive fits (kqueue, `waitpid`,
   platform futex) — Tier 0 owns the sleep and the wake.
4. On wake: reacquire per class (`WakeFromBlockingSyscall`), republish
   `Running`, resume.

### Exec

Same host pid, so no death watch fires. The runtime releases image-scoped
leases, bumps the record's exec generation (one atomic), and rebuilds under
`ExecveRebuild`. Late releases stamped with the old generation are ignored.

### Exit and death

- Normal exit: the runtime writes Linux exit metadata into its record, releases
  leases with generation-checked CASes, and exits; the host kernel delivers
  the real zombie to the real parent, whose `wait4` merges host status with
  arena metadata and retires the record.
- Hard death: the supervisor's kqueue fires; it re-verifies liveness, then
  reclaims every lease and lock stamped (pid, generation), repairs any bucket
  the dead process held locked, marks the record dead with observed host
  status, wakes waiters via the ordinary futex words, and runs provider
  cleanup. Polling remains a backstop for registration races only.

## VMM residency and the fork floor

The lease model must not just bound fork storms — it must enable removing the
per-fork rebuild tax, which is the top architectural performance debt
(epoll-ltp 36–38x, the gating waitid/splice/vmsplice cluster ~38x, getpid01,
fcntl14, fork09). Current decomposition: parent rebuild ~2.1–3.1 ms + child
rebuild ~2.4–3.5 ms, while raw `hv_vm_create` in fork churn is only
300–700 µs — most of the floor is Carrick's own teardown/replay, driven by one
constraint: a live parent VM at `fork(2)` leaves the child unable to
`hv_vm_create` ("resource busy"), so today the parent destroys its VM pre-fork
and both sides rebuild (`fork_prepare_and_teardown` / `fork_rebuild`).

Staged experiments, gated by the checked-in `perf_fork` probe and
`hvf_fork_probe`:

- **E1 — parent keeps its VM.** Probe whether the *child* can clear the
  inherited HVF state (child-side `hv_vm_destroy` before its `hv_vm_create`)
  without perturbing the parent's live VM. KVM already has this shape (the
  child's inherited fds point at the parent's VM; the child rebuilds its own;
  the parent keeps running), so E1 is an HVF-parity question, answerable with
  a ~50-line `hvf_fork_probe` mode. If HVF allows it, the parent's ~2–3 ms
  rebuild disappears from every fork, and `ForkChildBootstrap` admission stops
  double-charging the parent's slot.
- **E2 — lazy stage-2 replay.** Rebuild with zero eager `hv_vm_map` calls and
  map regions on first unmapped-IPA exit (the trap loop already classifies
  these translation faults). A fork-and-exit child (the LTP protected-region
  pattern: thousands of one-syscall children) pays for the two or three
  regions it touches instead of the full map set. Sibling-union replay
  becomes lazy for free.
- **E3 — coalesce the map set.** Fewer, larger contiguous regions so eager
  replay, where still needed, is a handful of `hv_vm_map` calls.

Target: fork p50 < 1 ms as the first milestone (order-of-magnitude), with the
stretch goal bounded by `hv_vm_create`+`hv_vcpu_create` (~0.5 ms) on the child
side only. Success is measured by `perf_fork` and by the epoll-ltp/waitid/
splice conformance ratios, not by any single LTP row.

## Failure model

There is no daemon whose death can strand the hot path. The arena lives as
long as any process maps it; robust locks make a crash mid-critical-section
recoverable; generations make stale ownership harmless.

- Supervisor death is a run-scope failure exactly as today (it is already the
  process that propagates init's exit): members detect the control channel
  closing, no new provider resources are granted, and cleanup falls back to
  process death plus scoped temp-root sweep. Fail closed.
- Arena attach with a wrong magic/version fails closed with a diagnostic.
- Section exhaustion fails the specific operation loudly (Linux errno where
  one exists — `EAGAIN`/`ENOSPC` — plus a probe); it never silently degrades
  to process-local state.

## Typed domains

Unchanged in spirit from rev 1; raw values cross only at syscall wire, host
libc calls, procfs text, and the arena's `#[repr(C)]` slot layouts, with
constructors naming the crossing. Domains: `RunId`, `HostPid`, `LinuxPid`,
`LinuxTid`, `LinuxProcessRef`, `LinuxThreadRef`, `PidNamespaceId`,
`ProcessGeneration`, `ExecGeneration`, `LeaseGeneration`, `PermitClass`,
`VcpuSlot`, `NetworkNamespaceId`, `BridgeId`, `KernelObjectId`,
`ArenaSectionId`, `BucketKey`, `ProviderLeaseId`. (Rev 1's `WaitQueueId` and
residency-lease ids collapse into `BucketKey` + `PermitClass` +
`LeaseGeneration`.)

## Relationship to existing designs

- The atomic HVF permit design is no longer "the macOS implementation strategy
  for the scheduler" — it is the seed of the arena itself; the permit table is
  the first section to move in.
- vCPU multiplexing keeps its per-backend execution strategy and consumes
  `CloneThreadRun`/`WakeFromBlockingSyscall` permits from the arena.
- The SysV IPC service and the socket network-namespace provider become arena
  sections plus (for sockets/PTYs) supervisor-brokered fds.
- The interactive supervisor and PTY relay converge on the process section for
  process-group/session/ctty authority instead of a parallel model.
- The go-net_http epoll blocker is intentionally OUT of scope here: it is a
  per-process typed-state-machine fix (guest-visible readiness = the
  Linux-deliverable queue), tracked in
  `docs/2026-07-06-go-net-http-epoll-diary.md`.

## Migration plan

Each step independently shippable; default behavior unchanged until a step's
gates pass. Order chosen so correctness wins land before scheduler behavior
changes.

1. `carrick-kernel` crate: arena layout (header, sections, capacities), the
   claim-sentinel record protocol, robust bucket locks, generation types, and
   exhaustive unit tests (including kill-9-mid-lock repair). No runtime
   dependency yet.
2. Move the vCPU permit table into the arena (mechanical relayout; reaper and
   backpressure semantics unchanged; flock fallback retired or kept behind the
   existing env flag).
3. Consolidate the process tables (PID-member region, fork-shared child table,
   run-state table) into the arena process section; `execed` becomes an exec
   generation. Pure relocation with the *existing* registration flow.
4. Flip fork registration to parent-pre-fills-child (removes the post-fork
   race window; delete the self-registration/late-parent repair code that
   ptrace06 needed).
5. Fork-child park-before-materialize: `ForkChildBootstrap` permits gate VMM
   rebuild; fork storms hold host processes, not VMs. (Rev 1 step 5, now one
   CAS instead of an RPC.)
6. Move the ulock waiter table into the arena and implement requeue as a
   two-bucket atomic move; retire the credit machinery; unmark
   `ltp-futex_cmp_requeue01`.
7. SysV semaphores (then msg queues) as arena objects with honest tunables;
   retire host `semget` forwarding; unmark `ltp-semget05`.
8. Network namespace registry + provider leases in the arena; supervisor
   socketpair fd brokering for published ports and PTYs.
9. `/proc`, `/proc/sys`, `/proc/net`, `/proc/sysvipc` read from the arena.
10. PTY/session/job-control ownership onto the process section.

The fork-floor experiments E1→E3 proceed in parallel with steps 1–5 (they are
per-backend engine work, coupled to this design only through the lease
classes) and are sequenced E1 first — it is the cheapest to probe and the
biggest single win if HVF permits it.

## Validation

Per-domain reducers and probes (kept from rev 1, with additions **bold**):

- process section: fork/exit/wait reducers; pgrp/session reducers; PID
  reuse/generation tests; pidfd identity probes; **a fork-storm race harness
  asserting no registration window (the ptrace06 shape) and loud exhaustion at
  section capacity**.
- leases/permits: fork storm with bounded live VM count; thread fanout above
  vCPU budget; hard-killed child lease reclaim; exec generation bump; the
  existing admission gate; **dtrace assertion of zero supervisor round trips
  during a 1000-fork storm (hot-path budget as a gate)**.
- futex/SysV objects: forked writer/reader handoff; blocking wake on
  send/receive capacity; `IPC_RMID` wakes waiters; **`futex_cmp_requeue01`
  full-load reproducer (the 1000-waiter/47-stranded shape) green without the
  known-gap marker; `semget05` green with honest tunables; kill-9 while
  holding a bucket lock recovers**.
- namespaces/procfs: namespace-filtered `/proc`; `/proc/net` and
  `/proc/sysvipc` reflect arena state; stale cleanup after hard death;
  same-bridge connect / cross-bridge deny; published-port cleanup on death.
- **fork floor: `perf_fork` p50 tracked in the perf lane with a ratchet
  (first gate < 1 ms); epoll-ltp / waitid / splice ratios below the 10x
  pathological threshold before any bless treats them as healthy.**
- **bless convergence: the campaign-level acceptance test for this design is
  two consecutive full `--force` conformance runs whose gating sets are
  identical — i.e., the measurement is load-stable — before a baseline bless
  is accepted.**

Before any default flip, a step must pass its reducers, the conformance probes
pinning the touched domains, `just lint-domains`, and the normal local gate
for the touched crates.

## Implementation decisions

- The authority is per-run shared state plus the existing supervisor — there
  is no `carrick-kernel` process. The crate name `carrick-kernel` names the
  arena layout + services library.
- The arena is file-backed `MAP_SHARED`, created before the first fork,
  version-stamped, fixed-capacity, loud on exhaustion.
- Hot paths (fork, dispatch, block, wake) perform no IPC; the supervisor
  handles cold control operations and death sweeps only.
- No userspace runnable queues or preemption engine; the host scheduler
  schedules, permits bound materialized VMM state, futex words park waiters.
- Leases and locks are (owner pid, owner generation, lease generation)-stamped;
  death notification via `EVFILT_PROC` is primary, polling is a backstop, and
  robust-lock repair is a supervisor duty.
- Registration is pre-fork by the parent; children never initialize their own
  ancestry.
- Process-shared futex wait *records* move to the arena in step 6 because
  requeue needs multi-bucket atomicity; plain wait/wake keep the current
  lock-free path. (Supersedes rev 1's "futexes stay local initially.")
- The first scheduler-visible behavior change is conservative and unchanged
  from rev 1: prevent over-admission and park fork/clone children before VMM
  materialization; aggressive residency eviction of already-blocked processes
  stays a follow-up.
- Do not read Linux kernel source; semantics from man pages, standards, ABI
  docs, and the Docker oracle.
