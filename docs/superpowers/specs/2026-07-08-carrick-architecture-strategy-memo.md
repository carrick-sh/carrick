# Carrick architecture strategy memo

Date: 2026-07-08

## Executive summary

Carrick should keep its central invariant: one Linux process is one host
process, and the VMM exists only to execute guest instructions. The current
pressure does not require retreating to a guest Linux kernel or a userspace
authority daemon. It does require making the implicit Linux-kernel delta
explicit: a per-run shared arena for cross-process Linux state, plus typed
leases for materialized VMM resources.

The design line is:

```text
host kernel primitives first
per-run arena for Linux-visible state the host cannot express
supervisor only for cold cleanup and fd brokering
per-process runtime keeps guest memory, trap loop, signal frames, and hot I/O
```

The immediate strategic priority is not another broad abstraction pass. The
highest-leverage path is to finish the arena consolidation already underway and
probe the HVF fork floor in parallel. Those two tracks answer different
questions:

- The arena track answers whether Carrick can stay coherent without adding a
  Linux-kernel-shaped daemon.
- The fork-floor track answers whether Carrick can remain lower-overhead than a
  VM for process-heavy workloads.

If either track fails its gates, the design should narrow, not sprawl: keep
hot-path execution local, move only the failing Linux-visible object class into
the arena, and treat expensive VMM residency as a lease that can be released and
reacquired.

## What remains load-bearing

The following constraints should be treated as architectural commitments unless
direct measurement proves they are impossible:

1. **One Linux process maps to one host process.** This preserves host-visible
   PIDs, host scheduling, real `fork`/`wait4`, normal kill/reap behavior, and
   a process boundary without a guest kernel.
2. **The host kernel is the authority where it has the primitive.** Process
   existence, zombies, wait readiness, scheduling, signals as carriers, host
   files, sockets, ptys, and death notification should stay native.
3. **The arena stores only the Linux delta.** PID namespace identity, Linux
   parentage, run state, ptrace stop markers, SysV objects, futex waiter
   records, provider leases, and namespace metadata belong in a run-scoped
   shared region when the host cannot express them.
4. **No hot-path IPC.** Fork, syscall dispatch, block, and wake may use atomics,
   robust locks, and platform futexes. They should not require a round trip to a
   broker process.
5. **VMM residency is a lease, not identity.** A host process can remain the
   Linux process while its VM/vCPU is parked, destroyed, rebuilt, or re-bound.
6. **M:N scheduling happens only at safe boundaries.** Trap, blocking wait,
   wake, fork quiesce, and exec rebuild are valid. Instruction-level preemption
   or a userspace runnable-queue scheduler is not the next move.
7. **Backend differences stay explicit where they are real.** HVF fork
   choreography, KVM fd/id lifetime, bhyve VM-node lifetime, NVMM host behavior,
   signal arrival, and trap vehicles are mechanism boundaries, not style drift.

## Current architecture state

The codebase already moved toward this shape:

- `carrick-kernel` exists as the arena crate. It has the versioned arena layout,
  process records, generation domains, robust bucket locks, and wait/wake
  abstractions.
- HVF vCPU admission moved toward arena-backed atomic permit slots rather than
  a process-local counter or file-lock-only gate.
- The shared `vcpu_sched` layer exists and is installed by the generic threaded
  loop using each backend's vCPU budget. HVF, KVM, and bhyve all expose finite
  budget/reclaim behavior through `ThreadedEngine`.
- There are already implementation plans for the arena foundation, the arena
  process section/pre-fork registration flip, and the HVF E1 parent-keeps-VM
  probe.

The remaining issue is coherence and ordering. The repo has the right pieces,
but some are still first-wave:

- not every cross-process object has moved into the arena;
- not every permit/lease has a shared class policy;
- supervisor death sweeping is not yet the single cleanup path for all arena
  leases and locks;
- the fork-floor experiments are planned but not the default execution path.

## Structural challenges

### Cross-process Linux state

The old shape had many independent fork-shared tables: run state, child CPU
metadata, PID namespace membership, futex waiters, signal rings, permit slots,
eventfd slabs, and subsystem-specific caches. That worked long enough to prove
the model, but it now produces repeated bug classes:

- post-fork parent/child registration races;
- capacity mismatches and silent fallbacks;
- stale pid ownership after reuse;
- waiter keys that are not stable across fork or remap;
- duplicated death-sweep and cleanup logic.

The arena is the correct consolidation point. It should not become a daemon or
a generic database. It should be a fixed-layout, typed, generation-checked
shared memory contract.

### Fork floor

The strategic performance problem is fork/exec process-spawn latency. Recent
notes put raw Carrick fork cost around 3.3-3.5 ms p50 where Docker's Linux path
is tens of microseconds. The current design attributes much of that to HVF
teardown and replay, especially parent VM destruction/rebuild.

This is the clearest existential performance gate. If Carrick cannot materially
reduce fork cost, fork-heavy workloads will remain load-coupled and conformance
blesses will keep requiring scheduling workarounds.

The right first experiment is E1: prove whether the parent can keep its VM while
the child clears inherited HVF state and creates its own VM. It is cheap and has
a high upside. If E1 fails, E2/E3 become the path: lazy stage-2 replay and map
coalescing.

### vCPU and VM residency

Carrick now has two resource planes that should stay separate:

- per-process runnable vCPU slots for guest threads;
- cross-process HVF VM/vCPU creation permits for fork storms.

This separation is important. Thread execution pressure and fork-storm
materialization pressure are different phenomena. A combined "scheduler" would
either overfit HVF or become a userspace kernel scheduler. The architecture
should keep the host scheduler responsible for CPU time while Carrick only
bounds materialized VMM state.

### Linux shared objects

SysV semaphores, message queues, process-shared futex requeue, and namespace
provider state are the places where host primitives do not line up with Linux
semantics. Forwarding them directly to Darwin or scattering per-key files and
per-process maps creates false capacity, missing atomicity, or incoherent fork
behavior.

The arena should absorb these one domain at a time:

- futex requeue as a two-bucket atomic move;
- SysV semaphores and message queues as arena objects with honest tunables;
- network namespace membership, published-port leases, and PTY/session state as
  arena sections plus supervisor fd brokering only for cold host resources.

## Strategic options

### Option A: arena plus leased residency

This is the recommended path.

It keeps the project thesis intact and makes the implicit Linux-kernel delta
explicit without introducing a guest kernel or hot-path daemon. It also matches
the codebase's current direction: `carrick-kernel`, `vcpu_sched`, arena-backed
permit sections, and the existing supervisor all compose naturally.

Tradeoffs:

- Requires careful fixed-layout evolution and typed domains.
- Does not make fork cost vanish by itself; fork-floor work remains a parallel
  VMM track.
- Some Linux objects will be Carrick-native implementations, not host-forwarded
  primitives.

### Option B: authority process over RPC

This should stay rejected for hot paths.

An authority process has a tempting taxonomy: process registry, resource
scheduler, namespace registry, kernel object registry, provider registry. But
putting it on fork, block, wake, or dispatch repeats the mistake Carrick was
created to avoid: reintroducing a second kernel-like scheduler/control plane in
userspace.

The limited valid use is cold brokering:

- published-port or PTY fd passing;
- teardown of provider resources;
- diagnostics attachment;
- cleanup after hard death.

That role already belongs to the existing run supervisor.

### Option C: full VM or guest-kernel fallback

This is the escape hatch, not the strategy.

A guest kernel solves many semantic problems by abandoning the host-process
invariant. It also gives up Carrick's differentiator: host-native processes with
less overhead than VM-plus-Linux-kernel. It should be considered only if the
fork-floor and arena-coherence gates fail in a way that cannot be narrowed to a
specific subsystem.

### Option D: aggressive userspace M:N scheduler

This is too broad for the next phase.

Carrick needs M:N admission and reclaim at known-safe points. It does not need a
guest-thread scheduler that shadows the host scheduler. Arbitrary migration or
preemptive userspace scheduling would multiply the hard parts: guest CPU state,
signals, futex ownership, fork quiesce, ptrace stops, `/proc` state, and backend
vCPU lifetime.

The right form is already emerging: bounded slot acquisition, reclaim on
blocking waits, preferred-slot reacquire, fork-aware timeouts, and backend-owned
rebind mechanics.

## Recommended backlog

### Track 1: fork-floor proof

Run the E1 parent-keeps-VM probe first. It is the fastest high-information
experiment.

Acceptance:

- probe records whether child-side `hv_vm_destroy` unblocks `hv_vm_create`;
- parent remains unperturbed after the child clears inherited state;
- threaded variant covers at least one additional live/quiesced vCPU shape;
- result is recorded before engine changes;
- if confirmed, flag-gated engine path removes parent VM rebuild;
- if refuted, E2 lazy replay becomes the next fork-floor target.

### Track 2: arena process consolidation

Finish the process-section migration before expanding into more kernel objects.

Order:

1. Keep arena late attach and process records as the shared substrate.
2. Move run-state, fork-shared child metadata, and PID namespace membership onto
   one process record.
3. Flip fork registration so the parent pre-fills the child's record before
   `libc::fork`.
4. Delete late self-registration and repair paths after gates pass.

Acceptance:

- no silent fallback on capacity;
- process records are generation-checked;
- ptrace stop, parent pid, run-state, and wait metadata live in one record;
- fork storm and ptrace06-shaped reducers show no post-fork registration window.

### Track 3: lease classes and death sweep

Move from "permit table" to explicit resource classes.

Classes:

- `InitialExec`;
- `ForkChildBootstrap`;
- `CloneThreadRun`;
- `ExecveRebuild`;
- `WakeFromBlockingSyscall`;
- future provider/resource leases.

Acceptance:

- each lease is pid/generation/lease-generation stamped;
- normal release and hard-death reclaim are idempotent;
- the supervisor becomes the single cold sweep path;
- no hot operation requires supervisor RPC.

### Track 4: shared waiters and IPC objects

After process identity is coherent, move the semantic shared objects:

1. Process-shared futex waiter records into arena buckets.
2. `FUTEX_CMP_REQUEUE` as an atomic two-bucket move.
3. SysV semaphores as arena sets with semadj and honest tunables.
4. SysV message queues as arena rings with futex-woken waiter buckets.

Acceptance:

- no credit approximation for requeue;
- `semget05` class is fixed by honest capacity, not host-global Darwin limits;
- kill-9 while holding a bucket lock is repaired by generation-checked sweep.

### Track 5: namespace/provider convergence

Move namespace metadata and provider leases after the process and IPC sections
are stable.

Scope:

- network namespace membership and bridge ids;
- published-port leases;
- PTY/session/ctty ownership;
- DNS aliases;
- `/proc`, `/proc/net`, `/proc/sys`, `/proc/sysvipc` views over arena state.

Cold fd resources remain supervisor-brokered. Hot socket operations should still
run on host sockets after namespace resolution.

### Track 6: backend and abstraction cleanup

Only after the correctness tracks are stable, continue backend cleanup:

- consume existing `ThreadedEngine` and `GuestArch` seams;
- avoid flattening real trap/fork divergences;
- use host capability traits where they remove repeated cfg logic;
- keep KVM hypercall ideas speculative until there is a real `VcpuExit` variant
  and validation path.

## Decision gates

This strategy should be judged by gates, not by narrative appeal.

### Fork-floor gate

- E1 confirmed or refuted with probe logs.
- First milestone: fork p50 below 1 ms if parent-keeps-VM or lazy replay lands.
- Pathological fork-heavy suite ratios move below the current 10-40x range.

### Arena-coherence gate

- No cross-process table silently falls back to process-local state.
- Exhaustion is loud and typed.
- Process identity, run-state, and wait metadata agree from one record.
- Hard-death reclaim is generation-checked.

### Hot-path budget gate

- No supervisor round trips on fork, dispatch, block, or wake.
- Ordinary syscalls do not touch the arena unless they semantically need
  cross-process Linux state.
- Blocking/wake paths add only the explicit run-state/lease/waiter atomics.

### Conformance-stability gate

- Two consecutive full force runs have identical gating sets before blessing a
  new baseline.
- Remaining report-only rows are honest unimplemented subsystems, not
  test-shaped denials.
- Perf/timing gaps are tracked separately from semantic correctness gaps.

## Risks

### Arena versioning risk

Fixed shared layouts are hard to evolve. Every layout change must bump the
version, fail closed on mismatch, and preserve late attach behavior. This is
manageable because the region is per-run, not persistent across versions.

### Over-centralization risk

The arena can become a dumping ground. The rule should remain strict: only the
Linux-visible delta or scarce-resource lease state goes in. Guest memory,
register state, trap loops, signal frame construction, and local fd tables stay
per-process.

### Scheduler overreach risk

It is easy to turn "lease materialized VMM state" into a scheduler. Avoid this.
The host scheduler owns CPU time. Carrick owns admission to scarce VMM objects
and safe-point reclaim.

### Fork proof risk

E1 may fail if child-side `hv_vm_destroy` perturbs the parent's live HVF object
or does not unblock child creation. That does not invalidate the arena strategy;
it redirects fork-floor work to lazy replay and map coalescing.

### Backend false-sharing risk

KVM, bhyve, NVMM, and HVF differ in how VM objects, vCPU ids, fault exits, and
memory backing behave. Shared abstractions should be grown from real common
contracts, not from naming similarity.

## Near-term recommendation

Run the fork-floor E1 probe before expanding the arena beyond the current
process-section work. In parallel, continue the process-section consolidation
because it is the correctness foundation for every later shared object.

The next two concrete work products should be:

1. an E1 verdict entry with probe logs and a flag-gated decision;
2. a closed process-section migration that removes the post-fork registration
   race class.

Those two results determine the next quarter of architecture work. If E1 is
positive, spend the next performance push eliminating parent rebuild and then
lazy-replaying child mappings. If E1 is negative, preserve the process model,
finish arena coherence, and make lazy replay the fork-floor track.

## Addendum 2026-07-08: residency ceiling narrows and re-scopes Track 3

E4 (`docs/2026-07-08-hvf-residency-e4-evidence.md`) measured the HVF residency
ceiling and **refuted this memo's prediction** that blocked guest processes hold
their VM/vCPU residency and that a workload past the soft budget stalls in the
unbounded permit wait. That is false for single-threaded blocked processes.

Measured reality:

- The ceiling is **per-VM (exactly 127 on this host/OS)**, not memory-coupled and
  not a system-wide vCPU budget: 127 VMs materialize whether `total_vcpus` is 127,
  254, or 508 and whether each VM maps 0, 16, or 64 MiB. The earlier "~126
  system-wide vCPU budget" reading (and the `trap.rs:761-775` comment) was
  measured with stray guests live and is refuted.
- **carrick already releases the whole VM for single-threaded blocked
  processes.** `park_vcpu_for_blocking_wait` → `save_shared_wait_state()` →
  HVF `shared_wait_park` destroys the vCPU *and* the VM while parked and rebuilds
  on wake (bounded at 14 stage-2 descriptors, ~200-670 µs replay, tens of µs
  create). `procladder` at `PROC_LADDER_N=160` — 160 simultaneously-alive blocked
  children, 33 over the hard ceiling — passes under carrick in under 2 s, rc=0,
  matching Docker, with no `HV_NO_RESOURCES` and no stall. The ceiling therefore
  binds on processes that *hold a VM*, not on all *alive* processes.

Priority change: Track 3's `WakeFromBlockingSyscall` lease class still moves ahead
of Track 4 (shared waiters and IPC objects) — E4 gives it the evidence — but its
**scope narrows to the multi-threaded blocked case only**. Multi-threaded blocked
processes take the other branch (`save_guest_state()` → HVF `reclaim_park`, a
vCPU-only destroy that keeps the VM alive), so more than 127 simultaneously-blocked
multi-threaded processes remain capacity-bound. The lease design parameters are
already measured: eviction unit is the whole VM (per-VM ceiling), reacquire budget
is tens of µs create + ~200-670 µs replay bounded at 14 descriptors, churn is flat
and non-degrading over 200 cycles. Acceptance = a `procladder-mt` variant (children
spawn a second thread, then block) failing red today and passing after the lease
extension, with `PROC_LADDER_N=160 procladder` staying green as the regression
guard and no `perf_fork`/`perf_fork_exec` regression.
