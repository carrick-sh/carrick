# HVPatch adaptive syscall portal design

## Outcome

Carrick will service a narrow class of nonblocking HVPatch syscalls without one
Hypervisor.framework exit per call. EL0 still enters Carrick's EL1 vector and
all Linux semantics remain in the Rust kernel graph. An executor-local host
helper consumes a typed request from the existing syscall mailbox while the
vCPU waits in EL1, publishes a typed response, and lets EL1 return directly to
EL0. Any ambiguity forces the existing HVC path.

The initial success criterion is mechanical: eligible calls reduce HVC exits
with identical return values, signal behavior, observer behavior, and kernel
work. The workload criterion is progress toward the `ltp-inotify09` maximum
2.0 Docker ratio without permanent helper CPU consumption. This design does
not claim that the first scalar allowlist alone will close that ratio.

## Evidence and choice

The `inotify09` reduction separates backend amplification from transition
cost. Private-rootfs virtual watches removed native vnode registration, yet
65,536-iteration watch churn improved only from about 5.47 us to 4.58 us.
Write/seek remains about 5.80 us and the serial four-operation body about
13.1 us. The exact LTP row still reaches its 40 s deadline at 3.89 times its
cached 10.344 s Docker oracle.

The signed micro-VMM portal experiment replaced 20,000 HVC exits with one
bounded exit. Its wall cost was 74.6-113.1 ns per operation versus
655.5-1168.6 ns for the stage-1 HVC path, with wall ratios 0.109-0.121 and
aggregate process CPU ratios 0.218-0.242. That establishes feasibility, not
production correctness.

Three approaches were considered:

1. Add more EL1 implementations. This remains correct for immutable or safely
   published values such as pid, tid, and time. It cannot own mutable file,
   inotify, signal, or scheduler state without creating a second kernel.
2. Recognize and fuse workload-specific syscall sequences. This can benchmark
   well but changes observable interleavings and scales poorly across Linux
   software.
3. Add a typed shared-memory portal to the existing dispatcher. This preserves
   one semantic implementation and amortizes the HVF boundary across ordinary
   stateful calls. This is the selected approach.

`sched_yield` is not an initial portal target. HVPatch already has an EL1 fast
path for it, and its return edge has scheduler and signal-delivery obligations.

## Architecture

Each persistent executor owns one `PortalSession` and one lazily active helper
thread. The session reuses the executor's existing 256-byte
`Aarch64SyscallMailbox`; no second wire ABI or raw byte-offset decoder is
introduced. Layout access goes through `Aarch64SyscallMailbox`, named offset
constants derived from that struct, and compile-time size, alignment, and
offset assertions.

The session identity contains:

- mailbox generation and monotonically increasing request sequence;
- persistent executor generation;
- Linux tid and process identity;
- MM identity plus live owner generation; and
- quantum epoch.

The helper retains the exact dispatcher and task context for that identity. It
never accesses HVF vCPU registers and never changes task or MM binding. The
vCPU owner remains the sole HVF API owner.

The first eligible syscall takes the ordinary HVC path. Before returning, the
owner publishes the session identity and wakes the helper. The mailbox response
advertises that the portal is armed. On a later eligible syscall, EL1 publishes
the normal typed request with release ordering and waits for a response with
acquire ordering. The helper validates the full identity, runs the same kernel
dispatcher, and publishes one of three results:

- `Returned(value)`;
- `Errno(errno)`; or
- `HostBoundary`, with the already-produced `DispatchOutcome` retained in
  host-owned session state for the vCPU owner to consume after HVC.

The third result is not redispatched. This prevents duplicate side effects if
an apparently eligible operation discovers a blocking or otherwise complex
outcome.

## Adaptive helper policy

A helper must not consume a host core while the guest is idle or compute-bound.
It parks by default. The first ordinary eligible HVC wakes it and pays the
normal transition cost. Once armed, it polls only for a bounded activity
window. Every valid request renews the window. Expiry publishes `PortalIdle`
and parks the helper; the next request observes that state and takes HVC.

The initial activity policy is a small operation bound plus a monotonic time
bound. Both are compile-time named policy values and observable counters. They
are tuned only from aggregate CPU and wall evidence; increasing them to hide a
failure is not accepted. One helper belongs to one active executor, so no
global service lock serializes independent guest CPUs.

## Eligibility and fallback

The initial allowlist contains only scalar, scheduler-neutral operations whose
documented dispatcher outcome is `Returned` or `Errno`:

- regular-file `lseek`; and
- `inotify_rm_watch`.

Eligibility is checked twice: EL1 uses a generated syscall-number bitmap to
choose portal versus HVC, and the helper independently validates the request
against the Rust allowlist and current runtime state. A disagreement forces
`HostBoundary`.

The portal is disabled or falls back for:

- blocking or continuation-producing outcomes;
- scheduler yield, fork, clone, exec, exit, futex waits, and signal return;
- MM mutation, task migration, quantum rollover, or generation mismatch;
- pending signal, job-control, preemption, or vCPU kick work;
- an active interceptor, debugger stop, or observer mode that cannot run in
  the helper unchanged;
- guest-memory pointer access in the first slice; and
- any unknown state, response action, syscall number, or protocol value.

Pointer-bearing operations such as `write` and `inotify_add_watch` are a later
slice. They require a pinned current-MM read lease that authenticates stage-1
translation and the exact owner generation while EL0 is stopped in the EL1
portal. They are not enabled by merely adding their syscall numbers.

## Signals, kicks, and scheduling

The existing signal pump and preemption machinery remain authoritative. A kick
sets a force-host-boundary flag in the owned mailbox and calls the existing
HVF exit mechanism. EL1 checks that flag before publishing, while waiting, and
again after acquiring a response before `eret`. A helper that observes it
publishes `HostBoundary`.

Session cancellation is a handshake. The owner increments the quantum epoch,
sets cancellation, forces the vCPU boundary, and waits until the helper reports
idle before migrating the task, rebinding the mailbox, changing MM authority,
or releasing the executor. Stale requests and stale responses are rejected;
they are never replayed against a new task incarnation.

The ordinary HVC completion and signal-return path remains the fallback and
the reference implementation. Portal completion does not skip pending-signal
checks: the force flag and kick close the publication race, and a bounded test
must exercise arrival before request, during dispatch, after response
publication, and immediately before EL1 return.

## Observability and contracts

The production path adds work metrics with real producers:

- `HvfSyscallExits`;
- `PortalRequests`;
- `PortalCompletions`;
- `PortalFallbacks`;
- `PortalStaleRejects`; and
- `PortalActiveCpuNs` or an equivalent process-CPU receipt outside an
  instrumented structural run.

The structural portal contract scales at 1, 8, 32, and 128 eligible calls. It
requires exact Linux results, zero stale acceptance, no dropped observations,
and an HVC-exit slope lower than one per operation after the single arming
boundary. A red control disables portal eligibility while retaining the same
fixture and must violate that exit slope.

The signed contract uses the real EL1 vector, mailbox, helper, dispatcher, and
generation transitions. VM-free tests cover the eligibility table, result
classification, cancellation state machine, stale generations, and complex
outcome handoff. Timing is measured separately in an uninstrumented signed
build against the same Docker workload.

Promotion proceeds through the focused portal contract, the inotify scaling
probe, exact `ltp-inotify09`, public probes, smoke, and full conformance. A
semantic pass cannot excuse excess helper CPU, excess fallbacks, stale
acceptance, or a runtime ratio above 2.0.

## Delivery slices

1. Define the typed portal states, session identity, eligibility table, work
   metrics, and VM-free state-machine contracts. No production selection yet.
2. Add the adaptive executor-local helper and scalar `lseek`/
   `inotify_rm_watch` path behind a separately selectable experimental policy.
3. Prove red-first signed exit reduction, signal/kick correctness, cleanup, and
   helper CPU bounds; then measure the decomposition and exact LTP row.
4. If scalar coverage leaves the ratio above 2.0, add the authenticated
   current-MM read lease and admit `write` and `inotify_add_watch` one at a
   time, each with its own red-first contract evidence.
5. Enable the policy by default only after the same signed artifact passes the
   applicable promotion ladder. Retain explicit disablement for differential
   diagnosis.

## Non-goals

The portal does not implement Linux semantics in EL1, bypass the kernel graph,
create a second syscall ABI, batch distinct Linux syscalls into one semantic
operation, weaken signal return edges, or make unsupported non-HVF backends
pretend to have equivalent transport. The contract and dispatcher remain
platform-neutral; each VMM backend may later provide a transport with the same
typed eligibility and fallback rules.
