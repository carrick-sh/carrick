# Authority-Enforced Kernel Closure

**Date:** 2026-08-19

**Status:** Approved design; awaiting written-spec review

**Design-time source:** `39cad6114e659191aae6874623d7bdf7cd96a1dd`

**Canonical completion lane:** macOS, Apple Silicon, HVF/HVPatch, Linux arm64

## Goal

Make Carrick's kernel the exclusive authority for Linux-defined state while
increasing exact Linux conformance and making fork, threads, waits, and signals
no slower than native-arm64 Linux.

The primary security boundary is **host containment**: guest-controlled state
must not acquire or invoke ambient Darwin process, identity, credential, path,
signal, or namespace authority. Intra-guest isolation is a co-equal Linux
conformance obligation. Carrick may be rearchitected wherever the existing
lowering cannot satisfy containment, semantics, or cost together.

Completion requires all of the following on one final clean source revision and
its exact signed binary:

1. Every Linux/aarch64 syscall has an explicit, mechanically enforced authority
   declaration, with no default classification and no unauthorized host
   transition.
2. Every applicable assertion in the frozen 2,127-suite closure surface and
   every applicable arm64 musl/GNU probe matches native-arm64 Linux, while the
   authority coverage surface grows as this campaign adds adversarial and
   multi-task cases.
3. Fork/exit/wait, clone/join, signal delivery, and signal interruption have
   median and p95 cost no greater than native-arm64 Docker through the declared
   1,000-task fan-out points.
4. The existing Go, CPython, Node, and LTP aggregates plus cold `go-build`
   remain within 2.0x native-arm64 Docker.
5. Two exhaustive clean closure passes and the final controlled performance
   pass succeed on the same exact artifact, with zero unauthorized host
   transitions, gaps, retries, skips, crashes, timeouts, or missing evidence.

This design improves containment. It does not describe Carrick as a hardened
boundary for untrusted code or as production-ready; that claim would require a
separate adversarial security review.

## Relationship to the current conformance campaign

This design extends, rather than replaces, the approved
`2026-08-16-exact-conformance-native-cost-closure-design.md` campaign:

- conformance remains first;
- the existing closure denominator remains a regression floor;
- no baseline, `known_gaps`, retry, timeout, crash, empty output, or matching
  setup failure can complete the campaign;
- every semantic change remains red-first against the exact pre-fix signed
  binary and differential against native-arm64 Docker; and
- a valid completing row at or above 10x Docker remains a correctness blocker.

The added requirement is that correctness must come from the right authority.
A result that matches Linux only by leaking host identity or delegating guest
semantics to Darwin is not conformant for this design.

## Design-time evidence

The current tree already points in the intended direction:

- HVPatch keeps guest processes, tasks, address spaces, waits, signals, and
  resource limits in Carrick's kernel graph.
- Recent changes moved shared futexes, eventfd, file locks, pipes, SysV
  semaphores, POSIX message queues, network-interface views, AF_UNIX sockets,
  and virtual time away from obsolete host-semantic implementations.
- `carrick_abi::syscall::Authority` and `authority_for_aarch64` now classify
  syscalls as `Guest`, `Host`, or `Hybrid`.
- `docs/host-facility-boundary.md` states the correct governing rule: use the
  host for real I/O and hardware, and answer guest-defined questions from the
  kernel graph.

The boundary is not yet enforceable:

- authority is metadata, not part of handler type-checking or dependency
  structure;
- `authority_for_aarch64` has a catch-all `Guest` arm instead of forcing each
  declared syscall to make an explicit choice;
- the documentation says `just lint-domains` enforces Guest-authority host-call
  restrictions, but `.semgrep/typed-domains.yml` contains no such rule; and
- at design time `just lint-domains` exits before analysis because Semgrep's
  runtime cannot initialize its CA trust store (`ca-certs: empty trust
  anchors`). A failing tool is fail-closed for CI, but it provides no evidence
  that the intended authority rule exists or works.

The measured lifecycle cost also identifies architecture rather than host
thread creation as the problem:

- raw `libc.fork` was 2.758 ms under Carrick versus 0.093 ms under Docker;
- with 256 live children, Carrick reached 25.29 ms per fork versus Docker's
  0.13 ms, with a super-linear Carrick curve and a flat Docker curve;
- fork quiesce measured at roughly 0.1 microseconds and host thread creation at
  roughly 14 microseconds, so neither is the leading term;
- the parent waits for child readiness and therefore for child vCPU admission,
  causing `ChildReady` to grow with live population;
- `ProcessSpec` also grows with population, indicating a scan on a path that
  must be constant-time; and
- the Python at-fork bookkeeping around the raw fork costs more than the fork
  handler because ordinary guest syscalls still pay avoidable trap and dispatch
  overhead.

The current design can already beat Linux when state is served from the right
place: the EL1 `getpid` path measured about 137 ns against Docker's 238 ns. The
campaign therefore treats the current lifecycle ratios as removable
architecture defects, not an unavoidable virtualization tax.

There is no authoritative closure result for design-time HEAD after the latest
kernel-object migration wave. Phase 0 must create one before current failures or
improvements are quoted as campaign state.

## Threat model and security properties

### Primary boundary: host containment

Guest-controlled input is hostile for purposes of authority routing. A guest
may attempt to:

- address arbitrary host PIDs, process groups, sessions, threads, or signals;
- smuggle guest UIDs/GIDs/capabilities into host credential decisions;
- escape its filesystem root through symlinks, races, path aliases, or stale
  file-description identity;
- use stale task, MM, VMA, frame, fd, or carrier generations;
- confuse two Carrick runs or two guest processes through process-global state;
- force a `Guest` syscall down a legacy host fallback; or
- exploit a partial lifecycle transaction to publish mixed generations.

Carrick must reject those shapes before they reach a host process primitive or
host resource outside the capability already authorized for that operation.

### Co-equal boundary: intra-guest Linux isolation

Carrick must enforce Linux-visible credentials, capabilities, ownership,
process relationships, namespaces, signal permission checks, ptrace checks,
resource limits, and fd/object sharing between guest tasks. Replacing a host
check with unconditional in-memory success would improve containment while
breaking isolation, and therefore does not satisfy this design.

### Explicit non-claims

This campaign does not claim:

- adversarial hardening of HVF, Carrick's ELF loader, JIT/translation
  primitives, or every host adapter;
- compatibility with Linux syscalls outside the declared closure and probe
  surfaces;
- completion of Linux/KVM, FreeBSD/bhyve, or NetBSD/NVMM conformance; or
- that host syscalls disappear. Host syscalls remain appropriate when the host
  owns the bytes, wire, pages, clock source, or CPU execution mechanism.

## Authority architecture

### Kernel authority

`KernelContext` is the exclusive authority for:

- task, process, thread-group, process-group, session, and parent/child
  identity;
- credentials, groups, capabilities, permissions, and resource limits;
- fork, clone, vfork, exec, exit, wait, pidfd, and ptrace relationships;
- signal dispositions, masks, pending queues, permission checks, target
  selection, and delivery state;
- futexes and other guest-only synchronization;
- SysV/POSIX IPC metadata and synthetic kernel objects;
- UTS, PID, time, and network namespace views; and
- virtual time offsets, timer ownership, and Linux-visible CPU accounting.

Kernel state is scoped to one run and keyed by typed IDs plus generations. Raw
host process identity is not part of any guest-visible key.

### Host capabilities

Host facilities are accessible only through narrow, typed capabilities:

- `FileBacking`: bytes and metadata rooted in an already-authorized filesystem
  capability. It accepts resolved VFS objects, not guest path strings.
- `NetworkWire`: packet and stream I/O for validated INET socket objects. Guest
  interface, route, DNS-policy, and AF_UNIX views remain kernel-owned.
- `PageBacking`: physical allocation, mapping, protection, and retirement for
  a generation-authenticated MM/VMA/frame transaction.
- `ClockSource`: monotonic/realtime hardware observations. Namespace offsets,
  timers, and expiry semantics remain kernel-owned.
- `CarrierExecution`: HVF vCPU execution, host CPU yielding, and exact
  authenticated kick/wake handles. It never accepts a guest PID/TID.

There is no generic `HostCapability`. A `Hybrid` operation receives only the
specific backing capability named in its declaration. Possessing file backing
does not grant host process, network, or ambient path authority.

Authority classifies **who owns the semantic answer**, not whether the host CPU
ever executes an instruction. A Guest-authority operation may use explicitly
declared substrate mechanics through a narrower mediator: bounded guest-memory
copy/materialization, authenticated carrier park/kick, and hardware clock reads
whose Linux-visible interpretation remains in the kernel. Those mechanics do
not grant host process, identity, credential, path, namespace, or signal
authority. They are named in the syscall/operation declaration and audited like
every other transition.

### Explicit syscall declarations

The syscall table becomes the single source of truth for:

- syscall number and name;
- support state;
- owning handler;
- authority (`Guest`, `Host`, or a named `Hybrid` composition);
- required capability set; and
- conformance and performance proof IDs.

Every table row is explicit. Unknown syscalls remain unknown, and adding a
declared syscall without an authority or proof mapping is a compile or build
failure. Range defaults and catch-all authority arms are not completion-safe.

Dispatch must make the declaration real in handler signatures:

- a `Guest` handler receives kernel state and bounded guest-memory access;
- a `Host` handler receives only its named host capability plus bounded
  guest-memory access;
- a `Hybrid` handler receives kernel state plus its declared backing
  capability; and
- no handler receives ambient access to host process, filesystem, networking,
  or signal APIs.

Metadata, generated dispatch, and handler types derive from the same
declaration so they cannot drift independently.

### Enforcement layers

Security cannot depend on Semgrep recognizing dynamic dispatch. Enforcement is
layered:

1. **Crate and module dependencies:** kernel-domain modules do not link raw
   host process, ambient filesystem, or ambient networking APIs.
2. **Typed handler contexts:** a handler cannot call a capability it was not
   given.
3. **Explicit declarations:** every syscall declares its authority and proof
   surface without a default.
4. **Forbidden-call inventory:** a checked mechanical inventory rejects new
   ambient `libc`, `std::process`, `std::fs`, and `std::net` uses in
   kernel-domain paths and drives the reviewed legacy inventory to zero.
5. **Fake adapters:** Guest-authority tests run with host adapters that panic on
   semantic or undeclared host access; explicitly declared guest-memory and
   carrier substrate calls remain observable. Hybrid tests panic on any
   capability except the declared backing or substrate capability.
6. **Runtime boundary probes:** every host-capability transition records the
   syscall, task generation, capability kind, operation, and outcome. Closure
   mode rejects an unauthorized or unclassified transition.
7. **Semgrep backstop:** typed-domain rules continue to catch known source
   shapes, but are not the sole authority boundary.

## Lifecycle architecture

### Task and carrier separation

A Carrick task owns Linux identity, registers, signal state, scheduling state,
and lifecycle relationships. A host pthread and HVF vCPU are execution
carriers. Carrier identity is never guest identity and is never persisted as
the answer to a Linux question.

The current one-host-pthread-per-live-guest-thread arrangement remains initially
because measurement shows host thread creation is not the dominant cost. A
parked carrier releases its scarce vCPU lease. A true resumable M:N worker pool
is a later evidence-gated option, not an assumed prerequisite.

### Fork

Fork is a kernel transaction:

1. Reserve the child Task/Process IDs and generations.
2. Create O(1) inherited references to credentials, files, signal actions,
   namespaces, and other share/copy-on-write objects according to clone flags.
3. Create the child MM through stage-1 COW and generation-authenticated frame
   inventory publication.
4. Publish the complete child task and parent-visible return state atomically.
5. Return to the parent after publication. Do **not** wait for the child to win
   a vCPU lease or execute its first instruction.
6. Admit and run the child independently when a carrier/vCPU is available.

The parent-visible path has no population scan, host fork, host child
registration, host wait, or child-readiness handshake. Failed pre-publication
transactions roll back completely. A failure after Linux's no-return boundary
uses the existing signal-shaped terminal path.

### Clone and thread lifecycle

Clone publishes a logical thread before carrier admission. The parent does not
wait for host-thread or vCPU admission beyond the Linux-visible publication
contract. Admission is cancellable by exec and exit and is generation-scoped.

Thread exit clears child-tid/futex state, publishes the kernel lifecycle event,
retires the logical task, and returns its vCPU lease. Process exit and exec
cancel and retire sibling tasks through kernel generations rather than polling
host `JoinHandle`s or sleeping for completion.

Host pthread creation remains an implementation detail and may be asynchronous
relative to task publication. No guest semantic state is keyed by
`std::thread::ThreadId`.

### Wait, exit, and pidfd

Child state changes publish into kernel wait queues keyed by parent/child
relationships and process generations. `wait4`, `waitid`, pidfds, subreapers,
orphan adoption, stopped/continued state, and exit rusage read that authority.

The HVPatch path does not call host `wait4`, `waitid`, or `kill(pid, 0)` to
infer guest liveness. Blocking waits park on kernel events and release their
vCPU lease when appropriate.

### Signals

Signal delivery has four steps:

1. Resolve the guest target from the kernel graph and check Linux credentials
   and namespace visibility.
2. Enqueue the exact signal and provenance in the target task or thread-group
   authority.
3. Atomically reconcile the pending signal with the target's current wait
   enrollment so neither the signal nor a concurrent ordinary wake can be
   lost.
4. Wake only the exact target's park token and, if it is currently executing,
   request exit from that exact vCPU carrier.

Process-group and broadcast signals enumerate the actual authorized target set
and apply the exact-target operation to each member. They do not wake unrelated
tasks. Guest signal semantics do not use host `kill`, `pthread_kill`,
process-global signal pumps, self-pipes, or all-waiter futex broadcasts.

Host signals used to control the Carrick container enter through an explicit
container-control ingress and are translated into kernel events. They are not
the transport for guest-to-guest signals.

### Blocking host I/O

Host kqueue/epoll remains appropriate for real host fd readiness. The event
multiplexer associates readiness with a generation-authenticated kernel wait
record and wakes the exact logical task. Readiness is a carrier mechanism, not
the source of guest object identity or signal semantics.

The initial design may park a host carrier while the guest task waits, provided
the vCPU lease is released. If controlled attribution later proves parked host
threads are the dominant residual lifecycle cost, the M:N decision gate below
may authorize resumable handlers and a bounded worker pool.

### Fast state

The EL1 shim may answer immutable or generation-coherent state without a VM
exit:

- per-MM slots: process identity shared by the whole address space, such as
  PID and generation-safe PPID;
- per-thread slots: TID and raw-syscall thread credentials; and
- time slots: only values whose update and clock-source contracts can be made
  coherent without weakening Linux semantics.

Per-thread state must not be placed on a per-MM page. Credential and parent
updates publish from the same kernel transaction that changes the authority.
A fast path with unverifiable invalidation is rejected even if it is faster.

## Failure behavior

- Unknown or unsupported guest behavior returns the Linux error established by
  the Docker oracle. It never invokes a broad host fallback.
- Invalid guest IDs, credentials, generations, paths, or object handles fail
  before entering a host capability.
- Capability denial is an ordinary typed error and is translated once into the
  Linux errno domain.
- A failed pre-publication lifecycle or memory transaction leaves no reachable
  partial state.
- Post-no-return exec failure terminates with the existing Linux signal-shaped
  path; genuine guest `exit(127)` remains distinguishable.
- An internal authority invariant violation terminates the affected Carrick
  run fail-closed. It must not broaden authority, target an unverified host
  process, or silently continue with mixed generations.
- A helper or backing authority death invalidates its exact epoch and fails
  outstanding operations; it is never silently recreated with inherited
  ambient access.

## Proof and coverage model

### Generated authority ledger

Closure mode generates and checks a ledger with one row per declared syscall
and semantic operation:

```text
syscall/operation
  -> authority
  -> handler
  -> allowed host capabilities
  -> semantic conformance probes
  -> adversarial containment probes
  -> ecosystem/LTP consumers
  -> performance benchmarks
```

The gate fails for a missing or duplicate mapping, an authority/handler drift,
an unclassified transition, or a Guest operation that touches semantic host
authority or an undeclared substrate capability.

### Coverage expansion

The existing 2,127 suites and applicable arm64 musl/GNU probes remain the
minimum regression surface. Each migrated mechanism adds durable probes for:

- at least two live guest processes where process identity or sharing matters;
- at least two live guest threads where per-thread state matters;
- credential allow/deny behavior;
- PID, task, fd, MM, VMA, and frame generation reuse;
- cross-run isolation;
- concurrent ordinary wake plus signal interruption;
- exec and exit cancellation at every admitted phase;
- invalid, boundary, and hostile arguments; and
- the absence of unauthorized host-capability transitions.

Probe output is deterministic and all waits are bounded. Applicable rows run
under arm64 musl and GNU where the existing probe gate requires both.

### Differential semantics

Every real gap follows the established loop:

1. Verify the intended Linux assertion under native-arm64 Docker.
2. Use bpftrace inside the Docker oracle for syscall shape when required.
3. Reduce the gap to a deterministic probe.
4. Prove the probe red against the exact pre-fix signed binary.
5. Attribute one mechanism with Carrick trace/DTrace or lldb/core evidence.
6. Implement the authority-correct fix.
7. Re-run the probe, originating suite, affected ecosystem cluster, and local
   gates.

Retries may establish that a case is probabilistic; a retry-recovered result
cannot complete a phase.

### Performance proof

Lifecycle benchmarks use paired, serialized Carrick and native-arm64 Docker
arms on the same host. Carrick and Docker never overlap. Each receipt records
source HEAD, binary hash, CDHash, LC_UUID, entitlement, DOF section, workload,
fan-out, sample count, host state, and raw data.

Required lifecycle families:

- raw fork; fork+exit; fork+wait; and CPython at-fork-inclusive fork;
- clone+join and thread exit;
- wait-any, wait-by-pid, pidfd readiness, and subreaper adoption;
- self, thread-directed, process-directed, group, and broadcast signals;
- signal interruption of futex, epoll/poll, sleeps, and child waits; and
- exec/exit cancellation with queued clone/fork admission.

Measurements cover quiet N=1 operation and fan-out points through 1,000 tasks.
Completion requires Carrick median and p95 no greater than Docker for each
required lifecycle family, with no Carrick-only super-linear population curve.
The comparison uses paired distributions and bootstrap confidence intervals;
the one-sided 95% upper confidence bound for each Carrick/Docker median and p95
ratio must be no greater than 1.0. The broad ecosystem requirement remains no
more than 2.0x Docker.

## Migration sequence

### Phase 0: re-establish a trustworthy current checkpoint

1. Repair `just lint-domains` so it performs deterministic offline analysis.
2. Add a red test proving the currently documented authority restriction is
   absent, then add real enforcement.
3. Replace implicit authority classification with an explicit inventory.
4. Inventory all reachable host transitions from Guest and Hybrid paths,
   separating legitimate backing from semantic delegation.
5. Run `just ci`, build and sign once, freeze the existing closure scope, and
   run the full suite and probe gates on design-time HEAD or its reviewed
   integration successor.
6. Record the exact current conformance, unauthorized-transition, and lifecycle
   performance baselines in a durable report.

**Exit gate:** the gate itself is trustworthy; every current transition is
classified; no new violation can land; the campaign has a fresh signed
baseline. Phase 0 does not claim security, conformance, or performance closure.

### Phase 1: make authority structural

1. Introduce typed handler contexts and named host capabilities.
2. Move raw host access behind host adapter boundaries.
3. Generate dispatch and the authority ledger from one explicit declaration.
4. Add fake-adapter and adversarial two-process tests.
5. Migrate existing Guest operations until their forbidden host-transition
   inventory is zero.

Temporary reviewed inventory entries may prevent regression during migration,
but they are not waivers and cannot survive phase completion.

**Exit gate:** all Guest handlers are structurally unable to call ambient or
semantic host capabilities and can reach only declared substrate mediators;
Hybrid handlers can call only declared backing and substrate capabilities; zero
unauthorized runtime transitions under focused and closure surfaces.

### Phase 2: fork, wait, exit, and pidfd

1. Delete HVPatch host-process fallbacks and isolate or remove retired backend
   code so it is not linked into the canonical product path.
2. Make fork publication independent of child vCPU admission.
3. Replace population scans with O(1) generation-stamped inheritance.
4. Move child state changes and reaping entirely to kernel wait queues.
5. Close fork/wait/pidfd/subreaper semantics and hostile generation-reuse
   probes.

**Exit gate:** no host fork/wait/liveness syscall is reachable from HVPatch
guest lifecycle; exact relevant conformance is green; fork cost no longer grows
with the live-child population. The final <=1.0x cost remains required even if
it needs Phase 4 work.

### Phase 3: threads and signals

1. Separate logical task publication from carrier and vCPU admission.
2. Replace guest-semantic host signal delivery and global wakes with exact task
   queueing and targeted wake tokens.
3. Make wait enrollment plus signal interruption atomic against ordinary wake.
4. Replace host-handle polling during exec/exit with generation-scoped kernel
   cancellation and completion.
5. Close the full signal, clone, futex-interruption, and concurrent exec/exit
   probe families.

**Exit gate:** guest-to-guest signals never target a host PID/TID; unrelated
tasks receive no wake; no missed wake or timeout remains; relevant exact
conformance is green through 1,000-task stress.

### Phase 4: lifecycle fast state and residual cost

1. Publish generation-safe per-thread TID and credential slots.
2. Close remaining identity/time fast-path trap floors without weakening
   invalidation semantics.
3. Attribute every remaining fork/thread/signal cost bucket with durable
   tracing.
4. Remove the measured bucket, not a presumed abstraction.

**M:N GO/KILL gate:** after asynchronous publication, O(1) inheritance,
targeted wakes, and safe fast state land, run the controlled lifecycle suite.
Proceed with resumable syscall handlers and a bounded reusable carrier pool
only if parked host carriers or carrier creation are the dominant measured
remainder preventing <=1.0x. Otherwise kill that rewrite and attack the actual
residual bucket.

**Exit gate:** every required lifecycle family has median and p95 no greater
than Docker at all declared fan-outs.

### Phase 5: remaining kernel objects and authority coverage

1. Audit every Guest and Hybrid declaration not closed by Phases 1-4.
2. Move Guest semantics and Hybrid metadata/synchronization into per-run kernel
   authority.
3. Retain only named host backing for real bytes, wire, pages, clock source,
   and CPU execution.
4. Add missing LTP, ecosystem, multi-task, hostile-input, and authority probes.

**Exit gate:** the generated authority ledger is complete; every Guest row has
zero semantic-host transitions and only declared substrate transitions; every
Hybrid transition is declared and exercised; fresh full closure shows no
regressions.

### Phase 6: exact conformance closure

Run the full fail-closed discovery on a fresh signed artifact, re-rank the
remainder by mechanism, and close every applicable semantic, crash, timeout,
empty, unexercised, oracle, and probe gap. Continue using red-first reducers and
serialized Docker ground truth.

**Exit gate:** all 2,127 frozen suites and the expanded applicable probe
inventory are exact, with no retry-recovered acceptance or unauthorized host
transition.

### Phase 7: final performance and containment audit

1. Run two exhaustive clean correctness passes on one exact artifact.
2. Run controlled lifecycle and ecosystem performance measurements on that
   unchanged artifact.
3. Perform hostile-input, path, credential, signal, cross-run, and stale-
   generation review over every host capability.
4. Record residual non-production security limitations explicitly.

**Exit gate:** every completion condition in this design passes together. A
focused green test, green CI, one closure pass, historical measurement, or
absence of a known exploit is insufficient.

## Expected code boundaries

The implementation plan may change exact names, but it must preserve these
responsibilities:

- `carrick-abi`: explicit syscall/authority/capability declarations and
  generated proof metadata;
- `carrick-runtime::kernel`: sole Linux semantic authority;
- `carrick-runtime::dispatch`: typed translation from syscall frames to kernel
  operations and named host capabilities;
- `carrick-host-*` and VMM backends: host mechanisms behind narrow traits;
- `carrick-thread`: per-run task parking/wake primitives with exact targeted
  tokens;
- conformance probes and `carrick-conformance`: semantic, containment, and
  authority-transition proof; and
- `scripts/dtrace` plus `docs/perf-results`: durable attribution and phase
  receipts.

Large existing dispatch modules should be split along authority boundaries as
they are migrated. The design does not require unrelated refactoring.

## Final completion audit

Before marking the campaign complete, inspect current evidence for every item:

- explicit authority declaration for every syscall and operation;
- zero reachable ambient host fallback in Guest paths;
- only declared backing transitions in Hybrid paths;
- no guest identifier can target a host process primitive;
- run/generation checks on every kernel object and host capability;
- expanded multi-process, multi-thread, hostile-input, and reuse probes;
- exact suite and probe inventory equality;
- two exhaustive closure passes on the final signed artifact;
- lifecycle median and p95 <= Docker through 1,000 tasks;
- ecosystem aggregates and cold `go-build` <=2.0x Docker;
- zero valid completing >=10x rows, timeouts, crashes, skips, missing evidence,
  unauthorized transitions, or retry-recovered acceptance; and
- a reviewed statement of remaining non-production security limitations.

If any evidence is indirect, stale, from another binary, or narrower than the
requirement, the goal remains active.
