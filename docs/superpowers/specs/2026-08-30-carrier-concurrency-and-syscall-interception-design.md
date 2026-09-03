# Carrier Concurrency and Typed Syscall Interception Design

**Date:** 2026-08-30

**Status:** Approved.

**Extends:** [`2026-08-25-carrick-embed-program-design.md`](2026-08-25-carrick-embed-program-design.md), specifically Phase B (container as a kernel-graph object), Phase C (`carrick-embed`), and Phase D (observer pipeline). This document does not replace the rest of that program.

## Goal

Make two consequences of Carrick being the Linux kernel available as stable,
composable embedding interfaces:

1. a host application can run multiple isolated Linux containers concurrently
   inside one explicit Carrick carrier, one VM, and one kernel graph; and
2. trusted host code can intercept a Linux syscall, rewrite its six scalar
   arguments, or replace its terminal return value/errno without granting the
   interceptor arbitrary access to guest memory.

The public demonstration is two concurrently progressing containers with
different VFS contents and syscall behavior, while both remain isolated PID 1
roots in the same carrier.

Correctness remains the first gate. The work is not complete because two
futures can be polled at once, because two narrow unit tests pass, or because a
hosted CI job is green. Completion requires a signed one-VM guest proof,
cross-container isolation, strict cleanup, the full repository gates, and the
no-extension performance check described below.

## Non-goals

- Interceptors cannot change the syscall number.
- Interceptors cannot dereference or mutate pointed-to guest memory.
- This does not add arbitrary syscall-handler replacement or a plugin ABI.
- This does not expose interactive embedded TTY sessions.
- This does not create more than one hardware VM carrier in a host process.
- This does not weaken Carrick launch policy, guest seccomp, namespace
  isolation, entitlement checks, or conformance gates.
- This does not claim production readiness or make a guest a hardened trust
  boundary.

## Current State (verified 2026-08-30)

### Embedding lifecycle

`carrick_embed::ContainerBuilder::prepare` resolves an image and constructs a
`PreparedContainer`. `PreparedContainer::execute` then calls the unit-style
`carrick_runtime::Runtime::prepare`, which creates a fresh `Container`,
dispatcher, root backing, extensions, and `PreparedRun`.

The kernel `Container` already owns typed identity, launch context, its PID
namespace region, clock, launch capabilities, resource budget, lifecycle
generation, and retirement witness. The dispatcher/run object still owns the
rootfs, VFS mount table, observer chain, network, stdio, and execution state.
That division can remain per-container, but it needs an explicit carrier owner
above all runs.

`Runtime` is currently a unit struct. `Runtime::prepare` uses a process-static
`CARRIER_INIT` and reaches other process/global facilities. `PreparedRun` owns
only one run and invokes the HVPatch execution path directly. The public embed
surface has no object that admits, indexes, shuts down, or joins several live
runs.

The tree contains a mix of legitimate carrier-wide singletons and historical
"current run" state. A concurrency implementation must classify every mutable
static it reaches. VM custody, physical-frame allocation, vCPU capacity, host
signal installation, and diagnostics can be carrier-wide. Container identity,
PID namespace, rootfs/VFS, UTS/net state, clock, capabilities, observer and
interceptor chains, seccomp, budgets, stdio, results, and teardown cannot be.

### Syscall boundary

`SyscallObserver` is public and supports syscall entry/return plus process
create/exec/exit callbacks. Existing `SyscallAction` values are `Allow`,
`Deny`, `Kill`, and the narrow `Short` action for read/write/send/recv byte
counts. `PolicyObserver`, `SandboxObserver`, `AuditObserver`, fault injection,
and resource budgets are shipped through this chain.

The current dispatch order is launch policy, guest seccomp, user observers,
budgets, then the syscall handler. `Short` changes only the count argument of a
known I/O syscall. There is no general typed argument-rewrite or return-
replacement contract.

Accelerated identity and clock calls can avoid the ordinary dispatch path.
Observers express whether visibility is required, and built-in rule types
derive that requirement. A general interceptor must fail closed here: it may
not silently miss a syscall because an optimization remained enabled.

### Documentation drift

The root README demonstrates policy and VFS filtering, and the embed README
names the extension seams. The crate-level rustdoc still incorrectly claims
that observers, VFS injection, networking, and time control are future work.
The READMEs do not yet give a complete interface/support table or distinguish
observation, filtering, interception, and unsupported guest-memory mutation.

## Decisions

| Question | Decision |
| --- | --- |
| Shared runtime API | Explicit, cloneable `carrick_embed::Carrier` handle. |
| Hardware topology | One live hardware carrier/VM per host process; many container objects inside it. |
| Backward compatibility | `ContainerBuilder::from_image` remains and uses an implicit single-use carrier when no explicit carrier is active. |
| Transform API | A new `SyscallInterceptor` trait, separate from the existing observer/filter trait. |
| Allowed mutation | Replace all six scalar arguments, return a value, or return a Linux errno. |
| Forbidden mutation | No syscall-number change and no guest-memory dereference/write. |
| Multiple interceptors | Registration order; each sees the latest effective args; first terminal replacement wins. |
| Policy relationship | Launch policy and guest seccomp validate the effective call before a replacement is honored. |
| Fast paths | A custom interceptor requires full visibility by default; no silent blind spot. |
| Failure containment | Interceptor panic becomes a typed error for its container and does not unwind through the carrier. |
| Isolation | Extension state and events are per-container unless the host deliberately shares the same thread-safe object. |
| Shutdown | Explicit admission close, orderly cancellation, join, retirement, and leak checks. |

## Public API

### Carrier

`carrick-embed` adds an explicit carrier handle:

```rust
pub struct Carrier { /* Arc<CarrierInner> */ }

impl Carrier {
    pub fn new() -> Result<Self, EmbedError>;
    pub fn container(&self, image: impl Into<String>) -> ContainerBuilder;
    pub async fn shutdown(self) -> Result<(), EmbedError>;
}
```

`Carrier` is `Clone + Send + Sync`. Its inner state owns:

- admission state (`Open`, `Closing`, `Closed`);
- the carrier kernel/runtime handle and container registry;
- live-run cancellation and join records;
- shared scheduler and bounded vCPU admission;
- the exact hardware VM custody and carrier-scoped allocator handles required
  by the selected backend;
- diagnostics that are genuinely carrier-wide.

`Carrier::container` returns the existing builder bound to a carrier lease.
Image resolution remains asynchronous and container preparation remains
transactional. The carrier allocates the `ContainerId`, run identity, and
generation; a standalone `PreparedContainer` no longer invents those outside
carrier admission.

Only one independent carrier may own the process hardware VM. A second
`Carrier::new()` while one is active returns
`EmbedError::CarrierAlreadyActive`. Cloning the existing handle is the way to
share it. The final retired handle permits a later carrier construction only
after all containers and hardware/runtime leases have been released.

`ContainerBuilder::from_image` remains source-compatible. It constructs an
implicit single-use carrier at preparation/execution time if no explicit
carrier is active. If an explicit carrier is active, the unbound builder fails
with a configuration error directing the caller to
`carrier.container(image)`; it never attaches ambiently to a carrier the caller
did not name.

### Interceptor

`carrick-runtime` defines and `carrick-embed` re-exports:

```rust
pub trait SyscallInterceptor: Send + Sync {
    fn intercept(
        &self,
        process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction;
}

pub struct InterceptedSyscall<'a> { /* borrowed metadata + original/effective args */ }

pub enum InterceptAction {
    Continue,
    RewriteArgs(SyscallArgs),
    Return(i64),
    Errno(LinuxErrno),
}
```

`SyscallArgs` is a typed six-word value with indexed getters and immutable
builder-style replacement. It does not expose a mutable reference into the
dispatcher's request. `InterceptedSyscall` exposes:

- canonical number and static syscall metadata/name;
- immutable original arguments;
- the current effective arguments after earlier interceptors; and
- container/process/thread identity through `ProcessInfo`.

The syscall number is not replaceable. Pointer-shaped arguments remain opaque
`u64` values. An interceptor can redirect a pointer value, but cannot read or
write the address through this API. Full emulation that needs guest bytes is a
future separately reviewed capability.

`ContainerBuilder::interceptor(Arc<dyn SyscallInterceptor>)` registers one
interceptor. Repeated calls append in deterministic order. Registration is
sealed by `prepare`; live mutation of a container's chain is not supported.

`ProcessInfo` adds `container_id()` and read-only run identity access. These
values come from the calling task's container graph edge, never a process
global.

## Dispatch Semantics

For every trapped syscall:

1. Capture an immutable original request.
2. Run the container's trusted interceptor chain in registration order.
3. `Continue` leaves the effective request unchanged.
4. `RewriteArgs` replaces all six effective scalar arguments; the next
   interceptor sees the rewrite.
5. `Return` or `Errno` records a proposed terminal outcome and stops the
   interceptor chain.
6. Apply Carrick's launch policy and the guest's seccomp filters to the final
   effective request. A denial or kill wins over the proposed outcome.
7. Run the existing user observer/filter chain against the effective request.
   Existing `Short` remains a reducing-only I/O transformation.
8. If all policy layers allow the call, publish the proposed outcome or invoke
   the normal syscall handler with the effective arguments.
9. Publish exactly one terminal return event to observers and compatibility
   reporting, including continuation-based syscalls.

This ordering ensures a rewrite cannot smuggle forbidden effective arguments
past seccomp. A returned value cannot make a syscall denied by number appear to
succeed. Trusted host code can change behavior, but it cannot accidentally
weaken a container's declared policy boundary.

Observers receive the effective request. Audit/diagnostic records preserve
both original and effective arguments when they differ. No-rewrite calls keep
the existing event shape and allocation behavior.

### Fast-path visibility

Installing a general custom interceptor requires
`FastPathVisibility::Required`. Preparation disables or reroutes the relevant
EL1 shim/vDSO acceleration for that container, so calls such as identity and
clock reads cannot evade interception.

The default is correctness-first. A future typed interest-set optimization may
prove that an interceptor cannot target accelerated calls and retain those
fast paths, but it is outside this version. No interceptor is allowed to opt
into an undocumented blind spot.

### Panic and error containment

Interceptor callbacks run behind a panic boundary. A panic becomes
`EmbedError::InterceptorPanicked { container_id }`, initiates orderly
termination of that container, and leaves sibling containers and carrier
admission healthy. Poisoned host locks inside user interceptor code remain the
embedder's responsibility, but Carrick never unwinds the callback through the
VM executor.

An interceptor returns no fallible host error other than its explicit Linux
errno action. This keeps guest outcomes separate from embedding/runtime
failures. Invalid carrier lifecycle operations use typed `EmbedError` variants:
`CarrierAlreadyActive`, `CarrierClosing`, and `CarrierClosed`.

## Concurrent Container Model

One carrier contains many `Container` graph objects. Each container owns or
uniquely reaches:

- `ContainerId`, run id, generation, and retirement witness;
- PID namespace root/region and PID-1 task;
- rootfs, VFS mount table, file descriptions, cwd, and UTS hostname;
- network namespace/interposer;
- clock domain;
- capabilities, launch policy, and guest seccomp state;
- interceptor and observer chains;
- budgets, stdio, result buffers, and cancellation state.

The carrier alone owns:

- the hardware VM and backend custody;
- kernel graph registry and scheduler;
- bounded vCPU leases and executor admission;
- physical/global-frame allocation;
- carrier signal/watchdog infrastructure; and
- carrier diagnostics/event storage, with container identity on every event.

Two prepared containers execute on separate host workers and interleave through
the carrier scheduler. Concurrency is real guest progress, not sequential work
hidden behind two ready futures. The bounded vCPU pool remains authoritative;
blocking waits release leases according to the existing HVPatch contract.

Every mutable process static reached by preparation, execution, or teardown is
classified before the concurrency gate opens:

- move run/container state behind `Container` or the carrier registry;
- move shared mutable runtime state behind `CarrierInner`; or
- retain only a proven carrier-wide facility with a documented concurrency
  contract.

Host process title and singleton "root network view" conveniences cannot name
one current container once several are live. They become carrier summaries or
container-keyed views. Thread registry/futex routing must derive the correct
container from task/executor custody rather than ambient current-run state.

## Lifecycle

### Admission and preparation

`Carrier::container` is allowed only while admission is open. Preparation
reserves a container identity/generation and builds all per-container state
off-graph. Publication is one transaction. Failure rolls back only that
container and releases all namespace, mapping, mount, network, stdio, and
registry reservations.

### Execution and result

A carrier-bound builder's asynchronous `run` resolves the image, prepares the
container, and executes on a blocking worker. A prepared container is
single-use. Results are container-scoped and cannot consume another run's
stdout, exit, traps, compatibility events, or budget counters.

`run_blocking` remains supported. Concurrent blocking runs require separate
host threads using builders bound to the same explicit carrier.

### Shutdown

`Carrier::shutdown` atomically closes admission, requests orderly termination
of every live container, waits for their workers, retires all container graph
objects, proves scoped cleanup, and then releases carrier runtime/hardware
ownership. New preparation after closing fails deterministically.

Dropping a user-facing handle does not invalidate live containers: builders,
prepared containers, and workers hold carrier leases. Dropping the last handle
without calling `shutdown` initiates non-blocking close; deterministic callers
use `shutdown().await` and inspect its result.

Cancellation of one run never closes the carrier. An infrastructure failure
that invalidates VM custody marks the carrier failed, cancels all runs, and
returns a carrier-terminal error rather than allowing sibling work to continue
on uncertain hardware state.

## Public Demonstration

The root README keeps the seven-line single-container path. Its advanced
example uses one explicit carrier and two concurrent containers:

- both run the same unmodified Linux image;
- each mounts different in-memory configuration through `FilterVfs`;
- one interceptor replaces `getuid`, while the sibling receives the normal
  Linux result;
- one interceptor rewrites `write`'s fd argument to redirect selected output;
- `tokio::join!` collects independent results; and
- the explanation states that both workloads shared one Carrick VM/kernel but
  not one Linux identity or extension state.

The example must live as compiled Rust source and be included or mirrored in
the README so the public API cannot silently drift.

## Documentation

### Root README

Add a compact embedding-interface table:

| Interface | Supported behavior | Current boundary |
| --- | --- | --- |
| Stdio | captured, inherited, or caller-provided writer | interactive embedded TTY remains out of scope |
| Observers | syscall/lifecycle audit and allow/deny/kill/short-I/O filters | custom fast-path visibility must be explicit |
| Interceptors | scalar argument rewrite and terminal return/errno replacement | no syscall-number or guest-memory mutation |
| VFS | in-memory, layered, filtered, recording, and custom mounts | Linux semantic coverage remains experimental |
| Time | system, offset, frozen, scaled, deterministic | container-scoped only |
| Faults and budgets | errno/kill/short-I/O injection and resource limits | only shipped resource counters/actions |
| Network | in-memory interception and mocks | not a general packet-filter API |
| Shared buffers | host-backed shared mappings and futex-capable leases | no arbitrary private-page access |
| Carrier concurrency | sequential and concurrent isolated containers in one VM | one carrier/VM per host process |

### Embed README and rustdoc

The crate README expands each interface with its public types, ordering,
failure behavior, and limitations. It explicitly distinguishes observers from
interceptors. The stale crate-level rustdoc is replaced with the same current
support boundary. Examples and links use relative repository paths.

## Verification Strategy

### Red-first unit and property coverage

Before implementation, tests fail for:

- deterministic interceptor ordering and cumulative rewrites;
- first terminal action winning;
- effective args reaching policy, seccomp, observers, and handler;
- policy/seccomp denial overriding a proposed replacement;
- exactly one return event for replaced and continuation outcomes;
- interceptor panic containment;
- container/run identity on every callback;
- admission close and preparation rollback;
- container registry isolation and generation-safe retirement; and
- no cross-container VFS, event, stdio, result, budget, clock, or network
  ownership.

Property tests cover arbitrary six-word rewrites and action chains without
guest-memory access. Static/domain gates reject a syscall-number rewrite field,
ambient current-container lookup, or unclassified mutable run static.

### Signed guest proof

`just test-embed` gains a serialized signed test that starts two containers
concurrently in one carrier and proves:

- one VM creation/custody generation;
- overlapping guest progress;
- `getpid() == 1` in both containers;
- distinct `/proc`, hostname, VFS data, stdout/stderr, and exit status;
- per-container replaced `getuid` behavior;
- per-container `write` fd rewrite behavior;
- no event leakage between observer/interceptor chains;
- sibling survival after one interceptor panic or guest failure; and
- complete namespace/task/mount/frame/vCPU cleanup after shutdown.

An entitlement error is a failure, never a skip. The artifact receipt records
source HEAD, binary SHA-256, CDHash, LC_UUID, entitlement, and USDT section.

### Repository and conformance gates

Completion requires:

1. focused host unit/property tests;
2. compile-tested public examples;
3. `RUST_TEST_THREADS=1 just ci`;
4. signed `just test-embed`;
5. cached differential probe gate;
6. strict baseline-free conformance closure on the receipted artifact;
7. explicit scoped cleanup proof; and
8. the still-shipped CLI/default-lane smoke on the same source/link identity.

Carrick and the Docker oracle remain serialized. Hosted GitHub Actions compile
and test host-only logic; trusted hardware runners own signed guest evidence.

### Performance gate

With no carrier concurrency or interceptor installed, dispatch retains one
predictable absent-extension branch and performs no allocation, lock, virtual
call, or payload formatting. A same-artifact no-extension comparison must show
no supported regression before closure.

Interceptor-installed runs may pay the explicit cost of callback dispatch and
required fast-path visibility. Concurrent-container throughput is measured
separately and is not allowed to hide a single-container regression.

## Implementation Sequence

1. Add red public-contract and dispatch-order tests.
2. Add typed interceptor values/trait and the pre-policy transform pipeline.
3. Add panic containment, identity exposure, diagnostics, and builder wiring.
4. Introduce `CarrierInner`, explicit admission, container registry, and
   carrier-bound preparation while preserving the old single-use builder.
5. Audit and migrate every mutable current-run static reached by two live
   containers.
6. Enable concurrent execution and deterministic shutdown.
7. Add signed one-VM isolation/interception tests and cleanup receipts.
8. Add compiled examples and update both READMEs/rustdoc.
9. Run correctness, conformance, and no-extension performance gates.

The implementation plan must split these into reviewable red/green swings.
No bulk baseline re-blessing, skip-based guest success, or unreceipted
concurrency claim is permitted.

## Acceptance Criteria

The work is complete only when all of the following are true:

- the public `Carrier` API runs two containers with overlapping guest progress
  in one hardware VM;
- isolation and teardown match the contract above under success, failure,
  panic, cancellation, and shutdown;
- typed interceptors rewrite scalar args and replace return/errno outcomes in
  deterministic order;
- transformed calls cannot bypass launch policy or guest seccomp;
- accelerated calls cannot silently evade an installed interceptor;
- existing single-container builder callers remain source-compatible;
- READMEs, rustdoc, and compiled examples describe the exact shipped surface;
- all required host, signed guest, conformance, cleanup, and performance gates
  are green on source- and artifact-bound receipts; and
- Carrick remains explicitly experimental and not a hardened boundary.
