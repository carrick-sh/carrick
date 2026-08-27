# Carrick Embed Reviewed Implementation Program

> **Superseded by [`../specs/2026-08-25-carrick-embed-program-design.md`](../specs/2026-08-25-carrick-embed-program-design.md) (owner decision 2026-08-25).**
> Kept as the static-review record. It no longer governs implementation; do not
> execute its work packages.

> **For agentic workers:** This is a program-level controller, not permission to
> implement every work package in one change. Before implementing a work
> package, use `superpowers:brainstorming` to validate its design and
> `superpowers:writing-plans` to create a task-level plan. Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` to
> execute that approved plan. Track progress with checkbox (`- [ ]`) syntax.

**Date:** 2026-08-23

**Status:** Superseded 2026-08-25 by the `carrick-embed` program design (see
banner); retained as the static-review record

**Goal:** Add a supported Rust library surface for resolving and running one
containerized Linux workload through Carrick, then add authority-safe extension
points as independently gated vertical slices.

**Architecture:** `carrick-embed` should remain a thin product facade over the
existing `carrick-engine -> RunSpec -> carrick-runtime` path. Runtime extension
points must be capability-bearing, generation-safe, and private by default;
they must not expose a mutable `SyscallDispatcher`, ambient host APIs, or raw
guest addresses. The current external Docker differential harness remains the
correctness oracle. Embed telemetry may improve diagnosis, but it cannot become
its own oracle.

**Tech Stack:** Rust 2024, Carrick's HVPatch kernel, `carrick-engine`,
`carrick-spec`, `carrick-runtime`, `carrick-observability`, the unified VFS,
signed macOS/HVF binaries, native-arm64 Docker oracle, DTrace/USDT, LLDB, and
the existing conformance harnesses.

**Source proposal:** [Original carrick-embed implementation plan](2026-08-23-carrick-embed-source-implementation-plan.md)

**Governing designs:**

- [`../specs/2026-08-23-versioned-linux-capability-embedding-design.md`](../specs/2026-08-23-versioned-linux-capability-embedding-design.md)
- `docs/superpowers/specs/2026-08-19-authority-enforced-kernel-closure-design.md`
- `docs/superpowers/specs/2026-08-20-hvpatch-persistent-executor-scheduler-design.md`
- `docs/superpowers/specs/2026-08-22-hvpatch-fork-lifecycle-closure-design.md`
- `docs/superpowers/specs/2026-08-16-exact-conformance-native-cost-closure-design.md`
- `docs/host-facility-boundary.md`

## How to use this document

The source proposal combines at least nine independently reviewable products:
the launch API, runtime preparation, VFS injection, telemetry, host policy and
fault injection, resource quotas, virtual time, shared memory, network
interposition, and conformance tooling. Treating them as seven implementation
phases would let a failure in one force unrelated APIs to stabilize around it.

This document therefore does three things:

1. records the static review of the source proposal against the 2026-08-23
   tree;
2. fixes the architectural and proof-boundary problems found in that review;
3. decomposes the idea into work packages that each produce independently
   useful and testable software.

Before changing code, select one work package, write its design spec, obtain
approval, and produce a task-level implementation plan. Do not begin a later
work package merely because this program lists it.

No project code, build, test, guest, Docker container, benchmark, or conformance
lane was run while producing this review. Current-tree claims below come from
static source and documentation inspection only.

---

## Review verdict

The product direction is worth pursuing: Carrick should have a library-facing
launch surface, and its kernel position can support unusually powerful testing
and control APIs. The source proposal is not implementation-ready as written.
It assumes away active lifecycle constraints, duplicates existing seams, and
turns Carrick's own observations into a proposed correctness oracle.

### Approaches considered

1. **Implement the source proposal as one seven-phase program.** This maximizes
   apparent momentum but couples unrelated APIs, makes fork retirement an
   underspecified prerequisite, and risks blessing Carrick with its own traces.
   Reject.
2. **Ship a minimal library facade, then add independently approved vertical
   slices.** This produces useful software after Work package 1, preserves the
   existing engine/runtime/oracle seams, and lets authority, correctness, and
   overhead reject one advanced feature without freezing the others.
   **Recommended.**
3. **Build only an internal conformance/testing harness first.** This avoids a
   public API commitment, but it does not meet the product goal and encourages
   test-only seams that later diverge from the CLI path. Keep this only as the
   signed feasibility harness in Work package 0.

### Keep

- A new `carrick-embed` facade over `carrick-engine` and `carrick-runtime`.
- A Docker-shaped single-container happy path with captured and inherited
  stdio.
- Reuse of the existing engine merge logic; no second OCI/image/CLI merge
  implementation.
- A sealed runtime preparation seam so extensions are installed before guest
  execution.
- Mount injection through the existing unified VFS.
- Opt-in syscall/lifecycle telemetry.
- Deterministic testing tools, fault injection, quotas, shared buffers, and
  network interposition as later vertical slices.
- Side-by-side conformance diagnostics that retain the independent Linux
  oracle.

### Revise

| Source proposal | Reviewed direction |
| --- | --- |
| Construct `CliRunRequest` inside `carrick-embed`. | Rename or wrap it as a library-neutral engine request. CLI vocabulary must not become the stable library API. |
| `run().await` and `run_blocking()` ship together. | Ship synchronous execution first. Image resolution may remain async. Add async execution only after the in-process path proves it never forks with a live async runtime. |
| Expose `PreparedDispatcher` mutation. | Expose a sealed `PreparedRun`; install typed `RuntimeExtensions` during preparation. The dispatcher remains a runtime implementation detail. |
| One observer can audit, deny, inject faults, mock the network, and enforce budgets. | Split read-only telemetry, host policy, test fault injection, network transport, and kernel quotas. They have different ordering, safety, and overhead contracts. |
| Wire time control only through `dispatch/time.rs`. | Add a kernel-owned clock domain shared by every clock read, timer, timeout, futex, poll/epoll wait, signal timer, file timestamp, and vDSO/fast path that exposes time. |
| Expose arbitrary `GuestMemoryAccess` by raw address. | Start with minted shared-buffer capabilities. Any later snapshot/debug API uses typed `GuestVa`, task/MM/execution generations, permissions, and stopped-state rules. |
| Mock HTTP at `connect(2)`. | Interpose a socket transport and readiness/data path first. HTTP is a helper above a byte-stream mock; TLS requires an explicit, separate design. |
| Enforce resources from observer counters. | Put quota authority in the kernel graph and enforce at allocation/admission/I/O boundaries. Telemetry may report counters but does not own enforcement. |
| Replace the external conformance harness with in-process tests. | Keep `carrick-conformance` as a pure external orchestrator. Embed-based telemetry is diagnostic evidence only. |

### Reject or defer

- Reject “no codesigning dance for the test harness.” Any process that creates
  an HVF VM on macOS must run from an entitled binary. A `cargo test` executable
  is not automatically suitable for in-process HVF execution.
- Reject a Carrick syscall trace as a Linux correctness oracle. It reports what
  Carrick did, not what Linux requires.
- Reject raw syscall-trace equality as a general verdict. Scheduling, PIDs,
  TIDs, fds, addresses, retries, helper calls, and pointer contents are not
  naturally aligned across two kernels.
- Reject a per-syscall “percentage of argument combinations” as a conformance
  claim. The denominator is undefined and the observed combinations are not an
  exhaustive argument space.
- Reject golden Carrick traces as correctness baselines. They may be diagnostic
  fingerprints, never authority to bless existing behavior.
- Defer `ContainerHandle`, detached exec, `ContainerGroup`, bridge networking
  between embedded containers, and multi-container orchestration until the
  single-container lifetime is correct and process-global state is eliminated.
- Defer `Scaled { factor: f64 }`; floating-point clock scaling is not a stable
  time contract.
- Defer generic HTTP/TLS mocking and arbitrary live guest-memory writes.
- Do not add public stub types for deferred features. Add an API when it has a
  working implementation and proof surface.

---

## Current-tree findings that change the plan

### The engine seam exists, but is CLI-shaped

`crates/carrick-engine/src/lib.rs` already has the right semantic split:
`Engine::resolve` performs image/platform resolution and returns a fully merged
`RunSpec`. The request is still named `CliRunRequest`, contains lifecycle and
CLI forwarding fields, has no public default/builder, and documents that some
fields are carried but not consumed by the engine. Reusing the merge is right;
making this CLI-shaped struct the embed API is not.

### Execution is not async-safe today

`crates/carrick-runtime/src/execute.rs` is a 1,000-plus-line assembly path.
`Runtime::execute` explicitly asserts that no Tokio runtime is live because
production paths still fork. Static references include PID-namespace
supervision, the interactive supervisor, runtime/file-authority helpers, and
CLI lifecycle paths. The prerequisite is therefore not merely “replace
NsSupervisor and PtyRelay.” It is a fail-closed census proving that the exact
in-process library execution path performs no unsafe host fork after an async
runtime or foreign application threads exist.

Guest `fork` under HVPatch must become a kernel task transaction and must not
create a host process. A deliberately separate helper process may still be a
valid architecture, but it must be started through an embedding-safe lifecycle
and must not be confused with guest process identity.

### The VFS injection seam already exists

`crates/carrick-runtime/src/vfs/mod.rs` publicly defines `Vfs`; `VfsMounts`
already implements longest-prefix routing and override behavior; and
`SyscallDispatcher` already installs mounts. A second generic layering engine
would duplicate rootfs/overlay/override semantics. In particular, “fall
through on `ENOENT`” is insufficient for whiteouts, mutations, rename/link
across layers, metadata ownership, read-only errors, and directory merges.

### Syscall observation already has an observability path

`carrick-observability::CompatReporter` already receives syscall entry and
return events, aggregates them without unbounded storage, and invokes an
opt-in USDT hook. A new observer added independently to every dispatch path
would duplicate this path and risk disagreement.

The current events are not yet a complete embed event API. They lack exact
kernel task/execution generations, bounded payload policy, lifecycle events,
and an embed-owned backpressure contract. Some identity syscalls can also use
an EL1 fast path that bypasses ordinary dispatcher observation. An API claiming
to “see every syscall” must either cover those fast paths or report an explicit
blind spot; silently disabling the fast path would be a performance and
behavior change that requires its own evidence.

### Guest memory is not a raw shared byte array

`carrick-guest-mem` already makes `GuestVa`, `Gpa`, and `HostVa` different
types and documents permission-checked access. HVPatch also has non-identity
stage-1 mappings, reusable global-frame IPAs, owner generations, COW, and
transactional stage-1/stage-2 publication. “Guest memory is host memory” is an
unsafe simplification. Any host-facing memory capability must authenticate the
live stage-1 translation and exact current owner generation throughout its
lifetime.

### Time and resource authority already live partly in the kernel

The runtime already models realtime offsets, timers, per-task CPU accounting,
and Linux rlimits. A new observer-owned clock or budget would create competing
answers. The missing work is to consolidate these facilities behind explicit
kernel-owned clock/quota objects and complete the enforcement surface, not to
add counters beside them.

### The conformance harness is intentionally external

`carrick-conformance` is a pure orchestrator that links none of the guest
stack. It shells out to an exact Carrick binary and Docker, runs the two heavy
engines in separate phases, parses ecosystem assertions, maintains an oracle
cache keyed by suite declaration, and emits durable results. That separation
is valuable: a bug in `carrick-embed` or the runtime cannot silently redefine
the oracle.

### Workspace membership is already globbed

The root `Cargo.toml` uses `members = ["crates/*"]`. Creating a crate under
`crates/` does not require a manual workspace-member edit. The crate map and
feature-closure documentation still require updates.

---

## Target product boundary

The host application and the `carrick-embed` caller are part of the trusted
host boundary. The Linux workload is not. Being trusted does not justify
ambient, untyped authority inside the runtime: mistakes in a host application
must not turn a guest path, PID, address, or stale handle into authority over an
unrelated host resource or Carrick task.

The library must preserve both governing properties:

1. **Host containment is primary.** Guest-controlled data can reach only the
   exact host backing capability the embedder supplied.
2. **Intra-guest Linux isolation is co-equal.** A contained result is still
   wrong if it bypasses Linux credentials, namespaces, task relationships,
   signals, rlimits, or object ownership.

The minimal architecture is:

```text
host application
  -> carrick_embed::ContainerBuilder
  -> carrick_engine::RunRequest
  -> Engine::resolve -> RunSpec
  -> Runtime::prepare(RunSpec, RuntimeExtensions)
  -> PreparedRun::execute
  -> HVPatch kernel + authenticated host capabilities

optional extensions installed before execute:
  injected mounts | runtime event sink | host policy | fault plan
  clock domain | quota set | shared-buffer leases | socket transport
```

Work-package dependencies are deliberately sparse:

```text
0 prerequisite proof -> 1 minimal facade -> 2 sealed preparation
                                            |-> 3 VFS
                                            |-> 4 events -> 5 policy/faults
                                            |            -> 10 diagnostics
                                            |-> 6 quotas
                                            |-> 7 time
                                            |-> 8 shared buffers
                                            `-> 9 network transport
```

`RuntimeExtensions` and `PreparedRun` have private fields. A caller cannot
replace kernel identity, reach the dispatcher directly, install arbitrary host
callbacks inside locks, or mutate extensions after guest execution starts.

---

## Global constraints

- HVPatch remains the single product execution model. Do not revive legacy
  host-process-per-guest-process backends to make embedding easier.
- Preserve the authority design: guest identity/lifecycle/signals/waits are
  kernel-owned; host access occurs through named capabilities.
- `run-elf` remains a bring-up/debug surface and is not part of the embed API.
- The first supported product is one foreground container per builder.
- The first execution API is synchronous. Async image resolution is allowed;
  async guest execution waits for the no-host-fork gate.
- The default extension set is empty and behavior-identical to
  `carrick run` for the same resolved `RunSpec`.
- With extensions disabled, add no heap allocation, lock acquisition, trait
  call, payload decoding, or event formatting to the syscall hot path. Any
  unavoidable branch must be measured.
- An enabled event sink never runs arbitrary user code while a kernel
  subsystem lock, stage-1 transaction, or vCPU ownership transition is held.
- Event delivery is bounded and nonblocking. Drops are counted and visible;
  a zero-event or dropped-event trace cannot support a completeness claim.
- Public path injection accepts a capability-rooted VFS object and a normalized
  absolute guest mount point, never an ambient host path string inside the
  runtime.
- Public memory APIs use address-domain types and generation-bearing handles.
  No bare `u64` crosses the embed boundary as a guest/physical/host address.
- System-time mode must remain Linux-conformant. Deterministic/offset time is an
  explicit test mode and cannot silently alter ordinary runs.
- Host policy, guest seccomp, test fault injection, and telemetry remain
  separate stages with explicit ordering.
- Resource quotas are kernel authority, not observer callbacks.
- The native-arm64 Docker result remains the semantic oracle. Carrick and
  Docker phases never overlap.
- Use immutable image identities for authoritative tests. A mutable `latest`
  tag cannot support a closure receipt merely because an oracle cache key hits.
- Every semantic change is red-first against the exact pre-fix artifact and
  differential against Linux where Linux behavior is the contract.
- Every signed runtime receipt records source HEAD, binary SHA-256, CDHash,
  LC_UUID, hypervisor entitlement, and `__dof_carrick` presence.
- Preserve unrelated dirt, use an isolated ignored worktree for implementation,
  and commit each independently reviewable deliverable narrowly.
- Do not describe Carrick or `carrick-embed` as production-ready or as a
  hardened boundary for untrusted code.

---

## Work package 0 — Prerequisite and feasibility gates

**Purpose:** Prove that a library can safely execute Carrick inside an existing
host process before stabilizing a public API around assumptions that are false
today.

**Consumes:** The governing lifecycle, scheduler, authority, and exact-
conformance designs listed in the header.

**Produces:** An approved embed-foundation design, an embedding-safe lifecycle
census, a signed integration-harness route, and a no-extension performance
baseline.

- [ ] **0.1 Reconcile with the active HVPatch lifecycle campaign.** Audit the
  then-current tree against
  `2026-08-22-hvpatch-fork-lifecycle-closure-design.md`. Record which host-fork,
  process-global signal, helper-process, and teardown paths remain reachable
  from `Runtime::execute`.
- [ ] **0.2 Define the exact embedding-safe execution boundary.** The gate is
  not “no `libc::fork` text in the repository.” It is: after the caller may
  have foreign threads or an async runtime, the in-process run path performs no
  raw host fork and does not call process-wide exit, signal-handler, cwd,
  rlimit, environment, or fd-table operations that escape the prepared run's
  ownership.
- [ ] **0.3 Add a fail-closed static reachability/census gate.** The checked
  artifact names every allowed helper lifecycle and rejects a new raw host
  fork or ambient process mutation on the embed-reachable path. Test-only fork
  fixtures and CLI-only detached lifecycle code are classified separately.
- [ ] **0.4 Design the signed library integration harness.** The harness must
  link the same runtime path as the library consumer, use Apple `ld64`, carry
  `com.apple.security.hypervisor`, retain `__DATA,__dof_carrick`, and expose a
  command that fails rather than skips when entitlement or probe registration
  is missing.
- [ ] **0.5 Freeze a no-extension baseline.** Capture CLI-equivalent behavior,
  syscall/trap counts, wall time, CPU, allocations, and DTrace attribution for
  representative hello, fork/exec, threaded, filesystem, and network cases.
  This baseline measures the exact signed binary that later embed work uses.
- [ ] **0.6 Approve the embed-foundation design.** Resolve synchronous/async
  lifecycle, runtime ownership, error boundaries, feature closure, and signed
  test execution before creating `carrick-embed`.

**Gate 0:** Do not create the public crate until the signed embedding harness
runs one single-container workload without violating the embedding-safe
lifecycle boundary, and the ordinary CLI path remains behavior-identical on
the same runtime seam. A static audit alone does not close this gate.

---

## Work package 1 — Library-neutral request and minimal embed facade

**Purpose:** Deliver the smallest independently useful product: resolve an
image and synchronously run one container with captured or inherited stdio.

**Candidate files:**

- Modify `crates/carrick-engine/src/lib.rs`
- Create `crates/carrick-embed/Cargo.toml`
- Create `crates/carrick-embed/src/lib.rs`
- Create `crates/carrick-embed/src/builder.rs`
- Create `crates/carrick-embed/src/result.rs`
- Create `crates/carrick-embed/tests/signed_smoke.rs` or the signed harness
  shape approved in Work package 0
- Modify `crates/README.md`

**Proposed public interface:**

```rust
pub struct ContainerBuilder { /* private */ }

impl ContainerBuilder {
    pub fn from_image(image: impl Into<String>) -> Self;
    pub fn platform(self, platform: Platform) -> Self;
    pub fn command<I, S>(self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>;
    pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self;
    pub fn workdir(self, path: impl Into<String>) -> Self;
    pub fn user(self, user: impl Into<String>) -> Self;
    pub fn stdio(self, stdio: StdioMode) -> Self;
    pub async fn resolve(self, engine: &Engine) -> Result<ResolvedContainer, EmbedError>;
}

pub enum StdioMode {
    Captured,
    Inherit,
}

impl ResolvedContainer {
    pub fn run_blocking(self) -> Result<ContainerResult, EmbedError>;
}
```

The engine owns a library-neutral `RunRequest`; the CLI maps flags into it, and
the embed builder maps its smaller surface into it. Keep lifecycle-only CLI
fields in the CLI. Do not add a second merge implementation.

- [ ] **1.1 Write red engine parity tests.** For the same explicit request,
  CLI and embed adapters must resolve identical `RunSpec` values for argv,
  environment precedence, workdir, user, platform, pull policy, mounts,
  seccomp/capabilities, network, fs backend, and trap limit.
- [ ] **1.2 Introduce the library-neutral request without changing merge
  behavior.** Prefer a rename plus adapters over two large request structs that
  can drift.
- [ ] **1.3 Add the minimal builder.** Use consuming builder methods. Omit tty,
  interactive stdin, detached execution, VFS injection, observers, virtual
  time, budgets, shared memory, and network mocks from this work package.
- [ ] **1.4 Wrap `RunResult` narrowly.** `ContainerResult` exposes exit code,
  terminating signal, stdout/stderr bytes, trap-limit status, and compat
  summary. Assertion convenience methods belong in a testing extension, not
  the core result type.
- [ ] **1.5 Prove pure request tests without HVF.** These tests may use the
  ordinary host unit-test path.
- [ ] **1.6 Prove one signed end-to-end run.** The test fails if it did not
  execute an HVF guest. It compares the library result with the CLI result for
  the same image/command and exact signed binary.
- [ ] **1.7 Record the public error contract.** Image resolution, invalid
  configuration, preparation, entitlement, guest exit, trap-limit, and runtime
  infrastructure failure remain distinguishable.

**Gate 1:** A host application can resolve and synchronously run one container,
capture or inherit stdio, and receive structured termination without depending
on CLI internals. CLI parity, signed execution, `just ci`, and the no-extension
performance comparison are green.

---

## Work package 2 — Sealed runtime preparation

**Purpose:** Create one preparation path shared by CLI and embed without
exposing a half-initialized dispatcher or duplicating host/memory fs assembly.

**Candidate files:**

- Create `crates/carrick-runtime/src/prepare.rs`
- Modify `crates/carrick-runtime/src/execute.rs`
- Modify `crates/carrick-runtime/src/lib.rs`
- Add focused tests under `crates/carrick-runtime/src/` and the signed embed
  harness

**Proposed interface:**

```rust
#[derive(Default)]
pub struct RuntimeExtensions { /* private capability-bearing fields */ }
pub struct PreparedRun { /* private, single-use */ }

impl Runtime {
    pub fn prepare(
        spec: &RunSpec,
        extensions: RuntimeExtensions,
    ) -> Result<PreparedRun, RuntimeError>;
}

impl PreparedRun {
    pub fn execute(self) -> Result<RunResult, RuntimeError>;
}
```

`Runtime::execute(&RunSpec)` remains the compatibility wrapper:
`prepare(spec, RuntimeExtensions::default())?.execute()`.

- [ ] **2.1 Characterize both fs-backend branches before extraction.** Pin
  rootfs/layer handling, cached lower behavior, mounts, network construction,
  PID namespace placement, privileges, Rosetta mounts, stdio, and cleanup.
- [ ] **2.2 Write red phase-order tests.** Reject duplicate execution, mutation
  after prepare, mount installation after boot, and extensions whose capability
  belongs to another run generation.
- [ ] **2.3 Extract sealed state transitions.** Preparation either returns one
  complete `PreparedRun` or rolls back every host mapping, helper, mount, and
  registry publication it created.
- [ ] **2.4 Keep dispatcher construction private.** Extensions are translated
  into narrow runtime-owned objects; callers never receive
  `&mut SyscallDispatcher`.
- [ ] **2.5 Re-run CLI and embed through the same wrapper.** There is no
  embed-only runtime assembly path.

**Gate 2:** Default extensions are byte/exit/behavior equivalent to the prior
`Runtime::execute`, preparation is rollback-complete, and a static diff plus
runtime evidence shows there is only one product assembly path.

---

## Work package 3 — VFS mount injection

**Purpose:** Let the host provide an exact VFS mount without inventing a second
overlay model.

**Candidate files:**

- Create `crates/carrick-embed/src/vfs.rs`
- Create `crates/carrick-embed/src/vfs/in_memory.rs`
- Modify `crates/carrick-runtime/src/prepare.rs`
- Test through runtime VFS unit tests and signed guest probes

- [ ] **3.1 Specify mount ownership and lifetime.** A mount has one normalized
  absolute guest target, one run generation, and one owned `Box<dyn Vfs>` or
  reviewed equivalent. It is installed before execution and dropped after all
  guest references close.
- [ ] **3.2 Audit the public `Vfs` trait surface.** Re-export it only if every
  argument/result type is suitable as a supported embed contract. Otherwise
  add a smaller embed trait and one runtime adapter.
- [ ] **3.3 Implement one `InMemoryVfs`.** Start with deterministic regular
  files and directories, explicit metadata, bounded file size, and defined
  write-capture behavior.
- [ ] **3.4 Pin Linux mount semantics.** Red-first probes cover longest-prefix
  routing, `ENOENT` versus `EACCES`/`EROFS`, shadowing, mutation overrides,
  directory enumeration, symlinks, hard links, rename/link across mounts,
  open-handle lifetime, fork, and exec.
- [ ] **3.5 Defer generic `LayeredVfs`.** Add it only after whiteout, directory
  merge, copy-up, metadata, and cross-layer mutation semantics have an approved
  design. Do not implement fallthrough-on-`ENOENT` as a substitute.
- [ ] **3.6 Add recording as a wrapper after semantics are stable.** Logs are
  bounded, redact content by default, count drops, and do not change errno or
  lookup ordering.

**Gate 3:** An injected in-memory mount is visible only at its declared target,
obeys Linux-visible mount and fd-lifetime semantics in differential probes, and
adds no cost to runs with no injected mounts beyond the already-existing mount
table behavior.

---

## Work package 4 — Read-only runtime event stream

**Purpose:** Provide structured syscall and lifecycle telemetry without
granting behavior-changing authority or adding unbounded hot-path work.

**Candidate files:**

- Extend `crates/carrick-observability/src/compat.rs` or add a focused
  `runtime_events.rs` in that crate
- Modify the canonical dispatch/lifecycle/fast-path publication seams
- Create `crates/carrick-embed/src/events.rs`

**Event contract:**

- entry and return are correlated by run, task serial, thread serial,
  execution generation, and monotonically increasing event sequence;
- syscall identity includes guest ABI, native number, canonical handler, raw
  scalar arguments, and outcome;
- pointer payloads are not decoded by default;
- fork/clone publication, exec commit, exit, signal delivery, and wait/reap are
  lifecycle events, not inferred from neighboring syscalls;
- fast-path syscalls are either explicitly published or counted in a named
  blind-spot field;
- delivery is nonblocking, bounded, and reports drops.

- [ ] **4.1 Write red event-order and identity tests.** Include two live guest
  processes, two threads, fork/exec, a denied syscall, a signal death, and an
  identity fast-path call.
- [ ] **4.2 Add one canonical publication path.** Reuse the existing compat/
  probe seam where possible. Do not maintain separate embed and DTrace event
  definitions that can drift.
- [ ] **4.3 Add a disabled fast path.** With no sink, do not allocate, lock,
  format, decode pointers, or invoke a trait object.
- [ ] **4.4 Add bounded sinks.** Provide a fixed-capacity collector and a
  channel/ring adapter. A full sink increments a drop counter and never blocks a
  vCPU or kernel transaction.
- [ ] **4.5 Separate secrets from metadata.** Paths, argv, environment,
  buffers, socket data, and credentials require explicit capture policy and
  bounded copies. Defaults expose metadata only.
- [ ] **4.6 Measure observer-off and observer-on cost.** Use DTrace to attribute
  added branch, copying, allocation, and lock cost. An observer-off regression
  is a blocker, not polish.

**Gate 4:** The event stream has exact multi-task identity, no silent drops,
and stated fast-path coverage. Observer-off behavior and cost remain unchanged.
The stream is diagnostic evidence; it is not a semantic oracle.

---

## Work package 5 — Host policy and deterministic fault injection

**Purpose:** Add behavior-changing test controls without conflating them with
telemetry or guest-installed seccomp.

This work package must be split into two task-level plans: host policy first,
fault injection second.

**Dispatch ordering:**

```text
authority/argument normalization
  -> immutable host containment policy
  -> launch-time container policy
  -> guest-installed seccomp
  -> explicit test fault point
  -> syscall handler transaction
  -> read-only event publication
```

If two deny stages could return different Linux-visible outcomes, the design
must pin the ordering with differential and security tests.

- [ ] **5.1 Define a typed `HostPolicy`.** Match canonical syscall identity and
  bounded scalar metadata. Path/socket predicates use permission-checked,
  bounded decoding outside kernel locks. The guest cannot remove or weaken the
  policy.
- [ ] **5.2 Reuse existing deny machinery where semantics match.** Do not add a
  third generic syscall filter beside container policy and seccomp merely for
  API convenience.
- [ ] **5.3 Define named fault points.** A pre-handler `errno` may be safe for a
  side-effect-free call; partial writes, post-publication fork failure, delayed
  wake, signal death, and transaction-stage failures require handler-specific
  points with rollback/no-return contracts.
- [ ] **5.4 Make fault plans deterministic.** Probability uses an explicit seed
  recorded in results. Count conditions are scoped by run/task/syscall as the
  API states; races do not silently change which occurrence fires.
- [ ] **5.5 Model delay and kill through the scheduler/signal kernel.** Do not
  sleep a host callback or call host process termination from the observer
  path.
- [ ] **5.6 Prove disabled overhead and enabled semantics.** Every fault point
  is red against a non-injected control and records the exact point, task,
  generation, seed/count, and outcome.

**Gate 5:** Host policy is immutable and fail-closed; fault injection is
deterministic and transaction-safe; neither uses observer callbacks as
authority; and the disabled path remains zero-allocation/zero-lock.

---

## Work package 6 — Kernel-owned resource quotas

**Purpose:** Add embeddable run limits that agree with Linux rlimits and actual
kernel accounting.

Do not advertise “cgroup-free resource budgets” until each counter has a
complete definition and enforcement surface. The first approved quota set
should use resources Carrick can already account exactly.

- [ ] **6.1 Define quota semantics per resource.** For CPU, memory, processes,
  syscall count, output bytes, file growth, fd count, and network bytes, state
  the scope, unit, inclusion rules, reset/inheritance rules, soft/hard behavior,
  Linux signal/errno/termination result, and relationship to existing rlimits.
- [ ] **6.2 Place counters in kernel-owned run/task objects.** Observer counters
  may mirror snapshots but cannot enforce limits.
- [ ] **6.3 Enforce at the operation boundary.** Process limits gate task
  reservation; memory limits gate mapping/backing commitment; byte limits gate
  the relevant write; syscall limits gate dispatch admission; CPU limits use
  existing task CPU accounting and scheduler delivery.
- [ ] **6.4 Preserve atomicity.** A denied reservation does not partially
  publish a child, mapping, fd, write, or network operation.
- [ ] **6.5 Expose read-only snapshots.** Live counters carry a run generation
  and state timestamp/sequence. A stale handle returns an error.
- [ ] **6.6 Add multi-task differential probes.** Cross-process `prlimit`, fork
  inheritance, shared process budgets, signal status, partial writes, and
  teardown are mandatory.

**Gate 6:** Every shipped quota has exact accounting, enforcement, and
termination semantics. Incompletely accounted resources remain absent from the
public API rather than returning plausible partial counters.

---

## Work package 7 — Kernel clock domains and deterministic time

**Purpose:** Make explicit test-time clock control coherent across all
Linux-visible time behavior.

**Initial public modes:**

```rust
pub struct SignedDuration(i128); // checked signed nanoseconds

pub enum TimeMode {
    System,
    RealtimeOffset { delta: SignedDuration },
    Manual(ManualClock),
}

impl ManualClock {
    pub fn advance(&self, delta: std::time::Duration) -> Result<(), TimeError>;
}
```

`ManualClock` owns an initial realtime value and monotonic/boottime counters;
explicit `advance` operations publish due timers and wake enrolled waiters.
“Frozen” means realtime may be fixed while monotonic behavior remains defined;
it must not silently freeze every blocking timeout. Scaled time remains
deferred until represented by exact integer/rational arithmetic and proven
across waits.

- [ ] **7.1 Inventory every time consumer.** Include `clock_gettime`,
  `gettimeofday`, nanosleep/clock_nanosleep, POSIX/interval timers, timerfd,
  futex timeouts, poll/select/epoll, socket timeouts, signal timers, file
  timestamps, CPU clocks, vDSO/vvar, scheduler watchdogs, and host-only
  infrastructure deadlines.
- [ ] **7.2 Separate guest time from host safety deadlines.** Test-controlled
  time must not stop deadlock watchdogs, cleanup deadlines, or host resource
  reclamation.
- [ ] **7.3 Move clock authority into the kernel graph.** Per-run/time-namespace
  state replaces process-global offset state on the embed path and follows
  Linux fork/clone/unshare/exec semantics.
- [ ] **7.4 Centralize due-time decisions.** Clock reads, wait enrollment,
  timer expiry, and wake publication use the same clock domain and sequence.
- [ ] **7.5 Add deterministic red-first probes.** Cover absolute/relative
  deadlines, realtime jumps, monotonic non-regression, timer overrun counts,
  EINTR/restart, simultaneous timers, fork/exec inheritance, and two waiters
  racing one `advance`.
- [ ] **7.6 Keep System mode differential.** All existing time conformance rows
  must remain exact under `TimeMode::System`. Manual-mode probes verify Linux
  relationships internally rather than comparing arbitrary absolute host time.

**Gate 7:** No Linux-visible timeout or timer bypasses the selected clock
domain, host safety clocks remain real, and System mode retains conformance and
cost.

---

## Work package 8 — Generation-safe shared buffers

**Purpose:** Deliver the useful zero-copy primitive without exposing arbitrary
live guest memory.

**Initial scope:** Host-created, page-aligned shared buffers mapped into one
prepared run through a minted capability. Arbitrary `read(addr)`/
`write(addr)` and generic `read_pod<T>` are outside the initial API.

- [ ] **8.1 Specify buffer discovery.** Choose one explicit guest contract—an
  injected fd/memfd-like object, auxv entry, environment value plus mapping
  API, or a small guest library—and prove it cannot be confused with an
  arbitrary address.
- [ ] **8.2 Define `SharedBufferLease`.** It carries run, MM, VMA/frame owner,
  and execution generations; length; protections; mapping state; and one
  retirement owner. No public host pointer outlives the lease.
- [ ] **8.3 Reuse page-backing transactions.** Mapping, stage-1/stage-2
  publication, frame inventory, rollback, fork sharing/COW, exec, unmap, and
  drop use the same authority as ordinary HVPatch memory.
- [ ] **8.4 Define concurrency semantics.** State whether host and guest may
  access concurrently, what atomicity/alignment is supported, and which side
  establishes synchronization. Data races are not hidden behind a safe Rust
  API.
- [ ] **8.5 Prove address-domain and generation failures.** Wrong run, stale
  exec generation, retired owner, changed protection, partial unmap, and IPA
  reuse fail closed.
- [ ] **8.6 Prove zero copy structurally and dynamically.** Receipts show the
  exact shared backing and no serialization/copy path, plus round-trip
  correctness across fork/exec/unmap as specified.

**Gate 8:** The only public memory primitive is a capability-minted shared
buffer with authenticated lifetime. Stale handles cannot reach reused frames,
and “zero copy” is supported by mapping evidence rather than timing alone.

---

## Work package 9 — Socket transport interposition

**Purpose:** Let tests replace selected network connections while preserving
Linux socket, fd, namespace, readiness, and signal semantics.

- [ ] **9.1 Start below protocols.** Define a TCP byte-stream `SocketTransport`
  selected after namespace, route, address-family, and endpoint resolution.
  `connect` interception alone is insufficient because read/write, shutdown,
  readiness, backpressure, errors, and close carry the observable contract.
- [ ] **9.2 Authenticate endpoint and task scope.** Matching uses the guest's
  network namespace view and exact socket description, not ambient host DNS or
  a host PID.
- [ ] **9.3 Integrate with fd descriptions and event multiplexing.** Mock
  readiness must behave through poll/select/epoll, blocking/nonblocking I/O,
  edge triggering, dup/fork, half-close, reset, timeout, and SIGPIPE.
- [ ] **9.4 Add deterministic connection records.** Metadata is bounded and
  ordered; payload capture is opt-in, size-limited, and redacted by default.
- [ ] **9.5 Add an HTTP helper only after TCP is correct.** It parses plaintext
  HTTP over the mock stream. HTTPS is not transparently mockable at `connect`;
  TLS termination, certificates, and trust injection require a separate
  approved design.
- [ ] **9.6 Differentially test Linux-visible behavior.** Guest probes compare
  fd flags, errno, readiness, partial I/O, shutdown, signals, and lifecycle
  with a real Linux server control.

**Gate 9:** A selected TCP endpoint can be served in-process without a host
server while the guest observes Linux-correct socket and epoll behavior. HTTP
convenience does not close the gate if the transport semantics are wrong.

---

## Work package 10 — Conformance diagnostics, not a self-oracle

**Purpose:** Use the embed/event APIs to improve failure localization while
preserving the independent external gate.

Do not create `carrick-conformance-next` as the first step. Extend the existing
harness or add a small support crate only when a concrete diagnostic needs a
library boundary.

- [ ] **10.1 Keep verdict authority external.** The same immutable workload
  runs under the exact signed Carrick artifact and native-arm64 Docker in
  serialized phases. Existing fail-closed assertion identity remains the
  verdict.
- [ ] **10.2 Add Carrick telemetry as a sidecar artifact.** On a divergence,
  emit bounded structured events keyed to the suite/run/task. Missing events,
  drops, and fast-path blind spots make the diagnostic incomplete but do not
  redefine the semantic result.
- [ ] **10.3 Treat Docker bpftrace as separate Linux evidence.** Run it only in
  the Docker phase with required privileges and tracefs. Record tool/version,
  probe coverage, drops, and raw artifacts. Do not align traces merely by
  ordinal syscall position.
- [ ] **10.4 Keep semantic probes in the guest.** Fork PID consistency,
  close-on-exec, signal reset, setsid, brk, mmap, close, and dup semantics are
  observable Linux contracts and belong in deterministic guest probes. Host
  observers may add structural proof but cannot replace guest-visible output.
- [ ] **10.5 Add differential property exploration through generated guest
  probes.** The same seed/case runs under both engines; invalid inputs, timeout,
  crash, shrink result, and raw outputs are retained. “No panic” is a Carrick
  robustness property, not Linux parity.
- [ ] **10.6 Keep trace fingerprints diagnostic.** A fingerprint can detect a
  changed implementation shape and help triage, but a blessed Carrick trace is
  never a correctness baseline.
- [ ] **10.7 Preserve the existing coverage model.** Update
  `docs/conformance-coverage.md` with owned invariants and probes. Do not replace
  it with an undefined argument-combination match percentage.
- [ ] **10.8 Require parity before retiring anything.** The existing harness
  remains until a replacement proves equal declared suite/probe/assertion
  inventory, fail-closed behavior, oracle validity, artifact provenance, and
  every historical false-green rejection on the same source revision.

**Gate 10:** Diagnostics point from a semantic divergence to an exact Carrick
task/syscall/lifecycle region without weakening, replacing, overlapping, or
self-validating the native Linux oracle.

---

## Deferred work packages

The following are intentionally not “readiness” tasks in earlier packages:

- async `run()` and runtime-specific `AsyncRead`/`AsyncWrite` adapters;
- tty/interactive embedding and terminal ownership in a foreign application;
- detached containers, exec, pause/restart/stop, and `ContainerHandle`;
- multiple embedded containers and `ContainerGroup`;
- bridge networking between embedded containers;
- generic layered/overlay VFS composition;
- scaled time;
- arbitrary stopped-process memory inspection and live memory mutation;
- TLS/HTTPS protocol mocking;
- replacing the existing conformance harness.

Each becomes a new design only after its prerequisite work package is green and
a real consumer justifies the API.

---

## Cross-package verification matrix

| Surface | Required proof |
| --- | --- |
| Pure request/types | Focused unit tests, compile checks for platform feature sets, no HVF/Docker |
| Runtime extraction | Red-first phase/rollback tests, default-path CLI equivalence, signed smoke |
| VFS | Unit tests plus signed line-exact guest probes against Docker |
| Events | Multi-task identity/order/drop/fast-path tests plus DTrace overhead attribution |
| Policy/faults | Fail-closed source/type tests, deterministic seeded probes, rollback/no-return receipts |
| Quotas | Kernel accounting tests, two-process differential probes, exact wait/exit/signal status |
| Time | Whole-consumer inventory, System-mode differential gate, deterministic manual-clock races |
| Shared buffers | Address/generation fail-closed tests, structural mapping receipt, fork/exec/unmap probes |
| Network | Socket/epoll differential probes, bounded payload/drop evidence, namespace isolation |
| Conformance diagnostics | Existing closure gate unchanged, serialized Docker evidence, sidecar completeness report |

### Commands future implementers must use correctly

- Use `just test`, not a bare parallel workspace library test. The recipe
  serializes fork-sensitive crates.
- Use `just build` or a dedicated signed embed-harness recipe before any macOS
  HVF guest execution. A plain `cargo build`/`just check` is compile-only.
- Rebuild `carrick-cli` and re-sign after runtime changes; bind every runtime
  result to the exact binary.
- Run `RUST_TEST_THREADS=1 just ci` at integration checkpoints. Record any
  pre-existing red gate rather than relabeling it green or weakening it.
- Use `just conformance-quick` and `just conformance-probes` as their work
  package requires. The harness must keep Carrick and Docker phases serialized.
- Run cross-platform compile/feature closure for Linux/KVM, FreeBSD/bhyve, and
  NetBSD/NVMM whenever a public/runtime-neutral interface changes. Runtime
  completion remains platform-specific unless real hardware was exercised.
- Use `carrick trace`/DTrace for reproducible guest behavior and overhead;
  use LLDB/core plus the event ring when tracing perturbs the problem.

### Performance rule

“Zero overhead when disabled” is a proof obligation:

- static inspection shows no disabled-path allocation, lock, formatting,
  pointer decoding, or indirect callback;
- controlled same-artifact ABBA runs do not demonstrate a regression;
- DTrace attributes any changed syscall/trap/host-operation amplification;
- event-heavy enabled measurements state their perturbation; and
- an unresolved noisy result remains unresolved rather than green.

Performance follows correctness for each feature, but a pathological ratio is
a correctness signal and returns the work package to mechanism diagnosis.

---

## Source-proposal coverage map

| Original component | Destination in this program |
| --- | --- |
| Builder API | Work package 1 |
| VFS injection/layering | Work package 3; generic layering deferred |
| Syscall observer | Work package 4 read-only events; behavior changes moved to Work package 5 |
| Phased runtime | Work package 2 |
| Result/lifecycle types | Work package 1 result; lifecycle handles deferred |
| Test harness utilities | Signed harness in Work package 0; testing helpers added only with real consumers |
| Multi-container readiness | Deferred |
| Time control | Work package 7 |
| Fault injection | Work package 5 |
| Zero-copy memory | Work package 8 shared buffers; raw memory API rejected |
| Network mocking | Work package 9 |
| Resource budgets | Work package 6 |
| Self-hosted conformance | Work package 10 diagnostic augmentation; self-oracle/replacement rejected |
| Workspace integration | Automatic crate membership; update crate map and feature closure per package |

---

## Program completion and progress reporting

Every work package closes with a dated evidence report under
`docs/perf-results/` containing:

- source revision and narrow commits;
- exact signed binary provenance where a guest ran;
- red-first test/probe identity and pre-fix result;
- focused and full gate commands with exit status;
- Carrick/Docker serialization and oracle/image identity where differential
  evidence was used;
- cleanup receipt;
- observer/performance perturbation statement;
- measured result versus projection;
- deferred scope and next work package; and
- explicit non-completion conditions.

The program is complete only when every non-deferred work package selected for
the product has its own approved design, task-level implementation plan,
reviewed implementation, correctness receipt, disabled-path cost receipt, and
cross-platform closure appropriate to its claim. A green unit test, signed
hello, one `MATCH`, observer trace, golden fingerprint, or `just ci` result does
not complete the program by itself.

## First future implementation session

Start with Work package 0, not crate scaffolding:

1. create an isolated ignored worktree;
2. record the current branch, dirt, and baseline gates without modifying them;
3. audit the exact embed-reachable host lifecycle after the active HVPatch fork
   closure work;
4. write and approve the embed-foundation design;
5. produce a task-level implementation plan for Work packages 0 and 1 only;
6. establish the signed in-process harness and no-extension baseline; and
7. stop if the lifecycle boundary cannot yet support a foreign multithreaded
   host process safely.

That session should not implement time control, observers, fault injection,
shared buffers, network mocks, quotas, multi-container support, or conformance
replacement.
