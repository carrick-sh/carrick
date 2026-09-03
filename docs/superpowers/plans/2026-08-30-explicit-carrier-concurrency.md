# Explicit Carrier Concurrency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose a cloneable `carrick_embed::Carrier` that admits, runs, and
shuts down multiple isolated containers with overlapping guest progress inside
one Carrick VM and kernel graph.

**Architecture:** Extract the already-proven CLI `container-gate` lifecycle
into a runtime-owned carrier state machine. An embed-facing `Carrier` holds an
`Arc` lease over that runtime, binds container identity during builder
creation, registers prepared/running workers, and closes admission before
joining and retiring them. `ContainerBuilder::from_image` remains compatible
through an explicit single-use implicit-carrier path, but never ambiently joins
an explicit carrier. Per-run process statics are moved to container/task edges;
only reviewed hardware, allocator, scheduler, signal, and diagnostic facilities
remain carrier-wide.

**Tech Stack:** Rust, Tokio `spawn_blocking`/`Notify`, Carrick kernel graph and
HVPatch carrier, OCI engine, signed HVF guest tests, conformance probes.

**Spec:**
[`docs/superpowers/specs/2026-08-30-carrier-concurrency-and-syscall-interception-design.md`](../specs/2026-08-30-carrier-concurrency-and-syscall-interception-design.md)

**Prerequisite:**
[`2026-08-30-typed-syscall-interception.md`](2026-08-30-typed-syscall-interception.md)
must be implemented and green first. This plan uses its exact public
`SyscallInterceptor` API in the final two-container demonstration.

## Global Constraints

- Reuse the existing `carrick debug container-gate` execution path and its
  `vm_create_success_events == 1` proof. Do not create a parallel scheduler or
  a second VM abstraction in `carrick-embed`.
- At most one independent live carrier owns hardware VM custody in a host
  process. Sharing occurs only by cloning an existing `Carrier`.
- `Carrier::shutdown` closes admission first, cancels and joins every live
  worker, retires every container, proves zero leaks, then releases VM custody.
- Builders and prepared containers hold carrier leases. Dropping a public
  handle cannot invalidate work already admitted.
- `ContainerBuilder::from_image` never discovers and joins an explicit carrier
  through ambient global state. It may acquire only a fresh implicit
  single-use carrier.
- Container state includes PID/UTS/network namespaces, rootfs/VFS, seccomp,
  extensions, clock, budget, stdio, results, and cancellation. These values may
  not be process-global.
- Carrier-wide state is limited to hardware VM/backend custody, kernel arena,
  global-frame allocation, bounded vCPU scheduling, shared-futex authority,
  host signal/watchdog installation, and carrier diagnostics whose events name
  a container.
- Concurrent blocking execution is supported only from separate host threads.
  Async `.run()` uses separate blocking workers.
- No guest gate passes by skip. No baseline or Docker-oracle cache may be
  re-blessed as part of this feature.
- Use scoped `CARRICK_RUN_ID` cleanup; never use `pkill -f carrick`.

---

### Task 1: Replace Process-Global Carrier Counters with a Runtime State Machine

**Files:**

- Modify: `crates/carrick-runtime/src/carrier.rs`
- Modify: `crates/carrick-runtime/src/run_result.rs`
- Modify: `crates/carrick-runtime/src/lib.rs:310-330`
- Modify: `crates/carrick-runtime/src/prepare.rs`
- Modify: `crates/carrick-observability/src/vm_lifecycle.rs`

**Interfaces:**

- Consumes: existing `ContainerAdmission`, `retire_container`,
  `live_container_count`, VM lifecycle ledger, and persistent VM teardown.
- Produces: runtime-owned `CarrierRuntime`, `CarrierLease`, admission state,
  typed lifecycle errors, registry snapshots, and reusable carrier generations.

- [ ] **Step 1: Write red carrier-state tests**

Replace the existing tests' dependence on non-resettable statics with tests for
these transitions:

```text
Open -> Closing -> Closed
Open + reserve -> Prepared -> Running -> Retired
Open + failed prepare -> Retired
Closing + reserve -> CarrierClosing
Closed + reserve -> CarrierClosed
```

Also test that a second independent `CarrierRuntime::new_explicit()` returns
`CarrierAlreadyActive`, cloning shares the same generation, and a new carrier
can be created only after the previous generation is closed and its final lease
is dropped. Create two carrier generations sequentially in one test process and
assert that the second snapshot counts only VM lifecycle events emitted after
its own creation cursor. Close both and assert that each window accepts exactly
one terminal without producing `DuplicateRunTerminal`. Repeat more generations
than the current 64-event capacity and prove completed windows do not cause a
later active window to report `EventCapacityExceeded`.

Run:

```bash
cargo test -p carrick-runtime carrier::tests --lib
```

Expected: FAIL because state is held in `LIVE_CONTAINERS`,
`LAST_CONTAINER_TERMINAL`, and `SHUTDOWN_DONE` statics.

- [ ] **Step 2: Define the runtime carrier types**

Use a process-global `Mutex<Weak<CarrierInner>>` only as the independent-owner
gate. Put mutable lifecycle state in the active `CarrierInner`:

```rust
#[derive(Clone)]
pub struct CarrierRuntime {
    inner: Arc<CarrierInner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierAdmissionState {
    Open,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInitSnapshot {
    pub container_id: ContainerId,
    pub internal_task_id: TaskId,
    pub namespace_pid: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierSnapshot {
    pub generation: u64,
    pub state: CarrierAdmissionState,
    pub live_containers: usize,
    pub kernel_graphs: usize,
    pub runtime_directories: usize,
    pub registered_containers: usize,
    pub live_tasks: usize,
    pub live_pid_regions: usize,
    pub live_mounts: usize,
    pub live_frame_leases: usize,
    pub live_vcpu_leases: usize,
    pub live_continuations: usize,
    pub live_job_groups: usize,
    pub live_workers: usize,
    pub vm_create_success_events: usize,
    pub vm_lifecycle_violations: usize,
    pub container_inits: Vec<ContainerInitSnapshot>,
}
```

Sort `container_inits` by `ContainerId` so concurrent publication cannot make
the evidence order nondeterministic.

`CarrierInner` contains the generation, state mutex, a
`BTreeMap<ContainerId, ContainerRecord>`, latest terminal, a transactionally
published `Arc<CarrierKernelRuntime>` slot, and a notification primitive. The
published value contains both the shared `Arc<Kernel>` and the shared
`Arc<HvpatchRuntimeDirectory>`/executor services; publishing only the graph
while creating one scheduler per run is forbidden. Do not put
`RunSpec`, VFS instances, observer/interceptor chains, or stdio buffers in this
object.

Open a typed `VmLifecycleWindow` when each carrier generation is created. Keep
the next serial and sequence monotonic at process scope, but store events,
violations, and the unique terminal in the active window. At most one window is
active because independent carrier admission is process-exclusive. Finalizing
a window returns its immutable snapshot and moves only a bounded summary into
recent diagnostic history, so an unbounded sequence of valid carrier
generations cannot exhaust the current 64-event buffer. Do not reset global
serial/sequence counters or clear a live shared ledger.

Every VM create count, violation, and terminal-state assertion exposed by
`CarrierSnapshot` considers only its window, so a later carrier in the same
signed test executable cannot inherit an earlier generation's VM count,
violation, terminal, or capacity usage.

Keep the existing v1 one-VM artifact schema and validator, but feed them the
completed window snapshot for the carrier being closed. Raw window records use
the globally monotonic sequence values; the v1 artifact materializer rebases
that selected window to relative sequences 1 through 5 before validation and
serialization. Preserve `process_snapshot()` compatibility as the active or
most recently finalized window plus bounded summaries; do not pass aggregated
multi-window history to the single-VM validator or weaken duplicate-terminal
detection inside one window.

- [ ] **Step 3: Make container admission an owned lease**

Change admission to be created by `CarrierRuntime::reserve(LaunchContext)` and
to hold a weak/strong carrier reference plus the exact container id and
generation. Provide explicit transitions:

```rust
impl CarrierLease {
    pub fn launch(&self) -> &LaunchContext;
    pub(crate) fn mark_running(&self) -> Result<(), RuntimeError>;
    pub(crate) fn retire(self, container: Arc<Container>)
        -> Result<ContainerTeardown, RuntimeError>;
}
```

Dropping an unretired `Prepared` lease performs rollback and wakes shutdown.
Dropping a `Running` lease without a terminal receipt marks the carrier failed;
it must not silently decrement a census.

- [ ] **Step 4: Add typed runtime lifecycle errors**

Add distinct `RuntimeError` variants for `CarrierAlreadyActive`,
`CarrierClosing`, `CarrierClosed`, and `CarrierFailed(String)`. Do not encode
these states as substring-matched `Configuration(String)` values.

- [ ] **Step 5: Replace `Runtime::prepare`'s static initializer**

Move one-time allocator/cache initialization into
`CarrierRuntime::initialize_facilities`. Add:

```rust
pub fn prepare_on(
    carrier: &CarrierRuntime,
    spec: &RunSpec,
    lease: CarrierLease,
    ext: RuntimeExtensions,
) -> Result<PreparedRun, RuntimeError>;
```

Keep `Runtime::prepare` as an internal compatibility wrapper over the CLI's
process carrier until Task 5 rewires every caller.

- [ ] **Step 6: Run carrier and prepare tests**

```bash
cargo test -p carrick-runtime carrier::tests --lib
cargo test -p carrick-runtime prepare::tests --lib
```

Expected: PASS.

- [ ] **Step 7: Commit the runtime state machine**

```bash
git add crates/carrick-runtime/src/carrier.rs \
  crates/carrick-runtime/src/run_result.rs \
  crates/carrick-runtime/src/lib.rs \
  crates/carrick-runtime/src/prepare.rs \
  crates/carrick-observability/src/vm_lifecycle.rs
git commit -m "runtime: own container admission in a carrier state machine"
```

---

### Task 2: Bootstrap Every Container into One Carrier Kernel Graph

**Files:**

- Modify: `crates/carrick-runtime/src/carrier.rs`
- Modify: `crates/carrick-runtime/src/kernel/core.rs`
- Modify: `crates/carrick-runtime/src/kernel/operations.rs`
- Modify: `crates/carrick-runtime/src/kernel/container.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs:1354-1465`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs:260-390`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/continuation.rs`
- Modify: `crates/carrick-runtime/src/namespace/pid.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/creds.rs`
- Modify: `crates/carrick-runtime/src/dispatch/proc.rs`
- Modify: `crates/carrick-runtime/src/vfs/proc.rs`

**Interfaces:**

- Consumes: `Kernel::bootstrap_root`, `Kernel::create_container`, the kernel's
  `IdRegistry`, `initialize_root_process`, `HvpatchRuntimeDirectory`,
  per-container PID regions, and `CarrierRuntime`'s kernel-runtime slot.
- Produces: one shared `Arc<Kernel>` and one shared scheduler/executor directory
  per carrier, plus transactional bootstrap of multiple container-init tasks
  with distinct internal ids but namespace PID 1.

- [ ] **Step 1: Write the red shared-graph reference-model test**

Bootstrap alpha into a new carrier kernel, then bootstrap beta into the same
carrier. Assert:

- `Arc::ptr_eq(alpha.kernel(), beta.kernel())`;
- `kernel.container_count() == 2`;
- alpha and beta have different `TaskKey` and `ThreadKey` values;
- both contexts translate their own task to namespace PID 1;
- neither context can resolve the other's internal task id through its PID
  namespace; and
- each context resolves its own container-init authority;
- alpha's `kill(-1)`, orphan adoption, and init-signal rules cannot target beta;
  and
- retiring the first-booted alpha removes only alpha's task tree and container
  registry entry while beta remains a valid kernel root.

Run:

```bash
cargo test -p carrick-runtime kernel::tests::two_container_roots_share_one_kernel_graph --lib
```

Expected: FAIL because `initialize_root_process` calls
`Kernel::bootstrap_root` for every run.

- [ ] **Step 2: Separate internal task identity from namespace PID 1**

For the first container, preserve the existing bootstrap path. For every later
container, allocate a fresh carrier-kernel `TaskId` and leader `LinuxTid` from
the installed kernel's id authority. Register that internal task id in the
container's `NsSharedRegion` as namespace PID 1. Do not use
`LINUX_BOOTSTRAP_PID` as the registry key for the second root.

Audit `ProcessGroupId` and `SessionId` construction at the same boundary: their
internal ids must be collision-free in the shared registry while guest-facing
PID-namespace translation reports the new init's values as 1.

Replace `RegistryState::root` with a container-keyed init registry. Add
`Kernel::container_init(ContainerId)` and make init protection compare against
the calling task's container init, never internal task id 1. Scope `kill(-1)`
and every all-task/process-group broadcast to the caller's container. Reparent
orphans only to that container's live init; if its init is exiting, follow the
container teardown rule rather than adopting into the first carrier root.

Audit every guest-visible identity surface, not only registry lookup. Route
`getpid`, `gettid`, `getppid`, `getpgid`, `getsid`, credential helpers,
filesystem-owner rendering, signal/process-group arguments, and every returned
PID/TID/PPID/PGID/SID—including fork/clone/vfork parent completion values—
through the existing context-aware translation in
`namespace/pid.rs`. Cross-container raw ids must resolve as invisible/`ESRCH`,
never leak the carrier-global identifier. Filter the shared kernel task census
by the caller's container before `/proc` enumeration, lookup, task-directory
rendering, symlink targets, status/stat generation, or directory cookies; then
translate only the retained ids into the caller's namespace. Alpha must not
enumerate beta even if beta's internal id happens to be a syntactically valid
alpha namespace number.

Use this census and classify every hit before completing the task:

```bash
rg -n "(getpid|gettid|getppid|getpgid|getsid|setpgid|TaskId|LinuxTid|ProcessGroupId|SessionId|list_tasks|snapshot_tasks|root_container|LINUX_BOOTSTRAP_PID)" \
  crates/carrick-runtime/src/dispatch \
  crates/carrick-runtime/src/vfs/proc.rs \
  crates/carrick-runtime/src/vcpu_loop/continuation.rs
```

- [ ] **Step 3: Add transactional `Kernel::prepare_container_root`**

Implement a prepare/commit/abort operation that creates the later root task,
leader thread, MM, resources, process group, session, observation entries, and
container table entry under one reservation. Publish all edges together on
commit. Abort removes every prepared edge and releases each exact id claim.

Add the inverse `Kernel::retire_container_root` transaction at the same
boundary. It must mark only the selected container exiting, cancel and reap its
task tree, remove its process-group/session and observation edges, release its
PID-namespace region, and finally remove its container-table entry. Return the
real `tasks_reaped` and `pid_regions_released` counts; do not leave the current
hard-coded zero values from `Container::retire` as cleanup evidence.

Return a `KernelContext` for the new init. Do not mutate `root_container` or
reuse first-root resources. Replace callers of `Kernel::root_container` that
answer a guest/container question with context-based container lookup, then
remove the singular root field once all invariant tests use the container-init
registry.

- [ ] **Step 4: Publish one kernel and one scheduler runtime under concurrent boot**

Add a carrier boot transaction around the kernel-runtime slot. The first
successful root boot publishes `Arc<CarrierKernelRuntime>` containing its
`Arc<Kernel>` and one `Arc<HvpatchRuntimeDirectory>`. A concurrent loser
observes both and uses `prepare_container_root`. Pass the directory to every
`KernelState::new` instead of `None`, so later containers cannot create a
second scheduler, continuation service, executor pool, auxiliary debug
provider, or process-job directory. A
failed first boot publishes nothing. A failed later boot leaves the existing
graph, shared services, and sibling containers intact.

Replace directory-wide job drain/join with a container-keyed `ContainerJobGroup`
token. Normal run retirement joins only that container's jobs and never shuts
down the shared executor pool. Only `Carrier::shutdown` joins the remaining job
groups and closes the pool.

- [ ] **Step 5: Rewire HVPatch initialization**

Pass `CarrierRuntime` into `initialize_root_process`. Bind MM inventory,
dispatcher process context, file authority, identity page, and debug metadata
to the `KernelContext` returned by the carrier boot transaction. Install the
kernel debug server once per carrier. Publish the shared scheduler/executor
auxiliary debug provider once with an exact unregister token; reject a second
distinct provider rather than aggregating unscoped rows. The former per-run
provider becomes carrier-owned with the shared runtime directory.

- [ ] **Step 6: Add boot-race and rollback tests**

Race two reference-model roots at a barrier and assert exactly one kernel graph
and one pointer-identical runtime directory are published with both containers.
Inject a failure before later-root commit and assert the first container remains
live, counts are unchanged, and the failed container's ids/namespace region are
reclaimable. Add a job-scope test where alpha exits first: its join must leave a
blocked beta continuation and beta executor capacity live. Retiring the
first-booted container must leave beta's init authority and directory valid.
Add a table-driven guest-identity test covering PID/TID/PPID/PGID/SID-returning
syscalls, fork/clone/vfork parent returns (including deferred vfork
continuation completion), and credential/fs owner paths. Build two proc trees concurrently and
assert each root sees its own init as 1, sees only its own task set, cannot open
or signal the sibling's raw internal ids, and never renders a carrier-global id
in `stat`, `status`, task directories, symlinks, or directory entries.

- [ ] **Step 7: Run kernel and HVPatch host tests**

```bash
cargo test -p carrick-runtime kernel::tests::two_container_roots_share_one_kernel_graph --lib
cargo test -p carrick-runtime carrier::tests::concurrent_kernel_boot --lib
cargo test -p carrick-runtime hvpatch::tests::container_root --lib
cargo test -p carrick-runtime vcpu_loop::tests::container_job_groups_are_scoped --lib
cargo test -p carrick-runtime dispatch::tests::container_pid_identity_isolated --lib
cargo test -p carrick-runtime vfs::proc::tests::container_task_census_isolated --lib
```

Expected: PASS.

- [ ] **Step 8: Commit the shared kernel graph**

```bash
git add crates/carrick-runtime/src/carrier.rs \
  crates/carrick-runtime/src/kernel/core.rs \
  crates/carrick-runtime/src/kernel/operations.rs \
  crates/carrick-runtime/src/kernel/container.rs \
  crates/carrick-runtime/src/hvpatch/mod.rs \
  crates/carrick-runtime/src/threaded_loop.rs \
  crates/carrick-runtime/src/vcpu_loop/mod.rs \
  crates/carrick-runtime/src/vcpu_loop/continuation.rs \
  crates/carrick-runtime/src/namespace/pid.rs \
  crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/dispatch/fs.rs \
  crates/carrick-runtime/src/dispatch/creds.rs \
  crates/carrick-runtime/src/dispatch/proc.rs \
  crates/carrick-runtime/src/vfs/proc.rs
git commit -m "runtime: boot container roots in one carrier kernel"
```

---

### Task 3: Move Root UTS and Network State onto Each Container

**Files:**

- Modify: `crates/carrick-runtime/src/kernel/container.rs`
- Modify: `crates/carrick-runtime/src/kernel/netns.rs`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs`
- Modify: `crates/carrick-runtime/src/prepare.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Modify: `crates/carrick-runtime/src/vfs/sys.rs`
- Modify: `crates/carrick-runtime/src/vfs/proc.rs`

**Interfaces:**

- Consumes: current `root_net_ns`, `root_uts_ns`, `publish_root_net_view`, and
  `publish_root_nodename` cells; task `NsProxy`.
- Produces: container-owned initial `Arc<NetNs>`/`Arc<UtsNs>` reached only
  through task/container identity.

- [ ] **Step 1: Add a red two-container namespace unit test**

Create two `Container::for_reference_model()` values with different hostname
and `LinuxNetworkModel` values. Bootstrap task contexts for each and assert that
`uname`, `/sys/class/net`, netlink, and `/proc/net` render their own values after
the other container is mutated.

Run:

```bash
cargo test -p carrick-runtime kernel::netns::tests::containers_do_not_share_root_uts_or_net --lib
```

Expected: FAIL because both `NsProxy` values clone the process-global roots.

- [ ] **Step 2: Add namespaces to `Container`**

Add `net_ns: Arc<NetNs>` and `uts_ns: Arc<UtsNs>` fields. Construct fresh
namespace ids and a host-mirror/default hostname in `Container::new`, then add
read-only accessors and builder-style launch overrides:

```rust
pub(crate) fn with_network_model(self, model: LinuxNetworkModel) -> Self;
pub(crate) fn with_hostname(self, hostname: impl Into<String>) -> Self;
pub(crate) fn net_ns(&self) -> &Arc<NetNs>;
pub(crate) fn uts_ns(&self) -> &Arc<UtsNs>;
```

- [ ] **Step 3: Delete the root cells and publication helpers**

Change `NsProxy::for_container` to clone from the supplied container. Route all
guest-facing fallback reads through the calling task/container. Remove
`root_net_ns`, `root_uts_ns`, `publish_root_net_view`, and
`publish_root_nodename` after `rg` shows no callers.

- [ ] **Step 4: Make preparation set namespaces before graph publication**

Build the final network model and hostname into the `Container` before wrapping
it in `Arc` and before installing the PID namespace or dispatcher binding.
Preparation failure must drop only that unpublished container.

- [ ] **Step 5: Run focused namespace and filesystem tests**

```bash
cargo test -p carrick-runtime kernel::netns --lib
cargo test -p carrick-runtime dispatch::tests::hostname --lib
cargo test -p carrick-runtime vfs::proc --lib
cargo test -p carrick-runtime vfs::sys --lib
```

Expected: PASS.

- [ ] **Step 6: Commit per-container namespaces**

```bash
git add crates/carrick-runtime/src/kernel/container.rs \
  crates/carrick-runtime/src/kernel/netns.rs \
  crates/carrick-runtime/src/kernel/mod.rs \
  crates/carrick-runtime/src/prepare.rs \
  crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/execute.rs \
  crates/carrick-runtime/src/lib.rs \
  crates/carrick-runtime/src/vfs/sys.rs \
  crates/carrick-runtime/src/vfs/proc.rs
git commit -m "runtime: isolate root namespaces per container"
```

---

### Task 4: Replace Ambient Thread/Futex and Separate Carrier/Container Run Scope

**Files:**

- Modify: `crates/carrick-thread/src/thread.rs`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs`
- Modify: `crates/carrick-runtime/src/dispatch/signal.rs`
- Modify: `crates/carrick-runtime/src/dispatch/proc.rs`
- Modify: `crates/carrick-runtime/src/vfs/proc.rs`
- Modify: `crates/carrick-runtime/src/dispatch/proctitle.rs`
- Modify: `crates/carrick-runtime/src/kernel/container.rs`
- Modify: `scripts/migrate/runtime-global-state.json`
- Modify: `scripts/migrate/check-runtime-global-state.py`
- Modify: `scripts/tests/test_runtime_global_state.py`
- Modify: `docs/identity-and-scope-domains-embed-census.md`

**Interfaces:**

- Consumes: `CURRENT_REGISTRY`, `CURRENT_FUTEX_TABLE`, process-global `RUN_ID`,
  dispatcher/kernel task identity, and the global-state ledger.
- Produces: container-keyed runtime endpoints, one cleanup-safe carrier scope,
  distinct container run ids, and a carrier-summary host title.

- [ ] **Step 0: Refresh and classify the complete concurrency census**

Expand the checker roots to include `crates/carrick-thread/src`,
`crates/carrick-embed/src`, and `crates/carrick-observability/src`. For every
mutable static/thread-local/environment read reachable from preparation,
HVPatch execution, continuation, signal, filesystem, networking, diagnostics,
or teardown, record one disposition in
`docs/identity-and-scope-domains-embed-census.md`:

- move to the calling `Container`/task/runtime endpoint;
- move to `CarrierInner` with its synchronization and teardown contract; or
- retain as host/process infrastructure with a proof that concurrent
  containers cannot overwrite or misroute it.

The census must explicitly cover root UTS/net cells, current thread/futex
registries, timer delivery, kernel debug server, process title, pty registries,
FIFO beacons, socket error/reuseport/SCTP registries, filesystem caches,
FileAuthority, signal delivery, vCPU permits, frame/IPA allocators, event ring,
and lifecycle ledger. A row marked container debt on the concurrent path blocks
Task 8's guest gate.

- [ ] **Step 1: Add red cross-container routing tests**

Install two registries and futex tables for different `ContainerId` values.
Assert that `/proc/<pid>/task`, thread name lookup, signal liveness, and timer
futex wake for alpha never consult beta. Add a host-title test proving a second
container does not overwrite the immutable carrier cleanup scope while both
containers still receive distinct run ids.

Run:

```bash
cargo test -p carrick-thread container_registry --lib
cargo test -p carrick-runtime cross_container_runtime_endpoint --lib
```

Expected: FAIL because current state is process-global.

- [ ] **Step 2: Introduce a container-keyed runtime endpoint registry**

Replace the two current cells with a carrier-wide map whose key is
`ContainerId` and whose value holds weak registry/futex references. Require an
explicit `ContainerId` for lookup and remove every no-argument
`current_*` accessor. Registration returns an RAII token that removes only the
exact `(container_id, generation)` entry.

- [ ] **Step 3: Route callers from task identity**

At syscall sites, derive the id from `KernelContext::task().container().id()`.
At asynchronous timer/signal sites, capture the container id and endpoint token
when the helper is created. Never infer the container from the current host
thread.

- [ ] **Step 4: Separate carrier cleanup scope from container run ids**

Retain the discovered argv/environ buffer as process infrastructure, but remove
the cached current-container run id. Resolve one immutable `CarrierScopeId` at
carrier creation: use the exact non-empty host `CARRICK_RUN_ID` when present,
otherwise generate a collision-resistant scope. Keep the process title in the
existing cleanup-compatible shape
`carrick:<carrier-scope>: <live-count> containers`; never rewrite it to an
individual container after admission.

Allocate a distinct `RunId` for every explicit-carrier container under that
scope and store both ids in `LaunchContext` and receipts. Preserve the exact
outer run id for an implicit single-use/ordinary CLI carrier where compatibility
requires it. `scripts/sudo/kill.sh <carrier-scope>` remains the process-level
recovery mechanism and may terminate the whole shared carrier; cancelling one
container uses its carrier API/kernel handle, never the process reaper. Add
tests that two containers have distinct run ids while the host title still
contains the exact scope that `kill.sh` searches.

- [ ] **Step 5: Strengthen the static-state gate**

Reclassify retained cells in `runtime-global-state.json`, add the new keyed
registry, and teach the checker to reject:

- no-argument `current_*registry`/`current_*futex` accessors;
- mutable `static` values named for one run/container; and
- calls to `std::env::var("CARRICK_RUN_ID")` below the launch-context boundary.

Add checker unit tests for each rejected and allowed shape.

Add `--require-concurrent-embed-clean`. In this mode any reachable ledger row
still classified `container_debt` is an error even when it names a destination;
the ordinary monotone-ledger mode may retain that classification for unrelated
future work. Require this mode in Task 8 and the final gate so the feature
cannot pass on a prose-only promise. Classify the process lifecycle ledger and
its window cursor explicitly under the newly scanned observability root.

- [ ] **Step 6: Run focused and static gates**

```bash
cargo test -p carrick-thread container_registry --lib
cargo test -p carrick-runtime cross_container_runtime_endpoint --lib
python3 -m unittest scripts.tests.test_runtime_global_state
python3 scripts/migrate/check-runtime-global-state.py --check
python3 scripts/migrate/check-runtime-global-state.py --check --require-concurrent-embed-clean
just lint-domains
```

Expected: PASS.

- [ ] **Step 7: Commit ambient-state removal**

```bash
git add crates/carrick-thread/src/thread.rs \
  crates/carrick-runtime/src/threaded_loop.rs \
  crates/carrick-runtime/src/dispatch/signal.rs \
  crates/carrick-runtime/src/dispatch/proc.rs \
  crates/carrick-runtime/src/vfs/proc.rs \
  crates/carrick-runtime/src/dispatch/proctitle.rs \
  crates/carrick-runtime/src/kernel/container.rs \
  scripts/migrate/runtime-global-state.json \
  scripts/migrate/check-runtime-global-state.py \
  scripts/tests/test_runtime_global_state.py \
  docs/identity-and-scope-domains-embed-census.md
git commit -m "runtime: route process services by container identity"
```

---

### Task 5: Bind `PreparedRun` and Every Runtime Caller to a Carrier Lease

**Files:**

- Modify: `crates/carrick-runtime/src/prepare.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs`
- Modify: `crates/carrick-runtime/src/carrier.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/debug.rs:954-1035`
- Modify: `crates/carrick-cli/src/main.rs`

**Interfaces:**

- Consumes: Task 1's `CarrierLease`, current `Runtime::prepare`,
  `run_address_space_with_hvf_and_dispatcher`, and CLI container gate.
- Produces: one lease path for CLI and embedding; no runtime-global admission.

- [ ] **Step 1: Add red lease-ownership tests**

Add tests proving `PreparedRun` owns one prepared lease, execute transitions it
once, a boot failure retires it once, and the container registry is empty after
all result paths. Include a compile-fail ownership test that a `PreparedRun`
cannot execute twice.

Run:

```bash
cargo test -p carrick-runtime prepare::tests::prepared_run_owns_carrier_lease --lib
```

Expected: FAIL because admission currently occurs inside
`run_address_space_with_hvf_and_dispatcher`.

- [ ] **Step 2: Carry the lease in `PreparedRun`**

Add `carrier: CarrierRuntime` and `lease: CarrierLease` fields. Move admission
out of the run loop. At execute start, transition the lease to running; on
every terminal/boot-error path, retire with the exact container and record the
terminal on that carrier generation.

- [ ] **Step 3: Remove global carrier calls from runtime execution**

Delete direct calls to `admit_container`, global `record_container_terminal`,
and global `retire_container`. Pass the carrier/lease explicitly through the
macOS HVPatch path. Keep non-macOS compilation explicit even where execution is
still `Unsupported`.

- [ ] **Step 4: Rewire CLI execution to one process carrier**

Construct one `CarrierRuntime` at CLI startup, pass clones through ordinary
commands and the debug container gate, and shut it down in the existing single
exit funnel. Remove the debug gate's manual allocator/cache initialization and
global shutdown; it now uses the same carrier as ordinary CLI runs.

- [ ] **Step 5: Preserve the current gate proof**

Keep the existing sequential/concurrent debug gate behavior and receipt keys.
Its two `Runtime::execute` calls become two reservations on the one explicit
runtime carrier. Do not weaken the assertions for one VM or zero live
containers.

- [ ] **Step 6: Run host tests and the signed existing gate**

```bash
cargo test -p carrick-runtime prepare::tests --lib
cargo test -p carrick-runtime carrier::tests --lib
cargo test -p carrick-cli --test conformance conformance_container_gate --no-run
just gate-containers
```

Expected: PASS. The signed receipt must still report one VM create in both
sequential and concurrent modes.

- [ ] **Step 7: Commit explicit runtime ownership**

```bash
git add crates/carrick-runtime/src/prepare.rs \
  crates/carrick-runtime/src/runtime.rs \
  crates/carrick-runtime/src/threaded_loop.rs \
  crates/carrick-runtime/src/carrier.rs \
  crates/carrick-cli/src/commands.rs \
  crates/carrick-cli/src/debug.rs \
  crates/carrick-cli/src/main.rs
git commit -m "runtime: bind every prepared run to its carrier"
```

---

### Task 6: Add the Public `carrick_embed::Carrier` and Builder Binding

**Files:**

- Create: `crates/carrick-embed/src/carrier.rs`
- Modify: `crates/carrick-embed/src/lib.rs`
- Modify: `crates/carrick-embed/src/builder.rs`
- Modify: `crates/carrick-embed/src/prepared.rs`
- Modify: `crates/carrick-embed/src/error.rs`
- Modify: `crates/carrick-embed/src/testing.rs`
- Modify: `crates/carrick-embed/Cargo.toml`

**Interfaces:**

- Consumes: `CarrierRuntime`, `CarrierLease`, `LaunchContext`, image resolution,
  and existing builder/prepared execution.
- Produces: the approved public `Carrier` API, explicit builder binding, and
  source-compatible implicit single-use behavior.

- [ ] **Step 1: Write red public lifecycle tests**

Add compile-time assertions for `Carrier: Clone + Send + Sync`. Add async
host-only tests proving:

- `Carrier::new()` then second `Carrier::new()` returns
  `EmbedError::CarrierAlreadyActive`;
- `carrier.container(image)` binds the carrier's generation and allocates a
  unique launch identity;
- closing refuses new preparation with `CarrierClosing`;
- closed refuses reuse with `CarrierClosed`; and
- a failed image resolution releases its reservation.

Run:

```bash
cargo test -p carrick-embed carrier --lib
```

Expected: FAIL because `Carrier` does not exist.

- [ ] **Step 2: Implement the public handle**

Expose this exact surface:

```rust
pub struct Carrier {
    inner: Arc<CarrierInner>,
}

impl Carrier {
    pub fn new() -> Result<Self, EmbedError>;
    pub fn container(&self, image: impl Into<String>) -> ContainerBuilder;
    pub async fn shutdown(self) -> Result<(), EmbedError>;
}
```

Implement `Clone` and `Drop` deliberately. Only user-facing `Carrier` clones
hold the `Arc<CarrierInner>`; builders, prepared containers, and workers clone
the contained `CarrierRuntime` lease instead. This makes the final public
handle detectable without confusing it with worker ownership. An explicit
`shutdown(self)` closes the shared runtime for all clones; dropping the last
public handle initiates the fallback close specified in Task 7.

Do not add `snapshot` to the stable `Carrier` surface approved by the spec.
Under a new non-default `test-support` feature, expose read-only
`testing::carrier_snapshot(&Carrier)` telemetry for the in-process gate:
carrier generation and state; kernel-graph, runtime-directory,
registered-container, task, PID-region, mount, frame, vCPU, continuation, job
group, builder-lease, prepared-lease, worker-lease, and worker counts; tracked
finalizer state; and sequence-scoped VM create and violation counts.
Production docs must not present this test evidence seam as a supported
embedding interface.

- [ ] **Step 3: Bind builders and prepared containers explicitly**

Add a private enum:

```rust
enum CarrierBinding {
    Explicit(CarrierRuntime),
    ImplicitSingleUse,
}
```

`Carrier::container` clones only its contained runtime into `Explicit`;
`ContainerBuilder::from_image` creates `ImplicitSingleUse`. The builder
reserves its `LaunchContext` through the binding and passes the resulting lease
to `PreparedContainer`. Represent builder, prepared-container, and worker
ownership as explicit `CarrierLeaseKind::{Builder, Prepared, Worker}` values in
the carrier census; converting one phase to the next transfers the lease
without a zero-owner gap. Remove `PreparedContainer`'s call to
`embedded_launch_context()`.

- [ ] **Step 4: Preserve the standalone builder without ambient attachment**

At `prepare`, an implicit builder asks for a fresh implicit carrier. If an
explicit carrier is active, return a configuration error containing the exact
remedy `use carrier.container(image)`. The implicit carrier closes after its
single prepared/run lease retires. It must not call `Carrier::new` and then
expose a public handle.

- [ ] **Step 5: Add typed embed lifecycle errors**

Add public variants `CarrierAlreadyActive`, `CarrierClosing`, `CarrierClosed`,
and `CarrierFailed { reason: String }`. Map the runtime variants by type, not
message text. Keep `EmbedError::InterceptorPanicked` from the prerequisite plan
unchanged.

- [ ] **Step 6: Run embed lifecycle tests**

```bash
cargo test -p carrick-embed carrier --lib
cargo test -p carrick-embed builder --lib
cargo test -p carrick-embed prepared --lib
```

Expected: PASS.

- [ ] **Step 7: Commit the public API**

```bash
git add crates/carrick-embed/src/carrier.rs \
  crates/carrick-embed/src/lib.rs \
  crates/carrick-embed/src/builder.rs \
  crates/carrick-embed/src/prepared.rs \
  crates/carrick-embed/src/error.rs \
  crates/carrick-embed/src/testing.rs \
  crates/carrick-embed/Cargo.toml
git commit -m "embed: expose an explicit Carrick carrier"
```

---

### Task 7: Track Workers, Cancellation, and Deterministic Shutdown

**Files:**

- Modify: `crates/carrick-embed/src/carrier.rs`
- Modify: `crates/carrick-embed/src/builder.rs`
- Modify: `crates/carrick-embed/src/prepared.rs`
- Modify: `crates/carrick-runtime/src/carrier.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/continuation.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/vfs/mod.rs`

**Interfaces:**

- Consumes: Tokio blocking tasks, kernel process-exit/continuation cancellation,
  vCPU kicker, container retirement, and carrier admission state.
- Produces: independently cancellable run records and orderly carrier shutdown.

- [ ] **Step 1: Add red shutdown-race tests**

Use host-only fake workers to prove:

- shutdown closes admission before it signals workers;
- all joins finish before the runtime carrier closes;
- one guest/run failure does not close the carrier;
- a carrier-terminal failure cancels every worker;
- concurrent shutdown calls observe the same terminal result; and
- dropping the final public handle returns before a blocked fake finalizer,
  starts close without invalidating a builder-held, prepared-held, or
  worker-held lease, and releases the process owner gate only after the final
  lease retires.

Run:

```bash
cargo test -p carrick-embed carrier::tests::shutdown --lib
cargo test -p carrick-runtime carrier::tests::shutdown --lib
```

Expected: FAIL.

- [ ] **Step 2: Register async and blocking workers**

Give each admitted container one run record containing its container id,
cancellation handle, terminal slot, and join state. `.run()` registers the
`spawn_blocking` handle before returning control to the caller.
`run_blocking()` registers a synchronous worker guard and requires separate
host threads for concurrent calls.

Carry teardown telemetry with the run record. Before dropping a dispatcher or
VFS, snapshot the selected container's live mount count; combine it with the
real kernel task/PID retirement counts and frame/vCPU/continuation lease counts
in the carrier registry. Never infer cleanup from an `Arc` strong count or a
zero-filled receipt.

Maintain separate builder, prepared, and worker lease counts plus their
container/generation identities. A phase transition atomically replaces its
old lease kind with the new one. Closing may reject new preparation and cancel
active work, but it may not release VM/runtime ownership while any admitted
lease kind remains. Add tests for close requested before any worker exists,
prepared-but-not-run close, worker close, and builder/prepared/worker phase
transfer races.

- [ ] **Step 3: Add a kernel-backed cancellation handle**

Capture the exact root task/executor endpoint after boot publication. On
cancel, mark the container exiting, cancel kernel-owned continuations with
`CancellationCause::ServiceShutdown`, and kick its live vCPUs. Scope every
operation by container id/generation. Cancellation of alpha must not iterate or
signal beta's tasks.

- [ ] **Step 4: Implement shutdown ordering**

Create one tracked carrier-finalizer authority when `CarrierInner` is created.
It owns no admission lease, has a named join handle/completion slot recorded in
`CarrierRuntime`, and parks until close is requested. Both explicit shutdown
and fallback drop signal this same authority; no finalizer is spawned from
`Drop`.

`Carrier::shutdown` requests and awaits that finalizer, which performs:

1. atomic `Open -> Closing`;
2. snapshot and cancel all live run records;
3. await/join all workers;
4. retire remaining prepared reservations and container job groups;
5. assert empty task/container/namespace/mount/frame/vCPU/continuation/job
   registries;
6. close and join the one carrier scheduler/continuation/executor directory;
7. destroy the persistent VM and publish one carrier-window terminal receipt;
   and
8. transition to `Closed` and release the process owner gate.

If VM custody becomes invalid, transition to `Failed`, cancel siblings, and
return `CarrierFailed` after joins.

Implement last-handle drop without an async wait, synchronous destruction, or
join: it atomically starts closing and wakes the already-tracked finalizer.
That authority waits for or retires work according to the shutdown contract,
and releases the process owner gate only after the builder/prepared/worker
lease census and all runtime registries are empty. The last admitted lease
wakes the finalizer when it retires; it never performs carrier destruction on
the user's drop path. `Carrier::shutdown().await` observes the same terminal
slot and joins the finalizer so deterministic callers receive teardown errors.

- [ ] **Step 5: Run lifecycle tests under repetition**

```bash
for run in 1 2 3 4 5; do
  cargo test -p carrick-embed carrier::tests::shutdown --lib || exit 1
done
for run in 1 2 3 4 5; do
  cargo test -p carrick-runtime carrier::tests::shutdown --lib || exit 1
done
```

Expected: every iteration PASS.

- [ ] **Step 6: Commit worker and shutdown lifecycle**

```bash
git add crates/carrick-embed/src/carrier.rs \
  crates/carrick-embed/src/builder.rs \
  crates/carrick-embed/src/prepared.rs \
  crates/carrick-runtime/src/carrier.rs \
  crates/carrick-runtime/src/vcpu_loop/mod.rs \
  crates/carrick-runtime/src/vcpu_loop/continuation.rs \
  crates/carrick-runtime/src/kernel/objects.rs \
  crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/vfs/mod.rs
git commit -m "embed: shut down carrier workers deterministically"
```

---

### Task 8: Migrate the In-Process Two-Container Conformance Gate

**Files:**

- Modify: `crates/carrick-embed/tests/guest_smoke.rs`
- Modify: `crates/carrick-embed/tests/common/mod.rs`
- Modify: `crates/carrick-conformance-next/tests/dedicated_container_topologies.rs`
- Modify: `crates/carrick-cli/tests/conformance.rs:1825-1945`
- Modify: `crates/carrick-cli/src/debug.rs:900-1035`
- Modify: `scripts/test-signed.sh`

**Interfaces:**

- Consumes: signed `container_gate` probe, public `Carrier`, the shared
  `Arc<Kernel>` carrier graph, per-container VFS,
  prerequisite interceptor API, test-support carrier telemetry, and existing
  CLI gate assertions.
- Produces: authoritative in-process embed proof and retained CLI compatibility
  smoke.

- [ ] **Step 0: Require a debt-free concurrency census**

```bash
python3 scripts/migrate/check-runtime-global-state.py \
  --check --require-concurrent-embed-clean
```

Expected: PASS. Do not start the guest gate while any reachable
`container_debt` row remains.

- [ ] **Step 1: Add the red signed embed topology test**

Teach the `carrick-embed` branch of `scripts/test-signed.sh` to build the signed
integration tests with `--features test-support`; do not enable that feature
for ordinary library consumers or other packages.

Acquire `common::guest_lock()` once around the entire two-container test. Create
one explicit carrier and two builders with:

- different hostname and VFS marker content;
- independent audit/interceptor objects;
- alpha `getuid` replacement and beta's normal `getuid`;
- alpha selected `write` fd rewrite and beta's ordinary streams;
- different exit codes; and
- a shared host rendezvous directory used only to prove overlap.

Start both as polled Tokio tasks, wait until both guests have published their
rendezvous markers, take the live carrier snapshot, then publish host release
tokens and collect the two join handles with `tokio::join!`. Assert
`getpid == 1`, distinct `/proc`, markers, hostnames, stdio, events, uid
behavior, and exit status. The fixture must not exit before its release token,
so the live snapshot is taken while both containers are registered.

Run:

```bash
just test-embed explicit_carrier_runs_two_isolated_containers --nocapture
```

Expected: FAIL until the full carrier path is wired.

- [ ] **Step 2: Add sibling-survival cases**

Run two additional subcases under fresh carrier generations:

- alpha's interceptor panics while beta completes successfully; and
- alpha exits/fails early while beta remains live through its rendezvous.

Assert the alpha typed error/result, beta success, carrier remains open until
explicit shutdown, and no cross-container callback/event leakage.

- [ ] **Step 3: Assert one VM and strict cleanup from test-only telemetry**

At the held live rendezvous assert `vm_create_success_events == 1`,
`vm_lifecycle_violations == 0`, `kernel_graphs == 1`,
`runtime_directories == 1`, two registered containers, and two sorted
`container_inits` with distinct internal task ids and namespace PID 1. Also
assert zero builder/prepared leases, two live worker leases/records, two
container job groups, and an idle/open tracked finalizer at that barrier.
After releasing and joining both runs—but before shutdown—assert registered
containers, task roots, PID regions, mounts, job groups, continuations, and
builder/prepared/worker leases and workers are already zero while the one
kernel/runtime directory, VM, and tracked finalizer remain owned by the open
carrier.

Keep one read-only clone for final observation, consume another clone with
`shutdown().await`, and assert the closed test snapshot also reports zero frame
and vCPU leases and no VM lifecycle violation. Drop the observation clone
before creating the next carrier generation. Bind the test receipt to source
HEAD and the exact signed test-binary identity emitted by
`scripts/test-signed.sh`, not `target/release/carrick`.

- [ ] **Step 4: Mark only the container topology audit migrated**

Change `conformance_container_gate` from `Blocked` to `Migrated` in
`dedicated_container_topologies.rs` and update its count assertions. Leave the
host-gateway and shared-network-namespace entries blocked; this plan does not
add those APIs.

- [ ] **Step 5: Retain CLI proof as a compatibility smoke**

Keep `conformance_container_gate` and `carrick debug container-gate` but make
the in-process embed test authoritative for the public API. The CLI receipt
must still assert one VM and zero live containers; do not delete it until all
workflow/document links have migrated.

- [ ] **Step 6: Run signed topology gates**

```bash
just test-embed explicit_carrier_ --nocapture
just gate-containers
cargo test -p carrick-conformance-next --test dedicated_container_topologies
```

Expected: PASS with no skip.

- [ ] **Step 7: Commit the topology proof**

```bash
git add crates/carrick-embed/tests/guest_smoke.rs \
  crates/carrick-embed/tests/common/mod.rs \
  crates/carrick-conformance-next/tests/dedicated_container_topologies.rs \
  crates/carrick-cli/tests/conformance.rs \
  crates/carrick-cli/src/debug.rs \
  scripts/test-signed.sh
git commit -m "test: prove concurrent embedded containers in one carrier"
```

---

### Task 9: Add the Compiled Advanced Embed Example and Rewrite Public Docs

**Files:**

- Create: `crates/carrick-embed/examples/advanced_embed.rs`
- Modify: `crates/carrick-embed/Cargo.toml`
- Modify: `README.md`
- Modify: `crates/carrick-embed/README.md`
- Modify: `crates/carrick-embed/src/lib.rs:1-38`
- Modify: `docs/architecture-overview.md`

**Interfaces:**

- Consumes: public `Carrier`, `FilterVfs`, `InMemoryFileVfs`, interceptor API,
  `tokio::join!`, and existing seven-line `ContainerBuilder::from_image` demo.
- Produces: compiled two-container example and accurate support/boundary tables.

- [ ] **Step 1: Add the example target before its source exists**

Append:

```toml
[[example]]
name = "advanced_embed"
path = "examples/advanced_embed.rs"
```

Run:

```bash
cargo check -p carrick-embed --example advanced_embed
```

Expected: FAIL because the file is absent.

- [ ] **Step 2: Implement the complete advanced example**

The example must:

- create one `Carrier`;
- create two different `InMemoryFileVfs` values wrapped in read-only
  `FilterVfs` mounts;
- install alpha-only `getuid` replacement;
- install alpha-only selected `write` fd rewrite;
- call `carrier.container(image.clone())` and `carrier.container(image)`;
- run both with `tokio::join!`;
- check both independent results; and
- call `carrier.shutdown().await`.

Keep the root README's seven-line standalone example unchanged. Mirror or
include the compiled advanced source so docs cannot drift from the build.

- [ ] **Step 3: Add the approved root README interface table**

Use the nine rows from the spec: stdio, observers, interceptors, VFS, time,
faults/budgets, network, shared buffers, and carrier concurrency. State each
current boundary, including one carrier/VM per host process and no arbitrary
guest-memory mutation.

- [ ] **Step 4: Correct embed README and crate rustdoc**

Document:

- explicit versus implicit carrier behavior;
- async and blocking concurrency rules;
- observer/interceptor order and policy veto;
- panic and lifecycle error variants;
- per-container isolation and deliberate shared `Arc` objects; and
- deterministic shutdown requirements.

Remove the stale rustdoc claim that networking, VFS, observers, and time are
future work.

- [ ] **Step 5: Align the architecture overview**

Describe many container graph objects in one carrier VM, identify which state
is per-container versus carrier-wide, and link the signed in-process proof.
Retain the experimental/not-hardened warning.

- [ ] **Step 6: Compile examples and docs**

```bash
cargo check -p carrick-embed --examples
RUSTDOCFLAGS="-D warnings" cargo doc -p carrick-embed --no-deps
```

Expected: PASS.

- [ ] **Step 7: Commit the public demonstration**

```bash
git add crates/carrick-embed/Cargo.toml \
  crates/carrick-embed/examples/advanced_embed.rs \
  README.md \
  crates/carrick-embed/README.md \
  crates/carrick-embed/src/lib.rs \
  docs/architecture-overview.md
git commit -m "docs: demonstrate concurrent Carrick embedding"
```

---

### Task 10: Add an ABBA Driver for the Implicit Embed Path

**Files:**

- Create: `scripts/perf/embed_implicit_driver/Cargo.toml.in`
- Create: `scripts/perf/embed_implicit_driver/src/main.rs`
- Create: `scripts/perf/embed_go_build_abba.py`
- Create: `scripts/tests/test_embed_go_build_abba.py`

**Interfaces:**

- Consumes: `ContainerBuilder::from_image`, the existing cold Go build guest
  script, ABBA environment controls, artifact signing, and paired statistics.
- Produces: source- and harness-bound performance receipts for the real
  source-compatible implicit carrier path.

- [ ] **Step 1: Write red harness tests**

Test that each prepared arm:

- materializes the same hashed driver source from the harness repository;
- writes a temporary manifest whose `carrick-embed` path names the selected
  source repository;
- builds and signs the driver executable, not `target/release/carrick`;
- records source commit, harness commit/driver hash, SHA-256, CDHash, LC_UUID,
  entitlement, and DOF presence; and
- emits an execution argv that never contains the CLI `run` subcommand;
- accepts a neutral synthetic eight-quad result under the no-regression
  predicate; and
- rejects a synthetic statistically supported CPU regression while leaving a
  noisy/unresolved ratio above 1.0 non-terminal rather than misclassifying it.

Run:

```bash
python3 -m unittest scripts.tests.test_embed_go_build_abba
```

Expected: FAIL because the driver and harness do not exist.

- [ ] **Step 2: Implement the standalone driver**

The driver accepts image, run id, working directory, and guest command
arguments. It runs exactly one workload through
`ContainerBuilder::from_image(image).run_blocking()` with no observer,
interceptor, custom VFS, or explicit carrier; verifies the container result,
and forwards captured stdout/stderr so the existing `WORKLOAD_NS` and
`BUILD_OK` parser remains authoritative.

Keep the driver outside the workspace. `prepare-arm --source-repo X` copies the
same driver source into a private arm build directory and materializes only the
absolute `carrick-embed` path to X. This lets the candidate harness compile the
unchanged public driver against `CARRIER_BASE`, where the new harness files do
not exist, without copying runtime sources across worktrees.

- [ ] **Step 3: Implement immutable ABBA preparation and execution**

Reuse the repository's performance-control validation, image identity,
thermal preflight, A/B/B/A ordering, workload parser, and paired statistics.
Add a distinct receipt/campaign schema that also authenticates the harness
commit and driver-source hash. Set the host `CARRICK_RUN_ID` and the same guest
environment value per sample, and prove scoped cleanup after every sample.

Do not reuse the existing improvement decision. Add a named
`_no_regression_decision` with this exact threshold-1.0 contract:

- evidence is eligible only when the campaign is complete, has at least eight
  quads, passes every performance-control preflight, and authenticates both
  artifacts/source trees;
- the primary total-CPU metric is a supported regression only when its median
  quad ratio is greater than 1.0, its bootstrap one-sided lower bound is
  greater than 1.0, and the exact one-sided sign-test probability for ratios
  above 1.0 is below 0.05;
- a secondary metric is a supported regression only when its median ratio is
  greater than 1.0 and its bootstrap two-sided lower bound is greater than
  1.0; and
- the decision is tri-state: `pass` only when evidence is eligible and every
  primary/secondary median ratio is at most 1.0; `fail` when any supported
  regression predicate above is true; otherwise `unresolved`.

Record every boolean and numeric input in the decision object. A median above
1.0 without the corresponding statistical support is `unresolved`, with both
`no_regression_pass` and `supported_regression_fail` false; it is not a pass
and not a supported-regression failure. Unit-test exact 1.0, neutral medians at
or below 1.0, noisy/unresolved medians above 1.0, supported primary regression,
supported secondary regression, insufficient quads, and failed
artifact/preflight eligibility.

Do not alter `native_go_build_abba.py`'s CLI-binary evidence schema. The new
harness is a separate evidence class because its executable contract is
different.

- [ ] **Step 4: Run harness tests and one non-evidence smoke**

```bash
python3 -m unittest scripts.tests.test_embed_go_build_abba
python3 scripts/perf/embed_go_build_abba.py --help
```

Expected: PASS. The help/synthetic tests are not performance evidence.

- [ ] **Step 5: Commit the embed performance harness**

```bash
git add scripts/perf/embed_implicit_driver/Cargo.toml.in \
  scripts/perf/embed_implicit_driver/src/main.rs \
  scripts/perf/embed_go_build_abba.py \
  scripts/tests/test_embed_go_build_abba.py
git commit -m "perf: measure the implicit embed carrier path"
```

---

### Task 11: Run Full Correctness, Cleanup, and Performance Closure

**Files:**

- Modify only if a gate finds a defect: files already named in Tasks 1-10.
- Create: `docs/test-results/2026-08-30-carrier-concurrency.md`

**Interfaces:**

- Consumes: both completed implementation plans.
- Produces: exact source/artifact-bound closure evidence and explicit remaining
  blockers if any gate is not green.

- [ ] **Step 1: Run focused host and static gates**

```bash
just fmt-check
cargo test -p carrick-runtime carrier --lib
cargo test -p carrick-runtime kernel::netns --lib
cargo test -p carrick-thread container_registry --lib
cargo test -p carrick-embed --lib
cargo check -p carrick-embed --examples
python3 scripts/migrate/check-runtime-global-state.py --check
python3 scripts/migrate/check-runtime-global-state.py --check --require-concurrent-embed-clean
python3 -m unittest scripts.tests.test_embed_go_build_abba
RUST_TEST_THREADS=1 just ci
```

Expected: PASS.

- [ ] **Step 2: Build, sign, and record the CLI artifact identity**

```bash
just build
shasum -a 256 target/release/carrick
codesign -dvvv --entitlements - target/release/carrick
otool -l target/release/carrick | rg "LC_UUID|uuid|__dof_carrick"
git rev-parse HEAD
```

Record source HEAD, SHA-256, CDHash, LC_UUID, hypervisor entitlement, and DOF
section before any CLI guest claim. Label this as the CLI artifact; it is not
the signed embed test executable.

- [ ] **Step 3: Run signed embed and existing carrier gates**

```bash
RUST_TEST_THREADS=1 just test-embed
just gate-containers
```

Expected: PASS with one VM create and complete cleanup receipts per separately
identified executable. Validate `scripts/test-signed.sh`'s JSONL and bind the
authoritative topology result to the exact signed `guest_smoke` test executable
that ran it: source HEAD, SHA-256, CDHash, LC_UUID, entitlement, DOF presence,
filter, run id, and zero-process cleanup. Record the CLI gate against its own
release-binary identity; do not call the two binaries one link identity.

- [ ] **Step 4: Run cached and strict conformance serially**

```bash
CARRICK_PROBE_WORKERS=1 just conformance-probes
CARRICK_PROBE_WORKERS=1 just conformance-probes-closure
just conformance-closure-scope
```

Expected: PASS; strict closure has no skips, filters, alternate backend, missing
artifact, or unavailable oracle. Carrick and Docker phases remain serialized.

- [ ] **Step 5: Run the still-shipped default/CLI smoke**

Run:

```bash
just run run ubuntu:24.04 /bin/echo hello
just conformance-quick
```

Use the exact signed CLI artifact from Step 2. Record command, status,
stdout/stderr, and scoped cleanup. A prior build or a different worktree does
not satisfy this step.

- [ ] **Step 6: Measure no-extension single-container performance**

Record the commit after the prerequisite interception plan as `CARRIER_BASE`,
ensure both source trees are clean, and first run the implicit-embed ABBA
campaign from Task 10 with a single container, no extensions, and identical
default overlays. Materialize both control and candidate as clean detached
worktrees and use the candidate worktree as the harness authority; the caller's
possibly dirty checkout is not evidence input:

```bash
test -n "$CARRIER_BASE"
git check-ignore -q .worktrees
CARRIER_CANDIDATE="$(git rev-parse HEAD)"
git worktree add --detach .worktrees/carrier-control "$CARRIER_BASE"
git worktree add --detach .worktrees/carrier-candidate "$CARRIER_CANDIDATE"
test -z "$(git -C .worktrees/carrier-control status --porcelain)"
test -z "$(git -C .worktrees/carrier-candidate status --porcelain)"
python3 .worktrees/carrier-candidate/scripts/perf/embed_go_build_abba.py prepare-arm \
  --harness-repo .worktrees/carrier-candidate \
  --source-repo .worktrees/carrier-control \
  --destination target/perf/carrier-embed-abba/control \
  --label carrier-embed-control --role control \
  --image localhost:5005/carrick-go-conformance:1.24
python3 .worktrees/carrier-candidate/scripts/perf/embed_go_build_abba.py prepare-arm \
  --harness-repo .worktrees/carrier-candidate \
  --source-repo .worktrees/carrier-candidate \
  --destination target/perf/carrier-embed-abba/candidate \
  --label carrier-embed-candidate --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
python3 .worktrees/carrier-candidate/scripts/perf/embed_go_build_abba.py run \
  --harness-repo .worktrees/carrier-candidate \
  --control-receipt target/perf/carrier-embed-abba/control/arm.json \
  --candidate-receipt target/perf/carrier-embed-abba/candidate/arm.json \
  --control-overlay .worktrees/carrier-candidate/scripts/perf/overlays/native-default.json \
  --candidate-overlay .worktrees/carrier-candidate/scripts/perf/overlays/native-default.json \
  --quads 8 \
  --output target/perf/carrier-embed-abba/campaign.json
```

Then run the existing CLI-binary ABBA as a separate shipped-default gate:

```bash
python3 .worktrees/carrier-candidate/scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo .worktrees/carrier-control \
  --destination target/perf/carrier-cli-abba/control \
  --label carrier-cli-control --role control \
  --image localhost:5005/carrick-go-conformance:1.24
python3 .worktrees/carrier-candidate/scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo .worktrees/carrier-candidate \
  --destination target/perf/carrier-cli-abba/candidate \
  --label carrier-cli-candidate --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
python3 .worktrees/carrier-candidate/scripts/perf/native_go_build_abba.py run \
  --harness-repo .worktrees/carrier-candidate \
  --control-receipt target/perf/carrier-cli-abba/control/arm.json \
  --candidate-receipt target/perf/carrier-cli-abba/candidate/arm.json \
  --control-overlay .worktrees/carrier-candidate/scripts/perf/overlays/native-default.json \
  --candidate-overlay .worktrees/carrier-candidate/scripts/perf/overlays/native-default.json \
  --quads 8 \
  --output target/perf/carrier-cli-abba/campaign.json
git worktree remove .worktrees/carrier-control
git worktree remove .worktrees/carrier-candidate
```

Apply Task 10's exact no-regression decision to the implicit-embed evidence.
For the CLI evidence, compute and record the same threshold-1.0 eligibility,
primary, and secondary predicates as a closure-side decision without changing
the existing harness schema. Reject a supported regression in either evidence
class; an unresolved result requires more quads or a documented non-completion,
not an unsupported pass. Then run a separate report-only two-container
throughput measurement; never use aggregate concurrency to hide a
single-container regression.

- [ ] **Step 7: Prove scoped cleanup**

After every guest lane, use the run-id-scoped cleanup script and carrier receipt
to prove zero matching host processes, live containers, PID regions, tasks,
mounts, frame leases, vCPU leases, continuations, and workers. Do not use a
global process kill as evidence.

- [ ] **Step 8: Write the closure receipt**

Record exact commands, timestamps, artifact identity, pass/fail counts,
performance decision, cleanup counts, and any deferred gate. If any required
gate is not green, state that the feature is not complete and do not call the
README claim proven.

- [ ] **Step 9: Commit the receipt**

```bash
git add docs/test-results/2026-08-30-carrier-concurrency.md
git commit -m "test: record carrier concurrency closure"
```
