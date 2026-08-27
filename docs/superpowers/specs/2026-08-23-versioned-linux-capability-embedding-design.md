# Versioned Linux Capability Graph for Carrick Embedding

> **Superseded by [`../specs/2026-08-25-carrick-embed-program-design.md`](../specs/2026-08-25-carrick-embed-program-design.md) (owner decision 2026-08-25).**
> Kept as the static-review record. The capability-graph vocabulary is not the
> governing design; the phases and gates in the 2026-08-25 spec are.

**Date:** 2026-08-23

**Status:** Superseded 2026-08-25 by the `carrick-embed` program design (see banner)

**Platform reference:** macOS, Apple Silicon, HVF/HVPatch, Linux arm64

**Related program:**
[`../plans/2026-08-23-carrick-embed-reviewed-program.md`](../plans/2026-08-23-carrick-embed-reviewed-program.md)

**Source proposal:**
[`../plans/2026-08-23-carrick-embed-source-implementation-plan.md`](../plans/2026-08-23-carrick-embed-source-implementation-plan.md)

## Goal

Make Carrick's embedding interface and Linux feature growth one program rather
than two parallel efforts.

Carrick will expose a versioned capability graph in which every capability
connects four things:

1. a frozen Linux semantic contract;
2. Carrick kernel objects and typed enforcement hooks;
3. an embedder-facing configuration or provider interface; and
4. fail-closed conformance, containment, and performance evidence.

This permits Carrick to ship useful embedding capabilities incrementally while
continuously increasing the Linux surface it implements. It does not lower the
Linux-parity bar: a capability version is conformant only when every invariant
declared for that version executes and matches the independent Linux oracle.

The primary security boundary remains host containment. Intra-guest Linux
isolation remains a co-equal conformance obligation. An embedder may provide a
mechanism at a declared hook, but cannot replace Carrick's task identity,
namespace semantics, permission checks, lifecycle rules, or Linux error
ordering.

## Why this is needed

The current syscall table is necessary but cannot describe the complete Linux
feature surface. Namespaces, cgroups, seccomp, Linux Security Modules, procfs,
sysfs, cgroupfs, ioctls, netlink, fork/clone inheritance, exec transitions, and
wait/readiness behavior each span multiple syscalls and kernel objects.

Static review of the 2026-08-23 tree found:

- the AArch64 table describes 242 `BringUp`, two `Planned`, and 95 `Deferred`
  syscall rows, while the emulation map documents many routed handlers as
  intentionally partial;
- PID and user namespace models are real, and network namespace state has a
  substantial modeled view, but several other `CLONE_NEW*` flags are accepted
  only in degraded shapes or rejected on clone paths;
- cgroup exposure is currently synthetic (`/proc/self/cgroup`, namespace links,
  and a controller-list sysfs stub) rather than a task hierarchy with controller
  semantics;
- seccomp has a fail-closed cBPF evaluator and filter stack, but user
  notification, complete trap/trace/log delivery, and several filter flags are
  absent;
- the three Landlock syscall rows are declared and deferred; and
- AppArmor security options are rejected rather than modeled.

These are not five unrelated backlogs. They share task identity, credentials,
namespace ownership, fd-backed kernel objects, inheritance, exec transitions,
poll/epoll, VFS/socket object identity, audit, and resource accounting. The
capability graph makes those shared requirements explicit and gives the embed
API stable hooks as Carrick implements each layer.

No project code, build, test, guest, Docker container, benchmark, or
conformance lane was run while producing this design. Current-state claims
above are static source/document observations, not a refreshed runtime
checkpoint.

## Governing decisions

1. Use a versioned capability graph, not a monolithic policy callback and not
   unrelated feature plugins.
2. Keep Linux semantics in Carrick's kernel. Providers supply mechanisms only.
3. Keep namespace, cgroup, seccomp, LSM, rlimit, and capability enforcement as
   distinct Linux stages with operation-specific ordering.
4. Make `IsolationProfile` ergonomic configuration over the graph, not an
   alternate enforcement engine.
5. Resolve capabilities transactionally before execution and seal the result.
6. Make required, preferred, unavailable, partial, and verified states
   explicit. Never silently downgrade.
7. Keep the native Linux/Docker harness as the semantic oracle. Embed telemetry
   remains diagnostic evidence.
8. Make composed feature behavior a first-class proof surface.
9. Begin with focused runtime module boundaries; extract more crates only when
   real dependency edges and consumers justify them.
10. Perform capability lookup and negotiation at preparation time. The hot
    path consumes direct typed references or prepared bitsets.

## Alternatives rejected

### One generic isolation/policy engine

A single `allow(Operation)` callback would make a superficially simple API,
but it would blur syscall-entry seccomp, namespace visibility, DAC and
capabilities, LSM object hooks, cgroup admission, and host backing. Those layers
have different inheritance, error precedence, and lifecycle rules on Linux.
The callback would also tempt embedders to become the semantic authority.

### Independent feature/plugin crates first

Separate namespace, cgroup, seccomp, Landlock, and AppArmor plugins maximize
local modularity but fragment task inheritance, enforcement ordering, version
negotiation, and proof. Feature implementation may later move into focused
crates, but all features participate in one kernel-owned capability graph and
one proof model.

### Syscall-count capability reporting

A routed syscall count cannot express whether a namespace view, cgroup
controller, LSM hook, proc file, readiness transition, or cross-feature
invariant works. The denominator must be declared capability invariants, not an
undefined percentage of possible syscall argument combinations.

## Version model

Each capability has three independent version/status axes.

### Linux semantic target

The Linux semantic target identifies the exact contract implemented. Examples:

- `namespace.time` semantic version 1;
- `cgroup.v2.pids` semantic version 1;
- Landlock ABI versions 1 through the highest version Carrick explicitly
  models; and
- `seccomp.notify` semantic version 1.

A semantic version freezes its syscalls, flags, object behavior, inheritance,
virtual files, error ordering, and composition invariants. Adding a semantic
requirement that can make a previously conformant implementation fail requires
a new semantic version.

### Embed provider ABI

The provider ABI versions the Rust interface an embedder may implement. It is
separate from the Linux ABI. A provider ABI change can occur without changing
Linux semantics, and a Linux capability may advance while reusing the same
provider interface.

### Maturity and proof

Source declarations and measured proof remain distinct:

- **Declared:** the Linux contract and dependency graph are known.
- **Experimental:** an implementation exists, but its proof set is incomplete.
- **Partial:** a frozen subset is exact; absent behavior is explicit.
- **Conformant:** every invariant for the semantic version executed and matched
  Linux on the named lane/artifact.
- **Performance-qualified:** conformant and within the capability's declared
  cost/amplification budget.

The source table declares the maximum implementation maturity it intends to
offer. A separate proof index binds verified maturity to an exact source
revision, signed binary, platform/lane, images, assertions, and raw artifacts.
A development build without a matching proof index reports the implementation
but not verified conformance.

An embedder provider can satisfy a provider contract. It cannot promote the
Linux semantic capability's maturity.

## Capability declarations

The shared declaration vocabulary belongs with Linux ABI/proof metadata in
`carrick-abi`. Embed-provider marker types and provider ABI details belong in
`carrick-embed`. Runtime-owned resolved state belongs in `carrick-runtime`.

A capability descriptor contains at least:

```rust
pub struct LinuxCapabilityDescriptor {
    pub id: LinuxCapabilityId,
    pub semantic_version: LinuxSemanticVersion,
    pub declared_maturity: CapabilityMaturity,
    pub authority: Authority,
    pub dependencies: &'static [CapabilityRequirement],
    pub syscall_proofs: &'static [ProofId],
    pub object_proofs: &'static [ProofId],
    pub composition_proofs: &'static [ProofId],
    pub performance_proofs: &'static [ProofId],
    pub platform_scope: PlatformScope,
}
```

Capability declarations complement, rather than replace, syscall declarations.
The syscall table continues to own syscall number/name/handler/authority data.
Capability descriptors reference those syscall declarations plus non-syscall
surfaces. Mechanical validation rejects:

- an unknown dependency or proof ID;
- a dependency cycle;
- a conformant declaration with an incomplete proof inventory;
- a syscall or kernel operation whose authority conflicts with the owning
  capability;
- a public capability with no platform scope; or
- an embed provider marker whose provider ABI is not mapped to a known Linux
  capability.

The checked capability table, proof index, capability report, and generated
documentation must use stable ordering and deterministic serialization.

## Ownership model

Linux state remains kernel-owned. Do not create a parallel embed-policy state
tree.

Existing `Task`, `Thread`, `ThreadResources`, process, and kernel-graph objects
gain or expose typed references to capability state. The intended vocabulary
includes:

```rust
NamespaceRef<PidNamespace>
NamespaceRef<UserNamespace>
NamespaceRef<MountNamespace>
NamespaceRef<UtsNamespace>
NamespaceRef<IpcNamespace>
NamespaceRef<NetworkNamespace>
NamespaceRef<CgroupNamespace>
NamespaceRef<TimeNamespace>

CgroupMembership
SeccompFilterChain
LsmDomainStack
```

Every reference carries typed identity and generation. Kernel/run ownership is
explicit. No namespace, provider, cgroup hierarchy, policy stack, or scheduler
is a process-global singleton.

Inheritance follows Linux object semantics:

- immutable `Arc` state is shared where Linux shares state;
- explicit copy-on-write is used where fork begins with shared values that may
  diverge;
- clone/unshare flags create or replace the exact typed memberships they name;
- exec retains, resets, or transitions each object according to its declared
  capability contract; and
- retirement and stale handles are generation-checked and fail closed.

## Enforcement model

There is no universal policy callback. Enforcement is operation-specific.

The broad order is:

1. syscall-entry seccomp evaluates the guest ABI-native frame;
2. dispatch validates raw shape and lowers arguments into a typed kernel
   operation;
3. namespace, credential, and capability logic resolves the visible target;
4. operation-specific LSM hooks evaluate the exact object and action;
5. cgroup controllers and rlimits admit, reject, reserve, or charge the
   operation;
6. the kernel operation publishes state transactionally; and
7. a named host capability performs only its declared backing/substrate work.

This is not one fixed errno-precedence pipeline. Each Linux operation
declaration specifies which stages apply and their precedence. Red-first
probes pin cases where several checks could fail. The resulting error is a
typed Linux outcome, distinct from provider or infrastructure failure.

Audit and embed telemetry observe the final decision and transitions. They do
not authorize the operation.

Provider callbacks never run while Carrick holds a kernel subsystem lock,
stage-1/stage-2 transaction, task-publication reservation, cgroup hierarchy
mutation, or vCPU ownership transition. Long-running mediation uses an fd-like
or bounded queue object with explicit cancellation and readiness.

## Capability families

### Namespace family

The graph contains all eight Linux namespace families:

- PID;
- user;
- mount;
- UTS;
- IPC;
- network;
- cgroup; and
- time.

The namespace foundation provides typed namespace objects, ownership by a user
namespace, namespace fds, `/proc/<pid>/ns/*`, membership/inheritance, and exact
`clone`, `clone3`, `unshare`, and `setns` behavior. Each namespace then owns its
specialized state.

Time namespaces virtualize monotonic and boot-time views, not realtime. Their
contract includes child-membership semantics, `time_for_children`,
`timens_offsets`, capability checks, clock reads, sleeps, POSIX timers,
timerfd, and `/proc/uptime`. Embed deterministic/manual clocks are providers
over the time-namespace/clock-domain abstraction; they are not a second time
system.

Mount namespaces own a mount tree and propagation/visibility semantics rather
than a list of paths on `RunSpec`. VFS injection installs objects into that
tree before execution. Landlock and AppArmor path/object checks consume stable
VFS identities resolved through the task's mount namespace.

Cgroup namespaces virtualize the task's view of `/proc/<pid>/cgroup` and the
cgroup2 hierarchy root. They do not themselves move a task between cgroups.

### Cgroup v2 family

`cgroup.v2.core` owns:

- a hierarchical `CgroupNode` graph;
- task and threaded membership;
- controller enablement and subtree control;
- delegation and namespace-root visibility;
- cgroupfs file objects and pollable events;
- migration and lifecycle rules; and
- atomic admission/rollback for fork and task movement.

Controllers are separate capability versions over the core:

- `cgroup.v2.pids`;
- `cgroup.v2.memory`;
- `cgroup.v2.cpu`;
- `cgroup.v2.io`;
- `cgroup.v2.cpuset`;
- `cgroup.v2.freezer`; and
- later controllers justified by workloads and oracle coverage.

Embed resource budgets become high-level configuration over these controllers
where the Linux controller exists. Carrick-specific safety limits remain
separate host/runtime safeguards and must not be reported as Linux cgroup
state.

Controller implementations define exact scope, unit, hierarchical
aggregation, inheritance, over-limit outcome, events, and relationship to
rlimits. A controller with incomplete accounting is absent or partial, never a
plausible counter backed by an observer.

### Seccomp family

Carrick's existing cBPF evaluator and irreversible filter stack become
`seccomp.filter` rather than being replaced.

Versioned additions include:

- strict/filter installation flags and validation;
- complete most-restrictive action ordering;
- real `SIGSYS` trap payload behavior;
- ptrace trace handoff where ptrace capability permits it;
- audit/log behavior;
- TSYNC and thread-group synchronization;
- action discovery and notification-size queries; and
- user notification, listener fds, readiness, cancellation, response IDs, and
  fd injection.

The embed syscall supervisor reuses seccomp user-notification machinery. A
host policy that is not guest-installed remains an immutable outer containment
policy and is reported separately. Test fault injection uses named transaction
points and does not masquerade as seccomp.

### LSM family

`lsm.hooks` defines focused, operation-specific hook vocabulary for:

- VFS/file/inode operations;
- task and credential transitions;
- signals and ptrace;
- socket bind/connect/send/receive actions;
- executable/profile transitions;
- key/IPC operations as they become supported; and
- audit records.

It is not a single `allow` trait. Hook request types name the exact object,
operation, task security context, namespace view, and already-established
permission facts required by Linux ordering.

Landlock is delivered by Linux ABI version. Filesystem, TCP, device ioctl,
abstract UNIX/signal scope, logging, TSYNC, pathname UNIX, UDP, and later
rights enter only with their owning ABI version and proof inventory. Rulesets
are fd-backed kernel objects, stack monotonically, and restrict the enforcing
task and descendants according to the declared ABI.

AppArmor compatibility builds on the same LSM hook surface but retains
AppArmor-specific labels, profiles, path mediation, exec transitions,
`/proc/<pid>/attr/*`, stacking behavior, and audit vocabulary. It must not be
described as full AppArmor until the parser/policy and hook denominator is
explicit and exact. Early versions may provide only a frozen compatibility
subset.

## Embedder API

Carrick supplies sealed capability marker types. Embedders cannot invent a
Linux capability ID or declare it conformant.

The public shape is:

```rust
pub trait CapabilitySpec: private::Sealed {
    const ID: LinuxCapabilityId;
    const PROVIDER_ABI: ProviderAbiVersion;
    type Config: Send + Sync + 'static;
    type Provider: ?Sized + Send + Sync + 'static;
    type Handle;
}
```

An embedder composes an isolation profile:

```rust
let profile = IsolationProfile::builder()
    .require::<TimeNamespaceV1>(time_config)
    .require::<CgroupPidsV1>(PidsLimit::new(64)?)
    .prefer::<LandlockFilesystemV3>(landlock_rules)
    .provide::<SeccompNotifyV1>(Arc::new(supervisor))
    .build()?;

let prepared = ContainerBuilder::from_image(image)
    .isolation(profile)
    .prepare(&runtime)?;
```

`require` fails preparation if the requested semantic version, maturity/evidence
requirement, platform support, dependencies, or provider ABI cannot be
satisfied. `prefer` permits explicit absence. It never substitutes a weaker
version unless the request contains a compatible range and the prepared report
names the selected version.

An evidence requirement may ask for implementation availability or for a
verified proof index matching the exact artifact. This lets ordinary
development use experimental features while release/test harnesses demand
verified capability versions.

`IsolationProfile` only compiles configuration into capability requests and
providers. It does not run authorization logic.

## Preparation and capability report

Preparation is a rollback-capable transaction:

1. load built-in capability descriptors and exact-artifact proof metadata;
2. merge requested versions and provider ABIs;
3. calculate and validate dependency closure;
4. reject cycles, conflicts, unsupported platforms, invalid maturity requests,
   and ambiguous providers;
5. allocate namespace, cgroup, seccomp, LSM, VFS, clock, notification, and
   backing objects;
6. publish them atomically into a private `PreparedCapabilitySet`;
7. seal configuration; and
8. return the prepared container plus a report.

Failure rolls back every namespace object, cgroup reservation, fd, mount,
provider enrollment, mapping, and registry publication created by the
transaction.

The report records for every request:

- capability ID;
- requested and resolved Linux semantic versions;
- provider ABI and built-in/provider source;
- required or preferred status;
- declared maturity;
- verified maturity and proof-receipt identity, if any;
- platform/lane scope;
- dependency closure;
- conformance, containment, and performance proof IDs;
- downgrade or absence reason; and
- any enabled diagnostic/perturbing mode.

The runtime catalog can be inspected before preparation, but only the prepared
report is authoritative for one run.

## Conformance and feature-growth model

The capability registry becomes the top-level feature ledger. Each capability
version owns a frozen invariant set covering:

```text
Linux ABI/version target
  -> syscalls, flags, structures, and errno precedence
  -> kernel objects and enforcement hooks
  -> procfs/sysfs/cgroupfs/ioctl/netlink surfaces
  -> fork/clone/unshare/setns/exec/exit inheritance
  -> embed configuration and provider contracts
  -> composition invariants
  -> conformance, containment, and performance proofs
```

Promotion to conformant rejects every unexercised or invalid proof shape,
including matching `TCONF`, `TBROK`, skip, retry-recovered acceptance, empty
output, timeout, crash, missing row/binary/oracle, mutable image drift,
observer-only assertion, or stale proof receipt.

Feature growth follows one loop:

1. discover a gap through LTP, language workloads, a real embedder need, or a
   newer upstream Linux ABI;
2. add the capability/version/invariant declaration before implementation;
3. reduce Linux behavior to a deterministic red-first guest probe;
4. decide from evidence whether the gap exposes a missing shared abstraction
   or belongs locally to one feature;
5. implement kernel semantics and any provider mechanism;
6. run pure model tests, line-exact probes, originating LTP/workload cases,
   composition cases, authority-transition checks, performance gates, and
   appropriate target-host lanes;
7. publish an exact-artifact proof index; and
8. promote only the proven version and regenerate capability/conformance docs.

The independent native-arm64 Linux/Docker run remains the semantic oracle for
the canonical lane. Carrick telemetry and embed event streams help localize a
failure but cannot redefine the verdict.

## Composition proofs

Capabilities are not complete when only isolated unit cases pass. The proof
registry includes cross-capability invariants such as:

- PID namespace + cgroup `pids` + fork/clone admission and rollback;
- user namespace + capabilities + namespace/cgroup/LSM permission checks;
- time namespace + nanosleep/timerfd/POSIX timers + deterministic embed clock;
- mount namespace + injected VFS + Landlock hierarchy/object rules;
- network namespace + Landlock network rules + socket transport provider;
- seccomp notification + namespace-visible PID + signal cancellation +
  poll/epoll readiness;
- Landlock and AppArmor stacking across fork and exec;
- cgroup freezer + signals/waits + vCPU lease release;
- cgroup memory accounting + shared buffers + mmap/fork/exec/unmap; and
- AppArmor exec transition + mount namespace path view + Landlock restriction.

The matrix is expanded whenever a new dependency edge or enforcement ordering
is introduced.

## Delivery waves

Each wave produces a useful embedding capability and expands Linux parity.
Every wave receives its own approved task-level plan after predecessor evidence
exists.

### Wave 0: capability and namespace foundation

- Add capability declarations, dependency validation, provider ABI mapping,
  proof-index vocabulary, and deterministic reports.
- Introduce typed namespace references/fds and exact membership/inheritance
  operations.
- Wrap current PID/user/network namespace and seccomp behavior as honest
  partial capability versions without changing semantics.
- Add red tests that prevent partial/degraded state from being called
  conformant.

### Wave 1: time namespace and deterministic clocks

- Implement time namespace objects, ownership, `time_for_children`,
  `timens_offsets`, and affected clocks/timers/proc views.
- Make the embed manual/deterministic clock a provider over the same clock
  domain.
- Preserve real host safety/watchdog deadlines outside guest-controlled time.

### Wave 2: cgroup v2 core and `pids`

- Implement hierarchy, membership, cgroup namespace visibility, cgroupfs core
  files, delegation subset, migration, events, and `pids` admission.
- Express embed process budgets through the controller.
- Prove task publication and rollback under concurrent fork/exit.

### Wave 3: seccomp completion and notification

- Complete action behavior, flags, TSYNC, audit/trace/trap integration, and
  user-notification fd objects.
- Expose an embed syscall supervisor through the notification provider ABI.
- Keep immutable host containment policy and test fault injection separate.

### Wave 4: mount namespaces, VFS injection, and Landlock filesystem

- Implement namespace-owned mount trees and required mount API semantics.
- Stabilize VFS object identities and mount-relative visibility.
- Deliver Landlock filesystem ABI versions in order.
- Make injected VFS mounts participate in the same namespace and LSM checks.

### Wave 5: network namespace, Landlock network, and socket providers

- Close modeled network namespace membership/visibility/lifecycle gaps.
- Deliver Landlock network and scope versions supported by the selected ABI.
- Integrate socket transport mocking below protocol helpers.

### Wave 6: cgroup memory, CPU, I/O, cpuset, and freezer

- Add controllers only with exact accounting and hierarchical semantics.
- Reuse task CPU accounting and page/file/socket object accounting where they
  are already authoritative; close missing accounting before advertising a
  controller.
- Keep Carrick host-safety limits separate.

### Wave 7: AppArmor compatibility and remaining namespace edges

- Implement the approved AppArmor compatibility denominator over shared LSM
  hooks.
- Close remaining UTS/IPC/user/mount/cgroup namespace and procfs edges.
- Expand profiles, transitions, audit, and stacking through new capability
  versions rather than silently broadening an old one.

## Idiomatic Rust architecture

### Stable crate responsibilities

- `carrick-abi`: Linux constants/wire types, syscall declarations, Linux
  capability descriptors, semantic versions, authority, and proof IDs.
- `carrick-spec`: serializable requested container configuration only.
- `carrick-embed`: typed capability builders, sealed marker types, provider
  traits, prepared handles, and reports; no Linux semantics.
- `carrick-runtime`: capability resolution, kernel operations, and enforcement
  composition.
- `carrick-kernel`: reusable kernel objects once dependency extraction is
  supported by multiple real consumers.
- `carrick-host-*`: named host backing/substrate mechanisms only.
- `carrick-conformance`: independent proof results, proof-index production,
  and generated capability matrix.

Within `carrick-runtime`, first establish focused module boundaries:

```text
kernel/capabilities
kernel/namespaces
kernel/cgroup
kernel/security/seccomp
kernel/security/lsm
kernel/security/landlock
kernel/security/apparmor
```

Do not create a crate for every feature at the start. Extract a leaf only when
its dependencies are acyclic and more than one real consumer benefits.

### Rust design rules

- Newtypes and typed generations replace raw IDs, versions, addresses, and
  adjacent flag domains.
- `NamespaceRef<K>` uses marker types so namespace families cannot be
  transposed.
- Immutable `Arc` state plus explicit copy-on-write models Linux inheritance.
- RAII guards own reservations, cgroup charges, mapping changes, task
  publication, provider enrollment, and rollback.
- Typestates enforce `Requested -> Resolved -> Prepared -> Running -> Retired`.
- Traits exist only at true substitution points: host mechanisms and embed
  providers. Kernel objects remain concrete unless multiple implementations
  are required.
- Public capability marker traits are sealed. Public provider traits use
  associated configuration/request/response types.
- Security-sensitive configuration has fallible constructors and no permissive
  `Default`.
- Public errors are typed and `#[non_exhaustive]`; Linux guest outcomes remain
  separate from configuration, provider, and infrastructure failures.
- Runtime/kernel-owned registries replace process-global `OnceLock` state.
- Deterministic tables and reports use stable order and serialization.
- No panic, `unwrap`, or silent fallback appears on production capability
  resolution or enforcement paths.

## Failure behavior

Failures are separated into domains:

- **configuration error:** invalid capability request, semantic version,
  dependency, or unsafe combination;
- **resolution error:** required capability/version/maturity/platform/provider
  unavailable;
- **preparation error:** allocation or publication failed; transaction rolls
  back completely;
- **provider error:** provider disconnected, timed out, returned a malformed
  response, or violated its ABI;
- **Linux outcome:** the capability intentionally denies/fails a guest
  operation with the operation's exact errno, signal, or wait status; and
- **internal authority violation:** impossible generation/ownership mismatch;
  fail-stop after ownership transfer, recover/rollback before it.

Provider failure maps to a Linux outcome only when the provider capability
contract explicitly defines that mapping. Otherwise it is an infrastructure
failure and cannot become an allow decision.

Required capability failure occurs before the first guest instruction whenever
possible. A runtime provider loss uses the capability's named cancellation and
terminal semantics; it never leaves a guest task waiting on an orphaned
callback.

## Performance model

Capability growth cannot tax the disabled path.

- Registry lookup, version negotiation, dependency resolution, and provider
  selection happen only during preparation.
- Prepared task/kernel objects contain direct typed references or compact
  bitsets; they do not perform string or hash-map capability lookup per
  syscall.
- A disabled capability adds no heap allocation, lock, callback, payload
  decoding, or dynamic dispatch to the hot path.
- Enabled provider work is offloaded through bounded/fd-like mechanisms where
  it can block.
- LSM and cgroup hooks are invoked only for operations declaring those hooks.
- Every wave measures disabled-path ABBA, enabled cost, syscall/host-operation
  amplification, and DTrace attribution.
- An unresolved noisy result remains unresolved; a demonstrated regression is
  a blocker.

Correctness closes before performance qualification. A pathological completing
ratio is treated as a correctness/architecture signal, not a tuning backlog.
The program-wide within-2x Docker requirement remains in force for the final
product surface.

## Migration strategy

The migration is incremental and reversible until each new authority path is
proven.

1. Add declarations, registry validation, reports, and proof-index plumbing
   without changing guest behavior.
2. Describe current behavior honestly as partial capability versions.
3. Add typed operation/enforcement hooks behind compatibility adapters.
4. Implement one vertical slice at a time with red-first proof.
5. Compare old/new paths on the same exact signed artifact and canonical
   oracle.
6. Make the new path authoritative only after semantic, authority, lifecycle,
   and performance gates pass.
7. Delete the superseded parallel state/path in the same or immediately
   following narrow change.
8. Extract a core crate only after real consumers prove the module boundary.

No migration phase may preserve two mutable authorities indefinitely. Adapters
translate into one owner; they do not synchronize two competing state models.

## Non-goals

- A claim that Carrick supports every current or future Linux feature.
- A generic embed callback that can approve arbitrary kernel operations.
- Treating the host kernel's namespace/cgroup/LSM state as guest authority.
- Reporting synthetic files or counters as a complete cgroup implementation.
- Treating Landlock/AppArmor labels as containment without their operation
  hooks.
- Replacing the external Linux oracle with Carrick telemetry.
- Shipping every capability before the first useful embed release.
- Crate-per-feature restructuring for aesthetic purity.
- Reviving host-process-per-guest-process execution backends.
- Claiming production readiness or a hardened untrusted-code boundary.

## Completion criteria

This design is implemented as a program when:

1. every public embed capability resolves through the versioned graph and
   produces a prepared report;
2. every advertised Linux semantic version has a frozen invariant inventory;
3. verified maturity is bound to exact signed-artifact proof, not a source
   claim;
4. providers cannot override kernel-owned Linux semantics or undeclared host
   authority;
5. all eight namespace families have explicit versions and honest maturity;
6. the selected cgroup v2, seccomp, Landlock, and AppArmor compatibility
   versions pass their isolated and composition proofs;
7. the capability matrix rejects every missing, skipped, excused, invalid, or
   stale proof shape;
8. disabled capabilities add no demonstrated hot-path overhead;
9. the final selected product surface retains exact conformance and the
   program-wide performance bar on one unchanged artifact; and
10. no superseded parallel authority remains reachable.

Individual embed releases may expose a smaller verified capability set. Their
reports and documentation must state that exact set and must not imply the
program-wide completion above.

## Upstream Linux references

- [Linux time namespaces (`time_namespaces(7)`, Linux man-pages
  6.17)](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.17.pdf)
- [Linux cgroup v2](https://docs.kernel.org/next/admin-guide/cgroup-v2.html)
- [Linux seccomp filters and userspace
  notification](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
- [Linux Landlock system-wide management](https://docs.kernel.org/admin-guide/LSM/landlock.html)

These links define upstream behavior to investigate. Carrick's completing
semantic evidence remains the exact native Linux oracle run and owned
deterministic probes for each capability version.
