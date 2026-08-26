# `carrick-embed` Program Design

**Date:** 2026-08-25

**Status:** Approved by the owner in the 2026-08-25 research session; supersedes
the 2026-08-23 static review documents as the governing design for embedding.

**Source proposal (the reference for purpose and spirit):**
[`../plans/2026-08-23-carrick-embed-source-implementation-plan.md`](../plans/2026-08-23-carrick-embed-source-implementation-plan.md)

**Platform reference:** macOS / Apple Silicon / HVF / HVPatch, Linux arm64
guests. Cross-platform lanes keep compile/feature closure; runtime claims are
macOS/HVF unless a lane was exercised.

## Goal

Give Carrick a Rust library surface — `carrick-embed` — that runs a
containerized Linux workload from a host application with a Docker-like happy
path, and exposes the capabilities that follow directly from Carrick *being*
the kernel: VFS injection, syscall observation, time control, fault injection,
zero-copy shared memory, in-process network mocking, resource budgets, and a
self-hosted conformance framework that uses all of the above.

Every component of the source proposal is retained. This document records what
the 2026-08-25 survey of the tree found, the decisions the owner took on the
resulting questions, and the phase structure those decisions imply.

## What the tree says (verified 2026-08-25)

Fourteen read-only survey agents mapped each seam of the source plan against
the tree at `3dc6cc72`; the load-bearing claims below were re-checked by hand.

- **Fork retirement (the plan's Phase 0) already landed**, one day after the
  plan was written: NsSupervisor collapsed into the carrier (`76495a04`),
  the interactive supervisor is a thread `PtyRelay` (`af6270ce`), the
  FileAuthority helper is deleted (`36d141d6`), and
  `scripts/migrate/check-carrier-only-process-invariant.py` enforces it inside
  `just ci`. No `libc::fork` survives in runtime production code. What
  remains is a `debug_assert!(tokio::runtime::Handle::try_current().is_err())`
  at `crates/carrick-runtime/src/execute.rs:196` whose comment cites a fork
  that no longer exists, plus fork-era prose in ~8 files.
- **The runtime is one-container-per-host-process by construction.** One HVF
  VM per process (`hv_vm_create` returns `HV_BUSY` on a second);
  `KernelArena::init_global` is a `OnceLock` (`carrick-kernel/src/arena.rs:198`);
  `namespace::pid::REGION`/`REQUESTED` are never reset; container identity is
  read from process env (`CARRICK_CONTAINER_ID`, `CARRICK_RUN_ID`,
  `ARENA_PATH_ENV`, `CARRICK_EXEC_OVERLAY`, `CARRICK_JOIN_REGION`,
  `CARRICK_LAUNCH_AUTHORIZATION`); `GUEST_REALTIME_OFFSET_NS`,
  `LAUNCH_GRANTED_CAPS`, host signal dispositions, the SIGWINCH pipe, the
  deadlock watchdog and `RLIMIT_NOFILE` are process statics. A second
  sequential run in one process inherits the first run's arena file and PID
  table.
- **Captured stdout is unreachable from any product path.** `resolve_run_spec`
  hardcodes `raw: true` (`crates/carrick-engine/src/lib.rs:449`); raw selects
  `stream_stdio`, which `libc::write`s guest fd 1/2 output to the carrier's
  own fds, so `RunResult.stdout/stderr` are always empty. The buffering mode
  (`stream_stdio=false`) exists in the dispatcher with no caller. `Piped` has
  no sink seam. tty mode `dup2`s a pty slave over the host's fds 0–2 and
  installs a process-global SIGWINCH handler.
- **A cargo test executable cannot boot a guest unsigned.** The hypervisor
  entitlement must be on the executable that calls `hv_vm_create`; nothing
  signs `target/debug/deps/*`. The only in-process VM test
  (`crates/carrick-runtime/tests/trap_hvf.rs`) self-skips on `HV_DENIED` and
  runs in no gate. Today's harness shells out to the signed `carrick` and
  re-signs it in-test (`ensure_signed`).
- **Observer visibility has three holes.** The EL1 identity shim serves
  exactly `getpid` (172) and `gettid` (178) with no exit
  (`crates/carrick-mem/src/memory.rs:291,297`; uid/gid reads *do* dispatch);
  the vDSO serves `clock_gettime`/`gettimeofday`/`clock_getres`/`getrandom`
  from `CNTVCT_EL0` under `CNTKCTL_EL1.EL0VCTEN=1`; blocking syscalls leave
  `dispatch_threaded` as continuations before a retval exists
  (`vcpu_loop/mod.rs:7360`); policy/seccomp denials on the threaded path emit
  no compat events. On the good side, `dispatch_threaded` already runs
  `container_policy_precheck → seccomp_precheck → handler`
  (`dispatch/mod.rs:5901-5908`) — the plan's pipeline order — and
  `KernelContext` already carries `TaskKey{id,serial}`, `ThreadKey`, creds
  and pgrp for a zero-copy `ProcessInfo`.
- **Time.** `GUEST_REALTIME_OFFSET_NS` (`39cad611`) is `TimeControl::Offset`
  for the wall clock minus plumbing, and is carrier-wide. `linux_clock_duration`
  is the single syscall-path pivot. Every sleep/timeout/timer is lowered to a
  host `Instant`, `EVFILT_TIMER`, `thread::sleep`, `Condvar::wait_for` or
  `poll` timeout at dispatch time. Three raw-host-clock bypasses exist (futex
  `FUTEX_CLOCK_REALTIME` `dispatch/mod.rs:6590`, `utimensat` `UTIME_NOW`
  `:8871`, mqueue `mqueue.rs:1090`) and `clock_settime` does not re-stamp
  `VVAR_OFF_REALTIME_OFF_NS`, so vDSO and syscall REALTIME disagree afterwards.
- **Memory.** `carrick_guest_mem::GuestMemory` already provides
  `read_bytes`/`write_bytes`/`read_kernel_struct<T>` over `GuestVa`. The
  MAP_SHARED-file lane (`DispatchOutcome::MapHostAlias{shared:true}` →
  `GlobalShared`) yields pages that are never fork-COW-armed and are
  futex-capable. Raw access to *private* guest pages from a foreign context
  needs a stage-1 walker bound to the target mm that does not exist.
- **Network.** `NetworkProvider` is a public decorator seam
  (`network/mod.rs:335`, `SyscallDispatcher::with_network`);
  `ConnectTarget::Denied(errno)` is `refuse` for free; `connect` sees IP:port,
  never hostnames; the only carrick-owned byte streams are the in-memory pipe
  and the unwired `dispatch/net/unix_pure.rs` (dead since `c4cb2487`).
- **Budgets.** Counters exist per Linux process (`CompatReporter`, `MemState`,
  task CPU ledgers) but not per container; `Registry::task_count()` is live;
  `PreparedFork::commit` is the single fork publication point;
  `RLIMIT_NPROC`/`AS`/`DATA` are stored but unenforced; nothing counts bytes
  written or bytes per mm.
- **Conformance.** The gate is a per-id *category* diff via five parsers, not
  raw text; 465 probe programs; proptest is already in use;
  `carrick debug dispatch-syscall` drives the dispatcher in-process without a
  VM. Docker-side bpftrace is a manual recipe with no capture code.
- **Dependency shape.** `carrick-engine` does not forward `syscall-shim`; an
  embed crate depending on the engine alone would run guests without the EL1
  shim. Both `lint-domains` scripts auto-scope any new crate.
- **Controller.** `handoff.md:62` (2026-08-25) directs the next sessions to the
  2,127-suite core-emulation roadmap.

## Decisions

| Question | Decision |
| --- | --- |
| First consumer | Carrick's own tests (dog-food first): observer + `TestContainer` lead. |
| Process model | De-globalize first. One kernel, many containers as namespace trees — Linux's own model. HVF's one VM per process stops mattering. |
| Sequencing | Embed is the active workstream; `handoff.md` is updated to say so. |
| Guest tests from cargo | New signing step for test executables; `HV_DENIED` is a failure, never a skip. |
| Time | Fund `Deterministic` now via a virtual-time scheduler. `Scaled` stays, as an integer rational. |
| Observer | One `SyscallObserver` trait in `carrick-runtime` as a third precheck; `ContainerPolicy` becomes the first built-in observer. |
| Return event | Fires at terminal retval publication (the guest-visible value). |
| Stdio | Output-mode field on the request + one `Box<dyn Write + Send>` sink in the dispatcher; tty excluded from v1. |
| Request shape | Engine grows a typed `RunRequest` with `Default`; CLI and embed both lower into it. |
| SharedBuffer | Host fd via VFS injection + guest `mmap(MAP_SHARED)`; raw private-page access deferred. |
| Network | v1 is a true in-memory stream endpoint designed against carrick-owned epoll. |
| Async | Delete the tokio assert; `run()` = `spawn_blocking(execute)`, `run_blocking()` direct; both in v1. |
| Conformance-next | All of 13a–13g in scope. |
| Independent defects | Land first as narrow red-first fix commits. |
| Models | Fable: design/plan/adversarial verify; Opus: implementation; Sonnet: mechanical edits + test scaffolds; Haiku: census/grep sweeps. |

Decided by the author, flagged for the owner: observer visibility of the EL1
shim and vDSO fast paths is opt-in per observer (installing an observer does
not by itself disable them); `Scaled` time uses an integer rational, never
`f64`.

## Architecture

```text
host application
  -> carrick_embed::ContainerBuilder
  -> carrick_engine::RunRequest  ->  Engine::resolve (async; tokio) -> RunSpec
  -> Runtime::prepare(&RunSpec, RuntimeExtensions) -> PreparedRun
  -> PreparedRun::execute() -> RunResult          (sync; spawn_blocking for async)
  -> HVPatch kernel: ONE carrier / ONE VM / ONE kernel graph
       `- Container objects on the kernel graph (namespace trees), each owning:
            pid-ns root, rootfs + mount tree, uts/net membership, ClockDomain,
            granted caps, observer chain, stdio sink, quotas, run identity

extensions installed at prepare time, sealed at execute:
  vfs mounts | observer chain | ClockDomain mode | FaultInjector | ResourceBudget
  | NetworkInterposer | SharedBuffer leases
```

Crate shape: `carrick-embed` depends on `carrick-engine` (image resolution,
merge) **and directly on `carrick-runtime`** (the `Vfs` trait,
`SyscallObserver`, `GuestMemory`, `NetworkProvider`, `RuntimeExtensions`), and
forwards `syscall-shim` and the platform features so embedded guests match the
shipped CLI. `carrick-conformance-next` depends on `carrick-embed`. Workspace
membership is automatic (`members = ["crates/*"]`); `crates/README.md` gains
both rows.

### Phase A — Fix-now commits

Narrow, red-first, independent of embed. Each is a plain defect or dead code
the survey found:

1. Route the futex `FUTEX_CLOCK_REALTIME`, `utimensat` `UTIME_NOW` and mqueue
   deadline reads through the guest realtime authority
   (`realtime_duration`).
2. `clock_settime` re-stamps `VVAR_OFF_REALTIME_OFF_NS` when it moves
   `GUEST_REALTIME_OFFSET_NS`.
3. `SeccompState::is_active` reads the existing `identity_fast_path_allowed`
   atomic (or a sibling atomic maintained at install time) instead of locking
   `programs` per syscall.
4. Enforce `RLIMIT_NPROC` at `PreparedFork::commit` (lowering to `EAGAIN`) and
   `RLIMIT_AS`/`RLIMIT_DATA` at mapping/brk commit (`ENOMEM`).
5. The DNS gateway's `maybe_queue_dns_response` publishes readiness
   (`notify_inmem_epoll`) and `epoll_ready_events` consults `synthetic_recv`.
6. Delete: the `carrick compat-report` scaffold, the no-op `--raw` flag, the
   unread `RunSpec.interactive` consumer path (field stays until Phase C
   replaces it), the tokio `debug_assert` and its comment, the vestigial
   `is_forked_child()` checks, the stale shim comments (`memory.rs:195`,
   `carrick-cli/Cargo.toml`), and the fork-era module prose (`runtime.rs`,
   `threaded_loop.rs`, `dispatch/mod.rs:87`, `lifecycle.rs`,
   `supervisor_perf.rs`, `lib.rs:731`, `pty_relay.rs`, `main.rs`,
   `commands.rs`).
7. Fix `crates/carrick-runtime/tests/interactive_tty.rs`'s binary path and the
   `justfile` `test` comment.

`unix_pure.rs` is deliberately left in place: Phase H generalizes it.

### Phase B — Container as a kernel-graph object

Introduce `Container` (name final at implementation; `kernel/container.rs`)
on the kernel graph. A `Container` owns, per instance:

- the PID namespace root and its region (replacing `namespace::pid::REGION`/
  `REQUESTED` statics with per-container allocation inside the per-carrier
  `KernelArena`, which stays a carrier singleton);
- the rootfs, `VfsMounts` table and fs backend;
- UTS hostname and network-namespace membership;
- a `ClockDomain` (Phase F supplies modes; Phase B introduces the object with
  `System` only and moves `GUEST_REALTIME_OFFSET_NS` into it);
- granted capabilities (replacing `LAUNCH_GRANTED_CAPS`);
- the observer chain, stdio sink and quotas (populated by later phases);
- run identity: a typed `LaunchContext` passed to `prepare`, replacing every
  env read of `CARRICK_CONTAINER_ID`, `CARRICK_RUN_ID`, `CARRICK_EXEC_OVERLAY`,
  `CARRICK_JOIN_REGION`, `CARRICK_LAUNCH_AUTHORIZATION` and `ARENA_PATH_ENV`
  inside the runtime (the CLI still reads its env and builds the context).

Carrier-lifetime infrastructure — host signal dispositions, the SIGWINCH
pipe, the deadlock watchdog, vCPU leases, `RLIMIT_NOFILE`, the HVF VM —
stays process-scoped and must never alias one container: every
`KernelContext` reaches its container through its task, never through a
static. Guest `fork`/`clone`/`unshare`/`setns` inherit or replace container
membership exactly as they do namespace membership today.

Sequential runs: `PreparedRun::execute` returning tears the container down
(tasks reaped, mounts dropped, region released) while the VM and arena
persist for the next container. Concurrent runs: two `PreparedRun`s execute
on two host threads in one carrier; their tasks interleave in the one kernel.

**Gate B:** two containers sequentially and two concurrently in one carrier,
each seeing `getpid() == 1`, its own rootfs and hostname, no cross-visible
`/proc/<pid>`, and independent exit statuses — proven by guest probes on a
signed artifact; CLI behavior identical on the same runtime seam;
`check-carrier-only-process-invariant.py` and the identity/scope audit both
green.

### Phase C — `RunRequest`, `prepare.rs`, `carrick-embed` v1

**Engine.** `CliRunRequest` becomes `RunRequest` with `Default`, a
`StdioMode { Captured, Inherit, Piped }` field (replacing the hardcoded
`raw`), and explicit inputs for what `resolve_run_spec` reads ambiently today
(host env import for bare `KEY`, the bridge namespace id, the named-user
notice becomes a typed warning in the result). Lifecycle-only CLI fields
(`rm`, `stop_signal`, `stop_timeout`, `volumes_from`) move to the CLI. The CLI
lowers clap flags into `RunRequest`; embed's builder lowers its surface into
the same struct. One merge path.

**Runtime.** `crates/carrick-runtime/src/prepare.rs`:

```rust
pub fn resolve_plan(spec: &RunSpec, launch: LaunchContext) -> Result<ExecutionPlan, RuntimeError>;
impl Runtime {
    pub fn prepare(spec: &RunSpec, launch: LaunchContext, ext: RuntimeExtensions)
        -> Result<PreparedRun, RuntimeError>;
    pub fn execute(spec: &RunSpec) -> Result<RunResult, RuntimeError> // = prepare(..default..)?.execute()
}
impl PreparedRun {
    pub fn execute(self) -> Result<RunResult, RuntimeError>;
}
```

`RuntimeExtensions` (private fields, builder-style setters) carries
`vfs_mounts: Vec<(GuestPath, Box<dyn Vfs>)>`, `observers`, `clock_mode`,
`fault_plan`, `budget`, `network_interposer`, `shared_buffers`, and
`stdio: StdioSink`. Preparation either returns a complete `PreparedRun` or
rolls back every mount, mapping and registry publication it made.
`SyscallDispatcher` stays private to the runtime; its existing setters
(`register_mount`, `set_fs_backend`, `set_stream_stdio`,
`apply_launch_privileges`, `with_network`) are called by `prepare`.
`write_all_stdio` writes through a `Box<dyn Write + Send>` sink; `Captured`
is a buffering sink into `RunResult`, `Inherit` wraps the carrier's fds,
`Piped` is the caller's writer.

**Embed crate.**

```rust
pub struct ContainerBuilder { /* private */ }
impl ContainerBuilder {
    pub fn from_image(image: impl Into<String>) -> Self;
    // platform, pull_policy, image_store, command, entrypoint, env, envs,
    // workdir, user, user_group, hostname, mount, mount_readonly, vfs_mount,
    // fs_backend, network_mode, publish, dns, extra_host, stdout, stderr,
    // observer, time, seccomp, cap_add, resource_budget, max_traps
    pub async fn prepare(self) -> Result<PreparedContainer, EmbedError>;
    pub async fn run(self) -> Result<ContainerResult, EmbedError>;      // spawn_blocking(execute)
    pub fn run_blocking(self) -> Result<ContainerResult, EmbedError>;   // own current-thread runtime for resolve
}
pub enum StdioConfig { Captured, Inherit, Piped(Box<dyn Write + Send>) }
pub struct ContainerResult { /* exit code, signal, stdout, stderr, trap-limit, terminal reason, compat summary */ }
pub struct PreparedContainer { /* inspect plan, inject, then execute() */ }
#[non_exhaustive] pub enum EmbedError { Image, Config, Prepare, Entitlement, Guest, TrapLimit, Runtime }
```

Assertion helpers (`assert_success`, `assert_stdout_contains`) live in
`carrick_embed::testing` beside `TestContainer` and `run_in_container`.

**Signed tests.** A `just test-embed` recipe runs
`cargo test -p carrick-embed --no-run --message-format=json`, codesigns each
produced test executable with `scripts/entitlements.plist` through
`scripts/build-signed.sh`'s post-link path, then runs them with
`RUST_TEST_THREADS=1`. `EmbedError::Entitlement` (from `HV_DENIED`) is a test
failure. The same recipe serves `carrick-conformance-next`.

**Gate C:** CLI/embed `RunSpec` parity tests (no HVF); one signed end-to-end
run comparing the library result to the CLI result for the same image and
command on the same artifact; `Captured`, `Inherit` and `Piped` each proven;
`just ci` green; no-extension ABBA shows no regression.

### Phase D — Observer pipeline

`carrick_runtime::observe::SyscallObserver` (re-exported by embed):

```rust
pub trait SyscallObserver: Send + Sync {
    fn on_syscall(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction { Allow }
    fn on_syscall_return(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>, o: &SyscallOutcome) {}
    fn on_process_create(&self, parent: &ProcessInfo<'_>, child: TaskKey) {}
    fn on_exec(&self, p: &ProcessInfo<'_>, exe: &[u8], argv: &[&[u8]]) -> SyscallAction { Allow }
    fn on_process_exit(&self, p: &ProcessInfo<'_>, status: ExitStatus) {}
    fn wants_fast_path_visibility(&self) -> FastPathVisibility { FastPathVisibility::Blind }
}
pub enum SyscallAction { Allow, Deny(LinuxErrno), Kill(Signal) }
```

`ProcessInfo<'a>` borrows `KernelContext`; `SyscallInfo<'a>` borrows
`SyscallRequest` plus the `carrick-abi` table entry (name is `&'static str`).
The dispatcher holds `observers: Option<Arc<ObserverChain>>`; `None` is one
predictable branch. `ContainerPolicy` is re-expressed as the first built-in
observer so the Docker profile is a preset and there is one host-side deny
path: `policy(observer) → seccomp → user observers → handler → return`.
The chain is cloned into every child in `fork_clone_in_process_with_mm_mode`.
`on_syscall_return` fires where the terminal retval is published
(`complete_returned`/`complete_errno` and the continuation resume paths),
which also repairs `CompatReporter`'s pre-wait reporting; `CompatReporter`
becomes a built-in observer on the same chain. Lifecycle events hook the
existing fork-commit (`quiesce.rs` after `prepared_fork.commit()`), exec
(`prepare_execve` before image load for the deny point; after `commit_exec`
for the event) and exit (`publish_exit_status`) points.

Fast paths: by default the EL1 shim and vDSO stay on and the run's compat
summary reports the blind spot (`getpid`/`gettid`; vDSO clocks). An observer
returning `FastPathVisibility::Required` makes `prepare` disable the shim word
and attach the vDSO in `clock-syscalls` mode for that container.

Provided: `AuditObserver` (bounded ring, drop counter, metadata by default,
opt-in payload capture), `PolicyObserver` (typed rules over canonical numbers
and scalar args; path rules belong to `FilterVfs`), `SandboxObserver`
(preset composition).

**Gate D:** multi-process event identity/order tests (two live guest
processes, threads, fork/exec, denied syscall, signal death); observer-off
same-artifact ABBA + DTrace attribution show no added cost; the blind-spot
field is populated and exact.

### Phase E — VFS injection

`vfs_mount(guest_path, Box<dyn Vfs>)` lands in `RuntimeExtensions` and is
installed by `prepare` through `register_mount`. `InMemoryFileVfs` gets a
writable in-memory `VfsHandle` variant plus a write-back path so write
capture is real. `LayeredVfs` (explicit fall-through policy per operation,
not "any ENOENT"), `FilterVfs` (path rewrite, content transform, access
control), `RecordingVfs` (bounded log, errno-transparent) are `Box<dyn Vfs>`
decorators in `carrick-embed`. Mount points are synthesized into the parent
directory's `readdir`. `/`-level layering over the image requires routing the
~50 direct `rootfs_vfs.rootfs/.overlay` accesses through the trait; that is
the second half of this phase, subtree mounts first.

**Gate E:** an injected mount is visible only at its target and obeys
Linux mount and fd-lifetime semantics in differential probes (longest-prefix,
`ENOENT` vs `EACCES`/`EROFS`, shadowing, readdir, symlinks, rename across
mounts, open-handle lifetime across fork and exec); write capture round-trips.

### Phase F — Clock domain and virtual-time scheduler

`ClockDomain` on the `Container`:

```rust
pub enum TimeControl {
    System,
    Offset(SignedDuration),
    Frozen(SystemTime),
    Scaled { base: SystemTime, num: u32, den: u32 },
    Deterministic { epoch: SystemTime },
}
```

Every time consumer routes through the domain: clock reads, `nanosleep`/
`clock_nanosleep`, POSIX and interval timers, timerfd, futex/poll/select/epoll
timeouts, socket timeouts, signal timers, file timestamps, CPU clocks,
`/proc/uptime`, SysV/mqueue stamps. `Deterministic` is a kernel-owned
scheduler service: every wait enrolls a due time on the virtual clock; the
clock advances to the earliest due time only when every task in the container
is blocked, so timers and sleeps fire in a fixed order and traces are
reproducible. The vDSO gains a vvar mode word (seqlock-published) so
controlled realtime stays fast; monotonic under `Deterministic`/`Scaled` is
served from the vvar-published virtual counter, with `CNTKCTL_EL1.EL0VCTEN`
cleared for that container as the fallback where the vDSO cannot answer.
Host safety deadlines — deadlock watchdog, trap limits, cleanup — stay on
real time. `Frozen` realtime-absolute waits follow the controlled clock
faithfully. Time-namespace semantics (`CLONE_NEWTIME` offsets monotonic and
boottime only) compose with the embedder's control; a guest `clock_settime`
under an embedder-controlled realtime returns `EPERM`.

**Gate F:** every Linux-visible timeout and timer goes through the domain
(inventory-checked); System mode keeps every existing time conformance row
exact; deterministic probes (two waiters racing one advance, absolute vs
relative deadlines, overrun counts, `EINTR`/restart, fork/exec inheritance)
are byte-stable across runs.

### Phase G — Fault injection and budgets

`FaultInjector` implements `SyscallObserver`. Rules keyed by syscall name are
compiled at build time through `carrick_abi::syscall` into a canonical-number
bitset; conditions (`Always`, `Probability{seed}`, `AfterCount`, `ForDuration`,
`When`, `And`, `Or`) are scoped by container/task/syscall; counts key on
`TaskKey`, never host pids. Actions: pre-handler `Errno` (safe for every
syscall — no handler side effect has occurred); Linux-correct `Short(n)` for
read/write/send/recv; `Delay` through the Phase F scheduler (a parkable
continuation, not a host sleep); `Kill` through the kernel-graph signal post
so a rule can target a child. Convenience: `oom_after`, `network_partition`,
`slow_disk`.

`ResourceBudget` is a quota set on the `Container`: processes checked at
`PreparedFork::commit`, syscalls at dispatch admission (the compat summary
records fast-path-served calls separately), CPU from the task ledgers
(guest time is wall-in-`hv_vcpu_run`, stated as such), memory as committed
VA maintained in `MemState` at mmap/brk/mremap/munmap, bytes written at the
write path. `ExceedAction::{Kill, Errno, Signal}`; `RunResult` gains a typed
`TerminalReason` (`BudgetExceeded{..}` beside `TrapLimit`); `counters()`
returns generation-stamped live snapshots. The carrier-static `RLIMIT_CPU`
poller is replaced by the same mechanism.

**Gate G:** each fault point red against a non-injected control with the
exact point, task, seed/count recorded; each budget has a two-process
differential probe (fork inheritance, shared budget, partial write,
teardown); disabled path zero-allocation/zero-lock by inspection and ABBA.

### Phase H — Network mocking

An in-memory stream `OpenDescription` (generalizing `unix_pure.rs` to
`AF_INET`/`AF_INET6`) whose readiness carrick owns, designed against the
carrick-owned epoll model (kqueue is a wake source only). `NetworkInterposer`
is a `NetworkProvider` decorator: `on_connect((ip|name, port)).intercept(mock)`
returns the in-memory endpoint; `.refuse(errno)` is `ConnectTarget::Denied`.
`MockService` produces bytes over the stream; `HttpMock` parses plaintext HTTP
above it. Hostname matching uses the bridge DNS gateway's `resolve_dns_name`
hook to allocate synthetic addresses and `/etc/hosts` seeding elsewhere.
`ConnectionRecord` is bounded and ordered with opt-in payload capture. Guest
listeners with a mock client, UDP, and TLS are follow-ons.

**Gate H:** guest probes compare fd flags, errno, readiness (poll/select/
epoll, edge-triggered), partial I/O, shutdown/half-close, `SIGPIPE`, dup/fork
and close against a real Linux server control.

### Phase I — SharedBuffer

`SharedBuffer::new(len)` allocates a host object that is a real fd; `prepare`
surfaces it at a VFS path (`/dev/carrick/shm/<name>`) via a host-fd-backed
`InMemoryFileVfs` entry; the guest `mmap(MAP_SHARED, fd)`s it through the
existing `GlobalShared` lane; the host holds its own mapping of the same
object. The lease carries run and container generation; drop after retirement
fails closed. Futex across host and guest works through
`SharedFutexLocation`. `carrick_guest_mem::GuestMemory` is re-exported for
in-dispatch observer reads over `GuestVa`. Raw read/write of private guest
pages from the host is deferred to the foreign-mm walker that
`process_vm_readv/writev` also needs.

### Phase J — `carrick-conformance-next`

- **13a** `TestContainer` + `AuditObserver` port of ~10 LTP/probe cases as
  `#[test]`s run by the signed recipe; must reproduce the existing gate's
  verdicts for those cases.
- **13c/13e** semantic probe observers and `SyscallFuzzer` over the in-process
  dispatcher (`carrick debug dispatch-syscall` path; proptest), no VM.
- **13b** a Docker bpftrace capture phase (`raw_syscalls:sys_enter/sys_exit`
  per tracked pid tree, privileged, tracefs, serialized after all carrick
  runs) plus a Rust alignment layer normalizing pids/fds/addresses/thread
  interleaving and accounting for vDSO-served calls absent from the Linux
  trace; `SyscallDivergence` reports point at the handler file.
- **13d/13f** deterministic tests on `TimeControl::Deterministic`; golden
  traces under `tests/golden/` as diagnostic fingerprints whose diffs are
  reviewed, never blessed as correctness.
- **13g** `CoverageReport` joins `docs/conformance-coverage.md`'s
  invariant→probe model and the `check-matrix` drift gate rather than
  replacing them.

The external Docker oracle remains the verdict authority throughout; the old
gate is retired only when the new one reproduces every historical
false-green rejection on the same revision.

## Data flow (one run)

1. Builder → `RunRequest` → `Engine::resolve` (async) → `RunSpec`.
2. `Runtime::prepare(spec, launch, ext)`: allocate the `Container` (pid
   region, rootfs, mounts incl. injected, clock domain, caps, observer chain,
   stdio sink, quotas, interposer, shared buffers); rollback on any failure.
3. `PreparedRun::execute`: boot init task in the container; vCPU loop
   dispatches `policy → seccomp → observers → handler`; returns publish
   through the terminal-retval hook; lifecycle events at fork/exec/exit.
4. Container teardown; `RunResult` (exit/signal/terminal reason, captured
   output, compat summary incl. blind spots) → `ContainerResult`.

## Error handling

`EmbedError` is `#[non_exhaustive]` and separates image resolution, invalid
configuration, preparation (rolled back), entitlement (`HV_DENIED`), guest
termination (exit/signal, typed terminal reason), trap limit, and runtime
infrastructure failure. Linux outcomes delivered to the guest (denials,
faults, quota errnos) are never `EmbedError`s. Observer callbacks never run
under a kernel subsystem lock, stage-1 transaction, or vCPU ownership
transition; a panicking observer is caught at the dispatch boundary and
converted to a run-terminating infrastructure error, never a guest-visible
outcome.

## Performance rules

- With no extensions installed, no heap allocation, lock, trait call, payload
  decode or formatting is added to the syscall path; the only additions are
  `Option` branches, measured by same-artifact ABBA and DTrace attribution.
- Every phase records a disabled-path receipt; an unresolved noisy result
  stays unresolved.
- A pathological ratio on any new path is treated as a correctness signal.

## Verification model

- Pure request/type tests: `just test`, no HVF.
- Guest-running embed and conformance-next tests: the signed recipe,
  serialized, fail-closed on entitlement, self-hosted only.
- Every semantic change: red-first against the pre-fix artifact, differential
  against Docker where Linux behavior is the contract, Carrick and Docker
  phases never overlapping.
- Every phase closes with a dated receipt under `docs/perf-results/`: source
  HEAD, binary SHA-256/CDHash/LC_UUID/entitlement/`__dof_carrick`, gate
  commands with exit status, cleanup receipt, ABBA result.

## Non-goals

- Reviving host-process-per-guest-process execution.
- tty/interactive embedding in v1.
- Raw host read/write of private guest pages in v1.
- TLS/HTTPS mocking in v1.
- Claiming production readiness or a hardened untrusted-code boundary.
- Retiring `carrick-conformance` before parity is proven.

## Execution model

Phases A–C form the first task-level plan
(`../plans/2026-08-25-carrick-embed-phase-a-c-plan.md`); each later phase gets
its own plan after its predecessor's gate closes. Work runs in an isolated
worktree under `.worktrees/`, one narrow conventional commit per deliverable,
with the model assignment recorded in the Decisions table.
