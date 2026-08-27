# `carrick-embed`: Library Embedding Interface for Containerized Linux Workloads

A new `carrick-embed` crate providing an ergonomic, type-safe Rust API for
embedding containerized Linux workloads into host-side applications — with a
Docker-like happy path for simple usage, deep VFS injection hooks, syscall
observation, and capabilities impossible from outside a traditional VM: time
control, fault injection, zero-copy memory sharing, network mocking, and
cgroup-free resource budgets. The embed API also becomes carrick's own
conformance testing framework, closing the dog-food loop.

## Background & Motivation

Today, the only way to launch a Carrick container is through the CLI path:
`carrick-cli` → `carrick-engine` → `carrick-runtime`. The engine's public API
(`CliRunRequest`) is a 30+-field struct with no `Default` or builder pattern,
tightly shaped for CLI flag forwarding. The runtime's `Runtime::execute(&RunSpec)`
is a monolithic function that assembles the dispatcher, rootfs, mounts, and trap
loop in one shot — there is no way to inject custom VFS mounts, observe
syscall behavior, or programmatically control the guest from a library caller.

Carrick's architecture — **it IS the kernel** — means every syscall, every
timer, every memory allocation, every network operation flows through Rust code
the embedder can touch. This enables capabilities that are impossible or
impractical from outside a traditional VM or container runtime:

| Capability | Why carrick can, VMs can't |
|---|---|
| Time control | Carrick dispatches `clock_gettime`/`nanosleep` — can freeze, travel, accelerate |
| Fault injection | Syscall dispatch path — inject errors with zero overhead, no ptrace perturbation |
| Zero-copy memory | HVPatch guest memory IS host memory — no virtio/vsock serialization |
| Network mocking | Socket syscalls flow through dispatch — mock services without running servers |
| Resource budgets | Syscall accounting is inherent in dispatch — no cgroups, no root, no `/proc` |
| Conformance oracle | Observer sees every syscall + return value — diff against Linux at the semantic level |

---

## Resolved Decisions

| Question | Decision |
|---|---|
| Crate placement | New `carrick-embed` beside `carrick-engine`, maximizing leverage |
| Output model | Both streaming and captured — embedder's choice |
| Multi-container | Single-container first, multi-container ready |
| Async vs sync | Both; async is natural post fork-retirement |
| Visibility relaxation | Phased `prepare.rs` facade in `carrick-runtime` |
| Fork retirement | **Prerequisite.** HVPatch only, no `libc::fork` in execute path |
| `run-elf` loop | **Excluded** from embed surface (bring-up tool only) |
| Observer hierarchy | Container-level installation, per-process dispatch |
| Self-hosted conformance | **Yes.** Embed API becomes the conformance testing framework |

---

## Prerequisites (Phase 0)

> [!IMPORTANT]
> **Fork retirement must land before `carrick-embed` ships.**
>
> 1. **NsSupervisor** → kernel-graph task
> 2. **Interactive supervisor** → thread-based pty relay
> 3. **`run-elf` loop** — excluded from embed surface
>
> Once these land, zero host forks in the HVPatch path. Tokio stays alive.

---

## Proposed Changes

### New crate: `carrick-embed`

```
carrick-embed → carrick-engine → { carrick-image, carrick-runtime } → carrick-spec
```

> [!IMPORTANT]
> **Leverage principle**: `carrick-embed` reuses existing codebase — constructs
> `CliRunRequest` internally, delegates to `Engine::resolve()`, feeds `RunSpec`
> into the phased runtime API. No merge logic duplicated. Where the runtime
> lacks a public seam, we add a narrow facade, not a parallel implementation.

---

### Component 1 — Builder API (Happy Path)

#### [NEW] [`crates/carrick-embed/src/builder.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/builder.rs)

```rust
let result = Container::from_image("ubuntu:24.04")
    .command(["echo", "hello world"])
    .run().await?;
assert_eq!(result.stdout_utf8().trim(), "hello world");
```

**Methods** (all `&mut Self`): `from_image`, `platform`, `pull_policy`,
`image_store`, `command`, `entrypoint`, `env`, `envs`, `workdir`, `user`,
`user_group`, `hostname`, `mount`, `mount_readonly`, `vfs_mount`, `fs_backend`,
`network_mode`, `publish`, `dns`, `extra_host`, `stdout`, `stderr`, `tty`,
`interactive`, `observer`, `time`, `seccomp`, `cap_add`, `resource_budget`,
`max_traps`

**Terminal**: `async fn run`, `fn run_blocking`,
`async fn prepare -> PreparedContainer`

```rust
pub enum StdioConfig { Captured, Inherit, Piped(Box<dyn AsyncWrite + Send + Unpin>) }
```

| Default | Value |
|---|---|
| stdout/stderr | `Captured` |
| observer | `None` |
| time | `System` (real) |
| seccomp | `ContainerDefault` |
| resource_budget | `None` (unlimited) |

---

### Component 2 — VFS Injection & Layering

#### [NEW] [`crates/carrick-embed/src/vfs_ext.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/vfs_ext.rs)

Re-exports `Vfs` trait. Provided implementations:
1. **`LayeredVfs`** — stack multiple Vfs, fall through on ENOENT
2. **`InMemoryFileVfs`** — in-memory files, optionally captures writes
3. **`FilterVfs`** — path rewriting, content transform, access control
4. **`RecordingVfs`** — log all operations for assertions

---

### Component 3 — Syscall Observer

#### [NEW] [`crates/carrick-embed/src/observer.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/observer.rs)

Container-level installation, per-process dispatch via `ProcessInfo` (zero-copy
view into `KernelContext`).

```rust
pub trait SyscallObserver: Send + Sync {
    fn on_syscall(&self, _: &ProcessInfo, _: &SyscallInfo) -> SyscallAction { Allow }
    fn on_syscall_return(&self, _: &ProcessInfo, _: &SyscallInfo, _: &SyscallOutcome) {}
    fn on_process_create(&self, _parent: &ProcessInfo, _child_pid: i32) {}
    fn on_exec(&self, _: &ProcessInfo, _exe: &str, _argv: &[String]) -> SyscallAction { Allow }
    fn on_process_exit(&self, _: &ProcessInfo, _exit_code: i32) {}
}
```

Pipeline: `container_policy → seccomp → observer.on_syscall → handler →
observer.on_syscall_return`

Provided: `AuditObserver`, `PolicyObserver`, `SandboxObserver`

#### [MODIFY] [`dispatch/mod.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mod.rs)

Add `observer: Option<Arc<dyn SyscallObserver>>` to `SyscallDispatcher`.

---

### Component 4 — Phased Runtime

#### [NEW] [`crates/carrick-runtime/src/prepare.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/prepare.rs)

```rust
pub fn resolve_plan(spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError>;
pub fn build_dispatcher(spec: &RunSpec, plan: &ExecutionPlan) -> Result<PreparedDispatcher, RuntimeError>;
pub fn execute_prepared(prepared: PreparedDispatcher, spec: &RunSpec, env: Vec<String>) -> Result<RunResult, RuntimeError>;
```

`PreparedDispatcher` exposes: `register_mount`, `set_fs_backend`,
`set_observer`, `set_time_control`, `guest_memory_handle`.

#### [MODIFY] [`execute.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/execute.rs)

Refactor `Runtime::execute` to delegate. Zero behavior change.

---

### Component 5 — Result & Lifecycle Types

#### [NEW] `result.rs`, `handle.rs`

`ContainerResult` (ergonomic accessors, `assert_success`, `assert_stdout_contains`).
`PreparedContainer` (inspect, inject, then run).
Future `ContainerHandle` (detached run + exec, multi-container ready).

---

### Component 6 — Test Harness Utilities

#### [NEW] [`crates/carrick-embed/src/testing.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/testing.rs)

```rust
pub fn run_in_container(image: &str, cmd: &str) -> ContainerResult;
pub struct TestContainer { /* shared store, pre-pulled image */ }
```

---

### Component 7 — Multi-Container Readiness

Shared `ImageStore`, bridge networking, independent observers/mounts per
container. Multiple containers = multiple tokio tasks. Future `ContainerGroup`.

---

### Component 8 — Time Control

#### [NEW] [`crates/carrick-embed/src/time.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/time.rs)

```rust
pub enum TimeControl {
    System,                                    // real time (default)
    Frozen(SystemTime),                        // wall clock frozen, monotonic advances
    Offset(Duration),                          // wall clock shifted by delta
    Scaled { base: SystemTime, factor: f64 },  // time passes at multiplier
    Deterministic { epoch: SystemTime },       // strictly incrementing, reproducible
}
```

```rust
Container::from_image("myapp:latest")
    .time(TimeControl::Frozen(datetime!(2025-12-31 23:59:59 UTC)))
    .command(["./test-new-year"])
    .run().await?;
```

#### [MODIFY] [`dispatch/time.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/time.rs)

Wire into `clock_gettime`, `nanosleep`, `clock_nanosleep`, `timer_*`, `timerfd_*`.

---

### Component 9 — Fault Injection

#### [NEW] [`crates/carrick-embed/src/observers/fault.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/observers/fault.rs)

```rust
let chaos = FaultInjector::new()
    .on_syscall("openat")
        .when(|_, sys| sys.path_arg(1).starts_with("/data/"))
        .after_count(100)
        .fail_with(libc::EIO)
    .on_syscall("connect")
        .probability(0.1)
        .fail_with(libc::ECONNREFUSED)
    .build();
```

Implements `SyscallObserver`. Rule builder with `SyscallMatcher`,
`FaultCondition` (Always, Probability, AfterCount, ForDuration, When, And, Or),
`FaultAction` (Errno, Delay, Kill). Convenience: `oom_after(n)`,
`network_partition()`, `slow_disk(latency)`.

---

### Component 10 — Zero-Copy Guest Memory

#### [NEW] [`crates/carrick-embed/src/memory.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/memory.rs)

```rust
pub trait GuestMemoryAccess: Send + Sync {
    fn read(&self, guest_addr: u64, buf: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&self, guest_addr: u64, data: &[u8]) -> Result<(), MemoryError>;
    fn read_pod<T: Pod>(&self, guest_addr: u64) -> Result<T, MemoryError>;
}

pub struct SharedBuffer { /* page-aligned, mapped into guest IPA */ }
```

---

### Component 11 — Network Mocking

#### [NEW] [`crates/carrick-embed/src/observers/network.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/observers/network.rs)

```rust
let network = NetworkInterposer::new()
    .on_connect(("api.example.com", 443))
        .intercept(Arc::new(HttpMock::new()
            .route("GET /health", 200, r#"{"status":"ok"}"#)))
    .on_connect(("evil.com", 80))
        .refuse(libc::ECONNREFUSED)
    .build();
```

`MockService` trait for inline response generation. `ConnectionRecord` for
test assertions. Implements `SyscallObserver`.

---

### Component 12 — Resource Budgets

#### [NEW] [`crates/carrick-embed/src/observers/budget.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-embed/src/observers/budget.rs)

```rust
let budget = ResourceBudget::new()
    .max_cpu_time(Duration::from_secs(30))
    .max_memory(256 * 1024 * 1024)
    .max_processes(16)
    .max_syscalls(1_000_000)
    .max_bytes_written(1 << 30)
    .on_exceed(ExceedAction::Kill);
let counters = budget.counters();  // live AtomicU64 reads while running
```

Implements `SyscallObserver`. Tracks via atomic counters per syscall group.
CPU time from existing `Thread::system_ns` accounting.

---

### Component 13 — Self-Hosted Conformance Framework

The embed API becomes carrick's own Linux conformance testing infrastructure,
replacing the shell-out + text-diff approach with in-process structured
verification. Every embed feature (observer, time control, fault injection,
budgets) directly improves conformance testing quality.

#### [NEW] [`crates/carrick-conformance-next/`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance-next/)

New workspace member. Depends on `carrick-embed`. Contains the next-generation
conformance test suite.

---

#### 13a. In-Process Structured Tests

Replace shell-out conformance with `#[test]` functions:

```rust
#[test]
fn getpid_returns_1_in_pid_namespace() {
    let observer = AuditObserver::new();
    let log = observer.log();

    let result = Container::from_image("alpine:latest")
        .observer(Arc::new(observer))
        .command(["sh", "-c", "echo $$"])
        .run_blocking().unwrap();

    result.assert_success();

    let getpid = log.lock().unwrap().iter()
        .find(|e| e.syscall.name == "getpid").unwrap();
    assert_eq!(getpid.outcome.retval, 1);
}
```

No text parsing. No codesigning dance for the test harness. Structural
assertions on syscall behavior, not string equality on stdout.

---

#### 13b. Syscall-Level Differential Oracle

Today's gate diffs stdout text against Docker. The new oracle diffs **syscall
traces** — it tells you not just "the output differs" but "carrick returned
`EINVAL` from `clone3` where Linux returned `0`":

##### [NEW] [`crates/carrick-conformance-next/src/differential.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance-next/src/differential.rs)

```rust
pub struct SyscallDivergence {
    pub syscall: String,
    pub args: [u64; 6],
    pub carrick_result: SyscallOutcome,
    pub linux_result: SyscallOutcome,
    pub process: String,  // executable that made the call
}

/// Run a workload under carrick (with AuditObserver) and under Docker
/// (with bpftrace), diff the syscall traces semantically.
pub fn differential_run(
    image: &str,
    cmd: &[&str],
) -> Vec<SyscallDivergence> { ... }

/// Map divergences across the entire LTP suite, grouped by syscall handler.
/// Produces a per-syscall coverage report:
/// "openat: 412 arg combinations match, 3 diverge (O_TMPFILE, O_PATH|O_NOFOLLOW, ...)"
pub fn map_divergences(
    suite: &ConformanceSuite,
) -> BTreeMap<String, SyscallCoverage> { ... }

pub struct SyscallCoverage {
    pub matching: u64,
    pub diverging: Vec<SyscallDivergence>,
    pub handler_file: String,  // e.g., "dispatch/fs.rs"
}
```

This gives a **per-syscall coverage map** rather than binary pass/fail per LTP
case. You can see: "we handle 98% of `openat` flag combinations correctly, but
`O_TMPFILE` is wrong" — and the divergence points directly at the handler to fix.

---

#### 13c. Observer-Based Semantic Probes

Verify kernel contract properties from the host side without modifying the guest.
Things that are invisible in stdout but critical for correctness:

##### [NEW] [`crates/carrick-conformance-next/src/probes/`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance-next/src/probes/)

```rust
/// Library of reusable semantic probe observers.
/// Each one verifies a specific Linux kernel contract.

/// Verify: after fork(), child's getpid() == the pid returned to parent
pub struct ForkPidConsistencyProbe { ... }

/// Verify: after execve(), O_CLOEXEC fds are not used by the new process
pub struct CloseOnExecProbe { ... }

/// Verify: after execve(), signal dispositions reset to SIG_DFL
pub struct SignalResetOnExecProbe { ... }

/// Verify: after setsid(), the new session/pgrp IDs match getpid()
pub struct SetsidProbe { ... }

/// Verify: brk(0) returns the current break; brk(addr) returns addr on success
pub struct BrkSemanticsProbe { ... }

/// Verify: mmap with MAP_FIXED at an occupied range unmaps the old mapping
pub struct MmapFixedProbe { ... }

/// Verify: close() on a fd makes subsequent read/write return EBADF
pub struct CloseFdProbe { ... }

/// Verify: dup2(old, new) closes new first if open, then aliases to old
pub struct Dup2SemanticsProbe { ... }
```

Each probe implements `SyscallObserver`, is installed via the builder, and
asserts invariants from the observed syscall trace. They compose — you can
install multiple probes on the same container run.

---

#### 13d. Deterministic Conformance Tests

Timer-dependent LTP cases are a major source of flakiness. With
`TimeControl::Deterministic`, they become reproducible:

```rust
#[test]
fn timer_create_fires_at_correct_interval() {
    let result = Container::from_image("conformance:latest")
        .time(TimeControl::Deterministic { epoch: UNIX_EPOCH })
        .observer(Arc::new(TimerFiringProbe::new(Duration::from_millis(100))))
        .command(["./timer_create_test"])
        .run_blocking().unwrap();
    result.assert_success();
    // With deterministic time, timestamps are identical across runs.
    // No "99ms vs 101ms" jitter — the test either matches or it doesn't.
}
```

---

#### 13e. Property-Based Syscall Fuzzing

Systematically explore the syscall argument space:

##### [NEW] [`crates/carrick-conformance-next/src/fuzz.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance-next/src/fuzz.rs)

```rust
/// Generate random but structurally valid syscall arguments for a given
/// syscall, run through carrick-embed with observer + resource budget,
/// and verify invariants (no panics, no hangs, valid errno or result).
pub struct SyscallFuzzer {
    pub syscall: &'static str,
    pub arg_generators: Vec<Box<dyn ArgGenerator>>,
    pub budget: ResourceBudget,
    pub invariants: Vec<Box<dyn SyscallInvariant>>,
}

/// Standard invariants that hold for ALL syscalls.
pub trait SyscallInvariant: Send + Sync {
    fn check(&self, request: &SyscallInfo, outcome: &SyscallOutcome) -> Result<(), String>;
}

/// Built-in invariants:
pub struct NoPanic;            // carrick process didn't crash
pub struct ValidErrno;         // retval is a valid errno or non-negative
pub struct NoHang;             // completed within budget
pub struct Idempotent;         // same args → same result (for pure syscalls)
pub struct MonotonicTime;      // clock_gettime never goes backward
```

Usage with proptest:
```rust
proptest! {
    #[test]
    fn openat_never_panics(flags in any::<u32>(), mode in any::<u32>()) {
        let result = SyscallFuzzer::for_syscall("openat")
            .with_arg(0, Arg::Fd(AT_FDCWD))
            .with_arg(1, Arg::Path("/tmp/fuzz"))
            .with_arg(2, Arg::Raw(flags as u64))
            .with_arg(3, Arg::Raw(mode as u64))
            .budget(ResourceBudget::new().max_syscalls(100))
            .invariants(&[NoPanic, ValidErrno, NoHang])
            .run();
        assert!(result.is_ok(), "{:?}", result);
    }
}
```

---

#### 13f. Regression Detection via Syscall Fingerprinting

Record golden syscall traces for known-good runs, diff against future runs:

##### [NEW] [`crates/carrick-conformance-next/src/golden.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance-next/src/golden.rs)

```rust
/// Bless the current syscall trace as the golden reference.
pub fn bless(name: &str, image: &str, cmd: &[&str]);

/// Assert the current run matches the golden trace.
/// With TimeControl::Deterministic, traces are fully reproducible.
pub fn assert_matches_golden(name: &str, image: &str, cmd: &[&str]);

/// Diff two traces, producing human-readable divergence report.
pub fn diff_golden(name: &str, image: &str, cmd: &[&str]) -> Vec<TraceDiff>;
```

Golden traces live under `tests/golden/` and are committed. Any change in
carrick's syscall behavior shows up as a concrete diff in CI:
```
REGRESSION in "echo_hello":
  syscall #47: write(1, "hello world\n", 12)
    golden:  retval=12, errno=None
    current: retval=-1, errno=Some(5)   // EIO
```

---

#### 13g. Conformance Dashboard / Coverage Map

##### [NEW] [`crates/carrick-conformance-next/src/coverage.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance-next/src/coverage.rs)

```rust
/// Run the full conformance suite and produce a per-syscall coverage report.
/// Replaces the binary pass/fail per-LTP-case view with a continuous
/// coverage metric per syscall handler.
pub fn generate_coverage_report() -> CoverageReport;

pub struct CoverageReport {
    /// Per-syscall: how many argument combinations tested, how many match Linux
    pub syscalls: BTreeMap<String, SyscallCoverage>,
    /// Overall: percentage of tested syscall surface that matches Linux
    pub overall_match_rate: f64,
    /// Regressions since last blessed baseline
    pub regressions: Vec<SyscallDivergence>,
    /// Improvements since last blessed baseline
    pub improvements: Vec<SyscallDivergence>,
}
```

Rendered to `docs/conformance-coverage.md` (replaces or supplements
`docs/support-matrix.md`). Shows not just "which syscalls exist" but "which
argument combinations produce correct Linux behavior."

---

#### Relationship to existing `carrick-conformance`

`carrick-conformance-next` does NOT replace `carrick-conformance` immediately.
The migration path:

1. **Phase 7a**: Stand up `carrick-conformance-next` with the `TestContainer`
   fixture. Port 10 representative LTP cases to in-process tests to validate
   the approach.
2. **Phase 7b**: Add the differential oracle. Run it alongside the existing
   text-diff gate. Verify it catches the same failures plus new ones.
3. **Phase 7c**: Add semantic probes and property fuzzing. These find classes
   of bugs the existing gate misses (e.g., brk never tested past 4 MiB).
4. **Gradual migration**: As `carrick-conformance-next` proves itself, the
   existing `carrick-conformance` cases are ported one by one. The old gate
   remains until the new one achieves coverage parity.
5. **Eventually**: `carrick-conformance-next` becomes `carrick-conformance`.

---

### Workspace Integration

#### [MODIFY] [`Cargo.toml`](file:///Volumes/CaseSensitive/carrick/Cargo.toml)

Add `"crates/carrick-embed"` and `"crates/carrick-conformance-next"` to
`workspace.members`.

#### [MODIFY] [`crates/README.md`](file:///Volumes/CaseSensitive/carrick/crates/README.md)

| Crate | Role |
|---|---|
| `carrick-embed` | Library embedding API: builder, VFS, observer, time, fault injection, memory, network, budgets |
| `carrick-conformance-next` | Self-hosted conformance framework using `carrick-embed`: differential oracle, semantic probes, fuzzing, golden traces |

---

## Implementation Phases

### Phase 0 — Fork Retirement (prerequisite)
1. NsSupervisor → kernel-graph task
2. Interactive supervisor → thread-based pty relay
3. Verify: zero `libc::fork` in non-test execute path

### Phase 1 — Foundation (builder + phased runtime + happy path)
1. Add `prepare.rs` to `carrick-runtime` with phased API
2. Refactor `Runtime::execute` to delegate to `prepare.rs`
3. Create `carrick-embed` crate with `ContainerBuilder`
4. Implement `StdioConfig`, `ContainerResult`, `PreparedContainer`
5. Wire `run()` / `run_blocking()` end-to-end
6. Tests: basic containers, mounts, env, exit codes

### Phase 2 — VFS injection
1. Re-export `Vfs` trait from `carrick-embed`
2. Wire `vfs_mount()` through `PreparedDispatcher::register_mount`
3. Implement `LayeredVfs`, `InMemoryFileVfs`
4. Tests: synthetic file injection, layered fallthrough

### Phase 3 — Syscall observer + time control
1. Add `observer` field to `SyscallDispatcher`, wire into `dispatch_threaded`
2. Wire lifecycle events (fork/exec/exit) from vcpu loop
3. Define `SyscallObserver` trait, `ProcessInfo`, `SyscallInfo`, `SyscallAction`
4. Implement `AuditObserver`
5. Add `TimeControl` to dispatcher, wire into time dispatch handlers
6. Tests: audit log assertions, deny policy, time freeze/offset/scale

### Phase 4 — Fault injection + resource budgets
1. Implement `FaultInjector` observer
2. Implement `ResourceBudget` observer
3. Implement `PolicyObserver`, `SandboxObserver`
4. Tests: chaos scenarios, budget exceed kill, live counter reads

### Phase 5 — Network mocking + zero-copy memory
1. Implement `NetworkInterposer` observer
2. Implement `GuestMemoryAccess` trait and `SharedBuffer`
3. Wire `SharedBuffer` into dispatcher (host alloc → guest IPA map)
4. Tests: mock HTTP service, connection recording, shared buffer round-trip

### Phase 6 — Advanced VFS + test harness + polish
1. Implement `FilterVfs`, `RecordingVfs`
2. Implement `TestContainer` fixture and `run_in_container`
3. Doc comments with examples on every public item
4. `README.md` with quick-start guide
5. Integration tests: full Docker-like happy path
6. Stub `ContainerHandle` (detached + exec) types

### Phase 7 — Self-Hosted Conformance Framework
1. **7a — Foundation**: Create `carrick-conformance-next`. Port 10 LTP cases
   to in-process `#[test]` functions using `TestContainer` + `AuditObserver`.
   Verify the approach catches the same failures as the existing text-diff gate.
2. **7b — Differential oracle**: Implement `differential_run` and
   `map_divergences`. Run alongside existing gate. Produce per-syscall coverage
   map. Identify divergences invisible to stdout-diff.
3. **7c — Semantic probes**: Implement the probe library
   (`ForkPidConsistencyProbe`, `CloseOnExecProbe`, `SignalResetOnExecProbe`,
   etc.). These catch kernel-contract violations that no LTP case exercises.
4. **7d — Deterministic tests**: Convert timer-dependent cases to
   `TimeControl::Deterministic`. Eliminate the flaky-timer class of failures.
5. **7e — Property fuzzing**: Implement `SyscallFuzzer` with proptest.
   Fuzz `openat`, `mmap`, `clone`, `ioctl` argument spaces. Budget-bounded.
6. **7f — Golden traces**: Implement bless/assert/diff for syscall fingerprints.
   Commit golden traces under `tests/golden/`. CI diffs against them.
7. **7g — Coverage dashboard**: Generate `docs/conformance-coverage.md` from
   the differential oracle and fuzzer results. Per-syscall match rate,
   regressions, improvements.

---

## Verification Plan

### Automated Tests

**Phase 0:**
```bash
just ci && just conformance-quick
```

**Phases 1–6:**
```bash
just check && just test && just clippy && just ci
just build && cargo test -p carrick-embed
```

**Phase 7:**
```bash
cargo test -p carrick-conformance-next   # structured conformance suite
# Differential oracle runs alongside existing gate:
just conformance-quick                   # old gate (text-diff)
cargo test -p carrick-conformance-next --test differential  # new gate (syscall-diff)
# Both must pass. When new gate achieves parity, old gate is retired.
```

### Refactor Safety
- `Runtime::execute` refactoring: `just test` + `just conformance-quick` diff
- Observer pipeline: zero overhead when no observer installed
- Time control: conformance probes pass with `TimeControl::System`
- Conformance-next: must catch ≥ 100% of existing gate failures before migration

### Manual Verification
- Example binary: embed API runs alpine with VFS + observer + time + budget
- Conformance coverage report reviewed for accuracy before committing baselines
