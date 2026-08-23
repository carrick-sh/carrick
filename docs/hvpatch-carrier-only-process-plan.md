# Carrier-only process model: the retirement map — 2026-08-22

Owner direction: the HVPatch lane should run as the VM CARRIER ALONE;
NsSupervisor and the detached FileAuthority helper are host-fork-era
machinery. Produced by a read-only Antigravity worker; claims carry
file:line but are UNVERIFIED until the write task re-checks them.

# Read-Only Audit & Retirement Map: Retiring `NsSupervisor` and `FileAuthority` Helper on the HVPatch Lane

**Repository**: `/Volumes/CaseSensitive/carrick` (main)  
**Rulebook**: [`AGENTS.md`](file:///Volumes/CaseSensitive/carrick/AGENTS.md)  
**Execution Context**: Read-only architectural audit. No files modified, no guest runs or builds executed.

---

## Executive Architectural Summary

In earlier host-fork architecture iterations of Carrick, every guest Linux `clone`/`fork` spawned a separate macOS host process via `libc::fork()`. Two outer processes were created to coordinate across those host processes:
1. **`NsSupervisor`**: A host supervisor process monitoring member host processes via kqueue (`EVFILT_PROC` / `NOTE_EXIT`) for orphan reparenting (overcoming macOS's kernel behavior of reparenting orphaned host processes to `launchd`), exit status harvesting, and process group teardown.
2. **`FileAuthority` Helper**: A detached helper process spawned via double-fork to own mutable file description, table, and epoll state and serialize cross-host-process mutations across disjoint host address spaces using Unix domain datagrams (`AF_UNIX` / `SOCK_DGRAM`) and POSIX file record locks (`fcntl(F_SETLKW)`).

**The HVPatch Reality**: Under the consolidated HVPatch kernel architecture ([`AGENTS.md:14-23`](file:///Volumes/CaseSensitive/carrick/AGENTS.md#L14-L23), [`carrick-spec/src/lib.rs:235-265`](file:///Volumes/CaseSensitive/carrick/crates/carrick-spec/src/lib.rs#L235-L265), [`carrick-runtime/src/threaded_loop.rs:172-177`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/threaded_loop.rs#L172-L177)), guest processes, threads, address spaces, credentials, and parent-child hierarchies are multiplexed **entirely within a single VM carrier host process**. Guest `fork`/`clone` do not create host processes. The authoritative event ring, thread registry, and process census live entirely in the carrier process.

Spawning `NsSupervisor` and the `FileAuthority` helper on the HVPatch lane creates two redundant host processes for every run. Below is the comprehensive retirement map and migration plan.

---

## 1. SPAWN: Creation Points, Conditions, and Decision Gates

### A. `NsSupervisor` Spawn Analysis

* **Creation Site**: [`crates/carrick-runtime/src/runtime.rs:600-688`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L600-L688) (`maybe_fork_ns_supervisor`).
  * At [`runtime.rs:635`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L635), `libc::fork()` is called before creating the HVF VM.
  * **Parent (Host PID $P$)**: Becomes `NsSupervisor` ([`runtime.rs:654-688`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L654-L688)), closes the registration pipe write end, updates the container registry if detached ([`runtime.rs:665-673`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L665-L673)), and enters the kqueue loop `crate::namespace::supervisor::run(pid, pipe_read)` ([`runtime.rs:674`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L674)).
  * **Child (Host PID $C$)**: Becomes the VM carrier / guest-init (guest ns-PID 1) ([`runtime.rs:645-653`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L645-L653)), calls `pid::set_init(std::process::id())`, and continues into `new_hvf_trap_engine` and the vCPU loop ([`runtime.rs:750-764`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L750-L764)).
* **Invocation Path**:
  * Called from `run_address_space_with_hvf_and_dispatcher` at [`runtime.rs:737`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L737).
* **Conditions & Decision Logic Today**:
  * Gated by `crate::namespace::pid::supervisor_requested()` at [`runtime.rs:603`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L603) and [`namespace/pid.rs:102-104`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/pid.rs#L102-L104).
  * In `Runtime::execute` ([`crates/carrick-runtime/src/execute.rs:224-241`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/execute.rs#L224-L241)):
    * `PidMode::Host`: No supervisor requested (`execute.rs:225`).
    * `PidMode::Private`:
      * If `CARRICK_JOIN_REGION` is present (`carrick exec`), `join_existing` is called; no supervisor requested (`execute.rs:227-234`).
      * Else if `spec.raw || spec.tty`: Calls `crate::namespace::pid::request_supervisor()` (`execute.rs:236`), setting `SUPERVISOR_REQUESTED = true`.
      * Else (buffered JSON envelope): Calls `crate::namespace::pid::request()` (`execute.rs:238`), setting `REQUESTED = true` but `SUPERVISOR_REQUESTED = false` (runs in-process without supervisor fork).
  * In detached container runs ([`crates/carrick-cli/src/lifecycle.rs:128, 584`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/lifecycle.rs#L128)): `run_detached` / `start_one` forks the detached process, which runs `Runtime::execute` with streaming stdio, which then forks a *second* time via `maybe_fork_ns_supervisor`.
  * In `run-elf` ([`crates/carrick-cli/src/commands.rs:1062-1077`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/commands.rs#L1062-L1077)): `supervisor_requested()` is false, so `maybe_fork_ns_supervisor` returns `SupervisorRole::InProcess`.
  * In cross-platform `run_threaded_loop` ([`crates/carrick-runtime/src/threaded_loop.rs:211-213`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/threaded_loop.rs#L211-L213)): `maybe_fork_ns_supervisor` is not called at all; it directly calls `pid::init(std::process::id())`.

---

### B. `FileAuthority` Helper Spawn Analysis

* **Creation Site**: [`crates/carrick-runtime/src/file_authority/ipc.rs:63-170`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L63-L170) (`IpcFileAuthority::spawn_per_run`).
  * Double-fork pattern at [`ipc.rs:76`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L76) (`launcher = unsafe { libc::fork() }`) and [`ipc.rs:83`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L83) (`helper = unsafe { libc::fork() }`).
  * Intermediate launcher child exits `libc::_exit(0)` at [`ipc.rs:96`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L96) and is synchronously reaped by the carrier at [`ipc.rs:101-110`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L101-L110).
  * The detached helper process closes unrelated descriptors ([`ipc.rs:88-92`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L88-L92)) and executes `serve(server, lifetime_read, core)` ([`ipc.rs:93`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L93), [`ipc.rs:389-446`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L389-L446)).
* **Invocation Path**:
  * Called from `FileAuthorityRun::launch()` at [`crates/carrick-runtime/src/file_authority/root.rs:39-49`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L39-L49).
  * Triggered via `SyscallDispatcher::activate_file_authority()` at [`crates/carrick-runtime/src/dispatch/mod.rs:4112-4126`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mod.rs#L4112-L4126).
  * Activated by the carrier in `run_address_space_with_hvf_and_dispatcher` ([`runtime.rs:741`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L741)) and in `run_threaded_loop` ([`threaded_loop.rs:190`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/threaded_loop.rs#L190)).
* **Conditions & Decision Logic Today**:
  * In non-test production builds (`#[cfg(not(test))]` at [`root.rs:41-49`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L41-L49)), `FileAuthorityRun::launch()` **unconditionally** spawns the double-fork helper process via `IpcFileAuthority::spawn_per_run`.
  * In unit tests (`#[cfg(test)]` at [`root.rs:50-57`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L50-L57)), it invokes `direct_root(epoch)` using `DirectFileAuthority` ([`transport.rs:33-51`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/transport.rs#L33-L51)) in-process.

---

## 2. DUTIES: Live Responsibilities & Verification

### A. `NsSupervisor` Duties

| Duty | Description & Live Code Evidence | HVPatch Equivalent in Carrier |
|---|---|---|
| **Namespace & Region Setup** | Allocates `NsSharedRegion` via `alloc_region()` ([`runtime.rs:610`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L610)); sets up non-blocking registration pipe ([`runtime.rs:613-630`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L613-L630)). | `KernelArena::init_global()` ([`runtime.rs:728`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L728)) and `pid::init(carrier_pid)` ([`threaded_loop.rs:212`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/threaded_loop.rs#L212)). |
| **Stdio / PTY Relay** | **None in `NsSupervisor`**. `NsSupervisor::run` ([`supervisor.rs:63-164`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L63-L164)) does not handle stdio. Stdio is either inherited directly or relayed by the distinct `InteractiveParent` fork in [`interactive_supervisor.rs:210`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/interactive_supervisor.rs) / [`execute.rs:372-395`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/execute.rs#L372-L395). | Guest writes directly to inherited stdout/stderr descriptors in carrier. |
| **Exit-Status Harvest & Relay** | Calls `try_reap_init(init_host_pid)` ([`supervisor.rs:102, 124, 266-274`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L102)); converts status via `status_to_exit_code` ([`supervisor.rs:314-322`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L314-L322)); returns `SupervisorRole::Parent(RunResult)` ([`runtime.rs:679-687`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L679-L687)). | Carrier's vCPU loop returns `RunResult { exit_code, ... }` directly from `run_threaded_hvf_loop` ([`runtime.rs:764`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L764)). |
| **Child Reaping & Orphan Reparenting** | Arms exit watches on registered host members via `arm_member_watches` ([`supervisor.rs:89-92, 197-221`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L89)); marks orphans on host parent death via `handle_member_death` ([`supervisor.rs:143, 225-229`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L143)). | **No consumer on HVPatch**. Guest tasks have no host PIDs. The `carrick-kernel` process graph and `ThreadRegistry` handle guest PID 1 orphan reparenting in-process. |
| **Teardown on Init Exit** | Calls `teardown(init_host_pid)` ([`supervisor.rs:103, 126, 235-262`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L103)), invoking `libc::killpg(init_host_pid, SIGKILL)` and sweeping `region.members()` with `libc::kill(host, SIGKILL)`. | `destroy_persistent_vm_at_run_terminal()` ([`runtime.rs:767`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L767)) and sibling thread cancellation in carrier. |
| **Container State Registry** | Updates `ContainerStatus::Running`, sets `supervisor_pid = std::process::id()`, `init_pid = child_pid` ([`runtime.rs:665-673`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L665-L673)); marks `Exited` on termination ([`runtime.rs:677`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L677)). | Carrier updates its own PID into `ContainerState` at boot and calls `container::mark_exited` in `finalize_persistent_hvf_run` ([`runtime.rs:690-717`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L690-L717)). |
| **Member Registration Drain** | Reads byte wakes from `reg_pipe_read` via `drain_pipe` ([`supervisor.rs:148, 297-309`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/namespace/supervisor.rs#L148)). | **No consumer on HVPatch**. No guest process writes to `REG_PIPE_WRITE`. |

---

### B. `FileAuthority` Helper Duties

1. **Requests Handled by `serve`**:
   * Loop: [`crates/carrick-runtime/src/file_authority/ipc.rs:389-446`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L389-L446).
   * Request framing: `decode_request` ([`ipc.rs:424`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L424)) / `encode_response_with_fd_count` ([`ipc.rs:434`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L434)).
   * Core dispatch: `FileAuthorityCore::execute_call` ([`ipc.rs:427`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L427), [`core.rs:123-148`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/core.rs#L123-L148)).
   * Commands serviced ([`crates/carrick-runtime/src/file_authority/types.rs:527-796`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/types.rs#L527-L796)):
     * Client management: `RegisterClient`, `ExitClient`.
     * Table & Descriptor Lifecycle: `CreateTable`, `ResolveSlot`, `ListSlots`, `SetDescriptorFlags`, `ReplaceSlot`, `MutateSlotRange`, `Dup`, `Close`, `ForkCopy`, `ForkCopyMappings`, `ShareTable`, `ExecSuccessor`.
     * Streams & Pipes: `CreatePipeAndInstall`, `SetPipeCapacity`, `AdoptHostStreamAndInstall`.
     * Event Backends: `CreateEpollAndInstall`, `EpollCtlAdd`, `EpollCtlModify`, `EpollCtlDelete`, `EpollRevalidateHostPlan`, `ObserveReadiness`, `EpollCollect`, `EpollAcknowledgeIo`.
     * Timers & Counters: `CreateTimerAndInstall`, `SetTimer`, `ExpireTimer`, `CreateSignalFdAndInstall`, `SetSignalFdMask`, `CreateEventCounterAndInstall`, `EventCounterRead`, `EventCounterWrite`.
     * VFS & Memory Objects: `CreateVfsFile`, `ResolveVfs`, `LinkVfs`, `UnlinkVfs`, `RenameVfs`, `OpenVfsAndInstall`, `CreateSyntheticAndInstall`, `AdoptHostFileAndInstall`, `AdoptIoUringAndInstall`, `InspectDescription`.
     * IO & Leases: `Read`, `Write`, `Seek`, `AcquireCapabilityLease`, `ReleaseCapabilityLease`, `FinalizeMappingLease`, `ReleaseMappingAttachment`.

2. **Client Population on HVPatch**:
   * Client endpoint setup: [`crates/carrick-runtime/src/dispatch/mod.rs:4112-4126`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mod.rs#L4112-L4126).
   * **Are all clients inside the carrier? YES.** All guest vCPUs/threads execute inside the single carrier process. Every syscall dispatcher instance references the same `file_authority: RwLock<Option<Arc<FileAuthorityRun>>>` ([`dispatch/mod.rs:2369, 3805`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mod.rs#L2369)).
   * Only the root client (`ClientId(1)`, host PID = carrier host PID) is registered ([`ipc.rs:123-128`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L123-L128)). Zero external host processes connect.

3. **Epoch & Lifetime-Pipe Teardown Contract**:
   * Epoch: [`crates/carrick-runtime/src/file_authority/root.rs:124-136`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L124-L136) (`run_epoch`). A 64-bit random non-zero value validated on every request/response.
   * Lifetime Pipe:
     * `cloexec_pipe()` creates `(lifetime_read, lifetime_write)` ([`ipc.rs:69`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L69)).
     * Carrier retains `_lifetime_write` in `IpcInner` ([`ipc.rs:119`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L119)); helper polls `lifetime_read` ([`ipc.rs:398`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L398)).
     * When carrier terminates or crashes, the host kernel closes `_lifetime_write`. `lifetime_read` receives `POLLHUP | POLLERR`, breaking the `serve` loop ([`ipc.rs:410-412`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L410-L412)) so the helper terminates with `_exit(0)` ([`ipc.rs:94`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L94)).

4. **Host Re-Exec Story**:
   * **Question**: Does guest `execve` on the HVPatch lane re-exec the host process (which would wipe in-process authority heap/state)?
   * **Answer**: **NO.**
   * **Evidence**:
     * In `crates/carrick-runtime/src/dispatch/proc.rs:3962` and `4008`, `execve`/`execveat` return `DispatchOutcome::Execve { path, argv, env }`.
     * In the HVPatch vCPU loop ([`crates/carrick-runtime/src/vcpu_loop/mod.rs:4157-4198`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L4157-L4198)), `DispatchOutcome::Execve` calls `prepare_execve` ([`vcpu_loop/mod.rs:4170`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L4170)), drains sibling vCPUs ([`vcpu_loop/mod.rs:4176`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L4176)), calls `finish_prepared_execve` ([`vcpu_loop/mod.rs:4183`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L4183)), and updates the VM memory mapping and vCPU registers **in-process**.
     * In the single-threaded fallback loop ([`crates/carrick-runtime/src/runtime.rs:1272-1310`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L1272-L1310)), `DispatchOutcome::Execve` calls `runtime.execve_into(&new_image)` in-process.
     * Neither path ever calls `libc::execve`. The host process is never re-execed. In-process file authority state in `Arc<Mutex<FileAuthorityCore>>` (`DirectFileAuthority`) safely survives all guest `execve` transitions.

---

## 3. LANE MATRIX: Process Separation vs In-Process Ownership

The codebase defines execution lanes in [`crates/carrick-conformance/src/lane.rs:78-84`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance/src/lane.rs#L78-L84) and [`crates/carrick-spec/src/lib.rs:235-265`](file:///Volumes/CaseSensitive/carrick/crates/carrick-spec/src/lib.rs#L235-L265):

| Lane Identifier (Code Spelling) | Architecture / Host | `NsSupervisor` Requirement | `FileAuthority` Helper Requirement |
|---|---|---|---|
| **`Lane::Hvf`** (`--exec-backend hvpatch` / macOS Apple Silicon HVF) | Unified HVPatch kernel in 1 VM carrier | **Can own in-process in carrier** (retire supervisor process) | **Can own in-process in carrier** via `DirectFileAuthority` (retire helper process) |
| **`Lane::Kvm` / `Lane::KvmLocal`** (`--platform linux/amd64`, Linux `/dev/kvm`) | Unified HVPatch kernel in 1 VM carrier | **Can own in-process in carrier** (already in-process in `threaded_loop.rs:211`) | **Can own in-process in carrier** via `DirectFileAuthority` |
| **`Lane::BhyveLocal`** (`--platform linux/amd64`, FreeBSD `/dev/vmm`) | Unified HVPatch kernel in 1 VM carrier | **Can own in-process in carrier** | **Can own in-process in carrier** via `DirectFileAuthority` |
| **`Lane::NvmmLocal`** (`--platform linux/amd64`, NetBSD `/dev/nvmm`) | Unified HVPatch kernel in 1 VM carrier | **Can own in-process in carrier** | **Can own in-process in carrier** via `DirectFileAuthority` |
| **Native Darwin / FreeBSD Primitives** (`carrick-native-darwin`, `carrick-dsr`) | Preserved building blocks (JIT / direct patch) | *If multi-host-process model re-introduced*: needs separate supervisor | *If multi-host-process model re-introduced*: needs `IpcFileAuthority` |

---

## 4. CARRIER-ONLY DESIGN: Surface Absorption & Consumer Inventory

### A. Surface Absorption in the Carrier

1. **Exit Code & Output Propagation**:
   * **Foreground (`carrick run <image> <cmd>`)**:
     * Current: `Runtime::execute` forks `NsSupervisor` $\rightarrow$ supervisor waits on carrier $\rightarrow$ supervisor returns empty `RunResult` with exit code.
     * Carrier-only: `Runtime::execute` runs carrier directly $\rightarrow$ `run_address_space_with_hvf_and_dispatcher` returns `RunResult { exit_code, stdout, stderr, traps, ... }` straight to the CLI caller.
   * **Detached (`carrick run -d`)**:
     * Current: CLI forks detached process $\rightarrow$ detached process forks `NsSupervisor` $\rightarrow$ supervisor forks carrier. (3 processes total).
     * Carrier-only: CLI forks detached process ([`lifecycle.rs:128`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/lifecycle.rs#L128)) $\rightarrow$ detached process **is** the carrier $\rightarrow$ sets its own PID as `init_pid` and `supervisor_pid` in `ContainerState` $\rightarrow$ runs VM $\rightarrow$ writes `ContainerStatus::Exited` in `finalize_persistent_hvf_run` ([`runtime.rs:690-717`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L690-L717)). (1 background process total).
   * **Reconciled Liveness**:
     * [`container::reconciled_status`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/container.rs#L500-L506) checks `pid_alive(state.init_pid)`. With `init_pid` pointing to the carrier, a crashed carrier correctly resolves to `Exited`.

2. **Scoped Kill & Process Tree Matching**:
   * [`scripts/sudo/kill.sh`](file:///Volumes/CaseSensitive/carrick/scripts/sudo/kill.sh#L45-L69) matches `carrick:<run_id>:` in `ps -axww -o pid= -o command=`.
   * Proctitle is rewritten in the carrier via `crate::dispatch::set_host_process_name` ([`proctitle.rs:88-93, 160-186`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/proctitle.rs#L88), [`execute.rs:247`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/execute.rs#L247)).
   * Carrier-only impact: `kill.sh <run_id>` finds **exactly one** process (the carrier) instead of three, and terminates it in pass 1 with zero script changes.

3. **`carrick debug hvpatch-kernel --run-id`**:
   * [`crates/carrick-cli/src/debug.rs:601-641`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/debug.rs#L601-L641) collects all processes matching `carrick:<run_id>`.
   * Carrier-only impact: LLDB attaches only to the single carrier process containing the authoritative VM, vCPU threads, and event ring. Eliminates failed attaches and empty state dumps from the supervisor and helper.

4. **Conformance Harness (`carrick-conformance`)**:
   * [`crates/carrick-conformance/src/engine.rs:439-469`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance/src/engine.rs#L439-L469) launches `carrick run` as a child process and samples CPU via `pid_cpu_ms(child.id())` ([`engine.rs:455`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance/src/engine.rs#L455)).
   * Current trap: `child.id()` was the `NsSupervisor`, which burned ~0% CPU in `kqueue` while the carrier spun in the VM, falsely classifying spins as `Blocked` or `Starved` timeouts.
   * Carrier-only benefit: `child.id()` is the carrier itself, restoring accurate CPU duty-cycle measurement for timeout classification ([`engine.rs:85-118`](file:///Volumes/CaseSensitive/carrick/crates/carrick-conformance/src/engine.rs#L85-L118)).

---

### B. Comprehensive Inventory of Consumers of the Three-Process Shape

| Consumer File | Exact Reference / Assumption | Required Update on Retirement |
|---|---|---|
| [`AGENTS.md:357`](file:///Volumes/CaseSensitive/carrick/AGENTS.md#L357) | Mentions raw runs containing `NsSupervisor`, VM carrier, and `FileAuthority` helper. | Update text to reflect single VM carrier on HVPatch. |
| [`.agents/skills/carrick-lldb/SKILL.md:72-114`](file:///Volumes/CaseSensitive/carrick/.agents/skills/carrick-lldb/SKILL.md#L72) | Documents selecting the right PID among `carrick:<run-id>` matches. | Simplify instructions: single process to attach. |
| [`.agents/skills/carrick-trace/SKILL.md:88-93`](file:///Volumes/CaseSensitive/carrick/.agents/skills/carrick-trace/SKILL.md#L88) | Tracing carrier vs supervisor / helper child processes. | Simplify instructions for single-process target. |
| [`docs/namespaces-design.md:192-280`](file:///Volumes/CaseSensitive/carrick/docs/namespaces-design.md#L192) | Entire architecture specification for `NsSupervisor`. | Mark supervisor process retired on HVPatch in favor of in-carrier kernel graph. |
| [`crates/carrick-cli/src/debug.rs:503-538`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/debug.rs#L503) | Iterates over all matched processes to attach LLDB. | Works automatically; will attach to 1 process instead of 3. |
| [`crates/carrick-cli/src/lifecycle.rs:32, 101, 179`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/lifecycle.rs#L32) | `supervisor_pid` comments and state persistence. | Record carrier PID into `supervisor_pid` / `init_pid`. |
| [`crates/carrick-runtime/src/container.rs:5, 46-51`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/container.rs#L5) | Documentation and field comments on `supervisor_pid`. | Update doc comments. |
| [`crates/carrick-cli/tests/conformance.rs:2605, 2822, 3576`](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/tests/conformance.rs#L2605) | Comments referencing NsSupervisor exit code harvest race. | Update test comments. |
| [`crates/carrick-runtime/src/file_authority/tests.rs:2094-2137`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/tests.rs#L2094) | `inherited_helper_endpoint_serializes_cross_process_requests` unit test. | Covered in Section 5 below. |

---

## 5. RISKS & THE STAGED MIGRATION PLAN

### A. Stage 1: In-Process `DirectFileAuthority` on HVPatch Lane (Smallest Honest Step)

1. **Implementation Seam**:
   * `DirectFileAuthority` already exists and is fully implemented in [`crates/carrick-runtime/src/file_authority/transport.rs:33-51`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/transport.rs#L33-L51), wrapping `Arc<Mutex<FileAuthorityCore>>`.
   * Promote `DirectFileAuthority` from `#[cfg(test)]` to `pub(crate)`.
   * In [`crates/carrick-runtime/src/file_authority/root.rs:39-58`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L39-L58) (`FileAuthorityRun::launch`):
     * Check backend authority: for HVPatch / in-process execution, instantiate `direct_root(epoch)` using `DirectFileAuthority`.
     * Retain `IpcFileAuthority::spawn_per_run` behind a typed backend capability for any execution backend requiring cross-process file authority.
2. **Immediate Wins**:
   * Eliminates the double-fork (`launcher` + `helper`) for every HVPatch run.
   * Replaces Unix datagram socketpair encoding/decoding and POSIX file lock (`flock`) contention with direct in-memory `Mutex<FileAuthorityCore>` execution.
   * Eliminates the helper lifetime pipe and helper reap tracking.

---

### B. Stage 2: `NsSupervisor` Collapse on HVPatch Lane

1. **Implementation Seam**:
   * In [`crates/carrick-runtime/src/runtime.rs:737`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L737) (`run_address_space_with_hvf_and_dispatcher`):
     * Bypass `maybe_fork_ns_supervisor()`.
     * Initialize PID namespace directly in carrier: `carrick_kernel::arena::KernelArena::init_global()` ([`runtime.rs:728`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L728)) and `pid::init(std::process::id())` (matching [`threaded_loop.rs:211-213`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/threaded_loop.rs#L211-L213)).
   * In [`crates/carrick-runtime/src/execute.rs:236`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/execute.rs#L236):
     * `spec.raw || spec.tty` calls `pid::request()` without setting `SUPERVISOR_REQUESTED`.
   * In [`crates/carrick-runtime/src/runtime.rs:690-717`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L690-L717) (`finalize_persistent_hvf_run`):
     * If `CARRICK_CONTAINER_ID` is set, carrier registers its own PID into `ContainerState` at launch and invokes `crate::container::mark_exited(id, code)` on run completion.
2. **Immediate Wins**:
   * Eliminates the pre-HVF `libc::fork()`.
   * Carrier runs as the direct child of the CLI / harness.
   * Fixes harness CPU sampling (`pid_cpu_ms`) to measure the true hypervisor process.
   * Eliminates kqueue `EVFILT_PROC` exit-watch loop and member registration pipe.

---

### C. Required Test Matrix

Before declaring completion of each stage, the following verification suite must pass:

1. **File Authority In-Process Concurrency**:
   * Add a multi-threaded stress test for `DirectFileAuthority` simulating concurrent vCPU syscall dispatch (file table allocation, epoll add/modify/collect, and VFS link/unlink) to guarantee mutex fairness and zero deadlocks.
   * Note on `same_client_requests_cannot_overtake_an_in_flight_round_trip` ([`root.rs:236-273`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L236-L273)): This existing test confirms that same-client sequence allocation and transaction execution form one serialized critical section.
2. **Container Lifecycle & CLI Integration**:
   * `carrick run -d` followed by `carrick ps`, `carrick logs`, `carrick exec`, `carrick stop`, and `carrick rm`.
   * Assert `ContainerState` records `status == Running` with valid `init_pid`, and reconciles to `Exited` after termination.
3. **PID Namespace & Conformance Probes**:
   * `conformance-probes/src/bin/pidnsinitreap.rs`: Verify orphan reparenting to ns-PID 1, `getpid() == 1`, and `getppid() == 0` within guest.
   * `just conformance-probes` (must run from repo root per rulebook).
4. **Scoped Process Count & Cleanup Receipt**:
   * Run a test workload with `CARRICK_RUN_ID=test-audit-1`.
   * Assert `ps -axww -o command= | grep "carrick:test-audit-1:"` reports **exactly 1 host process**.
   * Run `scripts/sudo/kill.sh test-audit-1` and confirm 0 remaining processes in 1 pass.

---

### D. Flaky Unit Test Flag: `inherited_helper_endpoint_serializes_cross_process_requests`

* **Subject**: [`crates/carrick-runtime/src/file_authority/tests.rs:2094-2137`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/tests.rs#L2094-L2137).
* **Flake Mechanism**: The test explicitly calls `IpcFileAuthority::spawn_per_run`, forks a host child process with `libc::fork()`, and races parent and child requests across the Unix datagram transport under `ProcessTransactionLock` (`libc::fcntl(F_SETLKW)`). Fork timing jitter and uncoordinated child execution can cause timeouts or sequence desynchronization.
* **Retirement / Replacement Strategy in Design**:
  * For the HVPatch lane, `IpcFileAuthority` is completely bypassed in production in favor of `DirectFileAuthority`.
  * The production HVPatch concurrency contract is validated by `same_client_requests_cannot_overtake_an_in_flight_round_trip` ([`root.rs:236-273`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/root.rs#L236-L273)) using host threads rather than `fork()`.
  * `inherited_helper_endpoint_serializes_cross_process_requests` remains scoped only to testing the fallback `IpcFileAuthority` transport for host-forking lanes. Under `RUST_TEST_THREADS=1` (mandated by [`AGENTS.md:65`](file:///Volumes/CaseSensitive/carrick/AGENTS.md#L65)), it will not impact normal HVPatch carrier execution.

---

### Delivery Confidence

| Item | Status | Key Justification |
|---|---|---|
| **Spawn Identification** | Confirmed | Exact line numbers for `maybe_fork_ns_supervisor` ([`runtime.rs:635`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L635)) and `IpcFileAuthority::spawn_per_run` ([`ipc.rs:76`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/file_authority/ipc.rs#L76)). |
| **Duties Verification** | Confirmed | Mapped every loop, pipe drain, kqueue event, and RPC request to live code. |
| **Host Re-Exec Proof** | Confirmed | Guest `execve` updates VM in-place ([`vcpu_loop/mod.rs:4157-4198`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L4157-L4198)); host `execve` is never called. |
| **Lanes Matrix** | Confirmed | All lanes (`Hvf`, `Kvm`, `BhyveLocal`, `NvmmLocal`) use HVPatch and can own state in-process. |
| **Safety & Staged Plan** | Confirmed | Two-stage decoupling preserves host-fork capability behind typed backend traits while eliminating outer processes on HVPatch. |
{"blockers":[],"description":"Read-only audit: retirement map for NsSupervisor and FileAuthority helper on HVPatch lane","files_changed":[],"questions_for_director":[],"self_review":["Completed read-only audit with file:line citations for spawn points, duties, lane matrix, carrier-only absorption design, and staged rollout plan. No files were modified and no builds/guests were executed per the prompt constraints."],"status":"done","summary":"Delivered a comprehensive read-only architectural audit and retirement map for eliminating NsSupervisor and the FileAuthority helper on the HVPatch lane, detailing spawn points, live duties, lane requirements, carrier-only absorption, and a staged rollout plan.","test_output_tail":"N/A - read-only audit task; no tests or builds were executed per prompt instructions.","tests_passing":false,"tests_run":[],"toolAction":"Finishing read-only audit task","toolSummary":"Complete read-only audit"}

