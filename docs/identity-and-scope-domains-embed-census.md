# Embed census: per-container state held in carrier-wide statics

Companion to [`identity-and-scope-domains.md`](identity-and-scope-domains.md)
("Scope: a `static` is just a `static`") for the `carrick-embed` program
([`superpowers/specs/2026-08-25-carrick-embed-program-design.md`](superpowers/specs/2026-08-25-carrick-embed-program-design.md),
Phase B). Taken at `3dc6cc72` on 2026-08-25 with

```sh
rg -n 'static [A-Z_]+:|OnceLock|std::env::var' crates/carrick-runtime/src crates/carrick-kernel/src \
  | grep -vE '^[^:]+:[0-9]+:\s*//'
```

(228 matching lines after dropping comment-only hits; re-checked at
`ea0dac4c`, where only the `dispatch/mod.rs` rows moved, by +49 lines). Every
row was read at its line, not inferred from the grep. Two verdicts:

- **container-state** — models one Linux container's state and MUST move onto
  the kernel-graph `Container` (`crates/carrick-runtime/src/kernel/container.rs`).
  Correct while exactly one container exists in the carrier; aliases the
  moment a second one does.
- **carrier-infra** — describes the host process, the HVF VM, a host kernel
  object keyed by host fd/path, a monotonic id allocator, a debug hatch, or
  test scaffolding. Stays process-scoped. It must never be *read as* container
  state; where its VALUE is per-run today (the run id in the process title) the
  source moves to `LaunchContext` and the static keeps its carrier scope.

The phase column names the plan cluster that moves the row: **B1** (this
census + `Container` identity, Task 15), **B2** (pid region, the arena
singleton, run identity, the SysV IPC scope; Tasks 16–19), **B3** (the
`ClockDomain` realtime offset + epoch, granted caps, UTS/net namespaces;
Tasks 20–21). Adjacent-crate rows the survey named are listed last for
completeness.

## Container-state (must move into `Container`)

| file:line | static / env read | what it models | Phase-B destination |
|---|---|---|---|
| `crates/carrick-runtime/src/namespace/pid.rs:69` | `static REGION: AtomicPtr<ProcessSection>` | the active PID-namespace process section (ns-pid allocator, member table) | `Container.pid_ns: OnceLock<Arc<NsSharedRegion>>` (`install_pid_ns`/`pid_region`), allocated per container from the per-carrier `KernelArena::global()` — **B2** (Task 15's `pid_root: OnceLock<TaskKey>` stays beside it; both fields exist) |
| `crates/carrick-runtime/src/namespace/pid.rs:75` | `static REQUESTED: AtomicBool` | "this run wants private PID placement" (written by `Runtime::execute`, read by the run loop) | `RunSpec.pid` read at prepare; the static is deleted — **B2** |
| `crates/carrick-runtime/src/namespace/pid.rs:113` | `std::env::set_var(ARENA_PATH_ENV, path)` in `attach_region` | the arena file a `carrick exec` joiner attaches | dead: nothing sets `CARRICK_JOIN_REGION` (`rg JOIN_REGION crates scripts` → only the read at `execute.rs:224` and the census row for it in `scripts/migrate/host-authority-transition-inventory.json`); `attach_region`/`join_existing` and the `CARRICK_JOIN_REGION` branch are deleted in **B1** Task 15 (the only cluster that deletes them) |
| `crates/carrick-runtime/src/namespace/pid.rs:127,133` | `CARRICK_CONTAINER_ID`, `ARENA_PATH_ENV` in `persist_detached_arena_path` | which registry entry records this container's arena path | `LaunchContext.registry_id`; `ARENA_PATH_ENV` itself is deleted with the by-path arena constructors — **B2** |
| `crates/carrick-runtime/src/dispatch/mod.rs:7480` (`ea0dac4c`: 7529) | `static GUEST_REALTIME_OFFSET_NS: AtomicI64` | the guest's `CLOCK_REALTIME` offset (`clock_settime`, `settimeofday`); A1 keeps it here (it is NOT relocated to `carrick_mem`) and adds the per-MM vvar epoch re-stamp around it | `Container.clock: Arc<ClockDomain>` — offset AND epoch (`ClockDomain::{set_realtime_offset_ns, epoch}`) — **B3** (object introduced, offset-only, in B1 Task 15) |
| `crates/carrick-runtime/src/namespace/process.rs:198` | `static LAUNCH_GRANTED_CAPS: AtomicU64` | the `--cap-add` grant every process in the container starts from | `Container.granted_caps: CapabilitySet` — **B3** |
| `crates/carrick-runtime/src/kernel/netns.rs:210` | `static ROOT: OnceLock<Arc<NetNs>>` (`root_net_ns`) | the container's initial network namespace; `publish_root_net_view` writes the run's addresses into it | `Container.net_ns: Arc<NetNamespace>` (`Container::net_ns()`); `NsProxy::for_container` seeds from the container; the OnceLock is deleted — **B3** |
| `crates/carrick-runtime/src/kernel/netns.rs:227` | `static ROOT: OnceLock<Arc<UtsNs>>` (`root_uts_ns`) | the container's initial UTS namespace (`--hostname` lands here via `publish_root_nodename`) | `Container.uts_ns: Arc<UtsNamespace>` (`Container::uts_ns()`, `Container::set_hostname` from `RunSpec.hostname`; `publish_root_nodename` becomes per-container); the OnceLock is deleted — **B3** (this is what makes B4's distinct-hostnames Gate B passable) |
| `crates/carrick-runtime/src/execute.rs:82` | `CARRICK_CONTAINER_ID` in `detached_stable_scratch` | which registry entry owns the stable overlay | `LaunchContext.registry_id` — **B1** Task 15 |
| `crates/carrick-runtime/src/execute.rs:224` | `CARRICK_JOIN_REGION` | `carrick exec` joining a live region | dead (no setter in the tree); branch deleted — **B1** Task 15 |
| `crates/carrick-runtime/src/execute.rs:265` | `CARRICK_EXEC_OVERLAY` | the overlay to ATTACH instead of extract | `LaunchContext.exec_overlay` — **B1** Task 15 |
| `crates/carrick-runtime/src/runtime.rs:624` | `CARRICK_CONTAINER_ID` (fallback `container::mark_exited`) | which registry entry receives the exit code | `Container.launch().registry_id` — **B2** |
| `crates/carrick-runtime/src/runtime.rs:693,719-720` | `ARENA_PATH_ENV` presence; `CARRICK_RUN_ID` / `CARRICK_CONTAINER_ID` (`kernel_arena_run_scope`) | the per-run arena directory name | deleted by **B2**: the arena becomes the lazy `KernelArena::global()` singleton over an unlinked temp file, so there is no scope path to name; the `pid-<pid>` run-id fallback survives only in `LaunchContext::from_process_env` (B1 Task 15) |
| `crates/carrick-runtime/src/threaded_loop.rs:351-352` | `CARRICK_CONTAINER_ID`, `CARRICK_LAUNCH_AUTHORIZATION` → `ManagedCarrierControl::start` | which registry entry this carrier is authorized to become | `LaunchContext.registry_id` / `.launch_authorization` — **B2** |
| `crates/carrick-runtime/src/dispatch/sysv.rs:867,884-885` | `static SYSV_FALLBACK_ROOT_PID`; `CARRICK_RUN_ID` / `CARRICK_CONTAINER_ID` (`sysv_run_scope`) | the SysV IPC namespace's on-disk scope | **B2** Task 16 replaces `sysv_run_scope` with `task.container().run_id().scope_component()` (the sanitizer lifted into `RunId::scope_component` by B1 Task 15) |
| `crates/carrick-runtime/src/kernel/debug/endpoint.rs:131` | `CARRICK_RUN_ID` (`DebugEndpoint::for_current_run`) | the run this debug endpoint rendezvouses for | `RunId` from the root container's `LaunchContext` — **B2** (the server at `kernel/debug/server.rs:42` stays carrier-infra: one kernel per carrier) |

## Carrier-infra (stays process-scoped)

### Source value is per-run today; only the SOURCE moves

| file:line | static / env read | note |
|---|---|---|
| `crates/carrick-runtime/src/dispatch/proctitle.rs:66,71` | `static RUN_ID: OnceLock<Option<String>>` seeded from `CARRICK_RUN_ID` | the host process TITLE is a carrier fact (`ps` sees one process); the id it embeds comes from the first container's `LaunchContext` after **B2**. Not a container object. |
| `crates/carrick-kernel/src/arena.rs:25,370` | `static GLOBAL: OnceLock<KernelArena>`; `ARENA_PATH_ENV` in `create_or_attach_from_env` | the arena is a carrier singleton by design (spec Phase B); **B2** makes `KernelArena::global()` its sole constructor (lazy, over an unlinked temp file) and deletes `init_global`/`create_or_attach_from_env`/`ARENA_PATH_ENV` and the `set_var` at `runtime.rs:713`. `arena.rs:24 ARENA_FILE_COUNTER` is its id allocator. |
| `crates/carrick-runtime/src/dispatch/pty_registry.rs:32` | `static MASTERS: LazyLock<Mutex<HashMap<u32, (i32, FileDescriptionId)>>>` | pts index → master. carrier-infra, unchanged in Phase B: the pts index space is the host devpts the carrier opened `/dev/ptmx` on, keyed by a host fd; a per-container devpts INSTANCE is a mount-table concern (Phase E), not a Phase-B move. No B-cluster gate depends on it. |

### Host-process / VM / HVF (spec: "must never alias one container")

| file:line | static | note |
|---|---|---|
| `crates/carrick-runtime/src/pty_relay.rs:76` | `WINCH_PIPE_WRITE: AtomicI32` | SIGWINCH self-pipe; host signal disposition |
| `crates/carrick-runtime/src/deadlock_watchdog.rs:25-27,31,54-56` | `LOCAL_TICKED`, `ARMED`, `CAPTURE_CLAIMED`, `COUNTER`, `CELL` (+ `CARRICK_DEADLOCK_WATCHDOG_MS`) | carrier progress word; host safety deadline stays on real time (Phase F) |
| `crates/carrick-runtime/src/dispatch/time.rs:1060-1078` | `setrlimit(RLIMIT_NOFILE)` raise (no static) | host fd budget of the carrier |
| `crates/carrick-runtime/src/dispatch/time.rs:1081,1085` | `RLIMIT_CPU_GENERATION`, `RLIMIT_CPU_FORK_GATE` | host-fork-era gate; candidate for deletion now that no host fork exists (not a container object) |
| `crates/carrick-runtime/src/lib.rs:294` | `VCPU_LIVE: AtomicI64` | vCPU census of the carrier |
| `crates/carrick-runtime/src/lib.rs:1637,1720,1747` | timer-delivery `OnceLock` cells | backend timer transport (HVF/KVM), one per carrier |
| `crates/carrick-runtime/src/vcpu_loop/mod.rs:74-78` | `VCPU_RECLAIM*` | vCPU lease statistics |
| `crates/carrick-runtime/src/dispatch/mod.rs:3700` (`ea0dac4c`: 3749) | `HVPATCH_LANE: AtomicBool` | lane fact of the carrier |
| `crates/carrick-runtime/src/host_tty.rs:882` | `SAVED_TERMIOS` | host termios save/restore for the carrier's fds |
| `crates/carrick-runtime/src/kernel/tty.rs:19` | `SLOT: OnceLock<Mutex<DeliveryState>>` | pre-route controlling-tty delivery for the one kernel |
| `crates/carrick-runtime/src/kernel/debug/server.rs:42,119` | `INSTALLED` (+ `CARRICK_KERNEL_DEBUG=0`, const at :46) | one kernel debug server per carrier |
| `crates/carrick-runtime/src/event_ring.rs:53-56,205-206` | `RING`, `IDX`, `WATCHDOG`, `NEXT_HVPWAIT_ID`, `DIR` (`CARRICK_EVENTRING`) | the always-on carrier event ring (spec: authoritative ring lives in the carrier) |
| `crates/carrick-runtime/src/run_state.rs:175` | `MY_SLOT` | this host process's run-state record |
| `crates/carrick-runtime/src/eventfd_shm.rs:39` | `SLAB` | MAP_SHARED eventfd counters (host-fork era; per carrier) |
| `crates/carrick-runtime/src/cred_ipc.rs:42` | `LAST_PUBLISHED` | host-pid-keyed credential projection cache (host-fork era) |
| `crates/carrick-runtime/src/exec_stamps.rs:137,236` | `FORK_LINK_SEQUENCE` (+ `CARRICK_EXEC_STAMPS`) | host-process fork-attempt ids (diagnostic) |
| `crates/carrick-runtime/src/fs_resolve_cache.rs:40` | `CELL: OnceLock<usize>` MAP_SHARED generation page | carrier-wide path/topology generation; a per-container mount table (Phase E) invalidates through it, it is not container state itself. Its one-time `fs_resolve_cache::init()` moves from the CLI into `Runtime::prepare` in C2 Task 28. |
| `crates/carrick-runtime/src/fs_backend.rs:2263` | `SENDER` scratch-cleanup thread | one cleanup worker per carrier |
| `crates/carrick-runtime/src/container.rs:507` | `STRIPES` lifecycle-lock stripes | on-disk lifecycle registry locking (not the kernel-graph `Container`) |
| `crates/carrick-runtime/src/vfs/proc.rs:397` | `OOM_SCORE_ADJ_SINGLE_PROCESS` | single-host-process lane cell; HVPatch authority is `Task::oom_score_adj` — candidate for deletion, not container state |
| `crates/carrick-runtime/src/vfs/proc.rs:460` | `BOOT_ID` | `/proc/sys/kernel/random/boot_id` is per KERNEL boot; containers share the kernel |
| `crates/carrick-runtime/src/vfs/proc.rs:3881-3882` | `AARCH64_CACHE`, `X86_64_CACHE` | rendered `/proc/cpuinfo` text caches |
| `crates/carrick-runtime/src/dispatch/perf.rs:147` | `BASE: OnceLock<Instant>` | perf-event wall base; routes through `ClockDomain` in Phase F, stays one instant per carrier |
| `crates/carrick-runtime/src/runtime.rs:1950,1963` | rosetta bytes/blob `CACHE` | host Rosetta binary cache |
| `crates/carrick-runtime/src/execute.rs:159` | `SHOWN` | one-per-process Rosetta notice |
| `crates/carrick-runtime/src/apfs.rs:283` | `CACHE: OnceLock<PathBuf>` | host scratch volume root |
| `crates/carrick-runtime/src/layer_cache.rs:449` | `FALLBACK_FLAGGED: Once` | one-per-process probe notice |
| `crates/carrick-runtime/src/binfmt.rs:87` | `REGISTRATIONS: &[BinfmtRegistration]` | const table |
| `crates/carrick-runtime/src/dtrace_consumer.rs:312` | `STDOUT_FP` | libc extern |
| `crates/carrick-runtime/src/network/socket_namespace.rs:1245,1683,1869` | `SWEPT`, `INSTANCE`, `WARNED` | one-per-process sweep / instance id / notice |

### Host-kernel-object tables keyed by host fd or host path

| file:line | static | note |
|---|---|---|
| `crates/carrick-runtime/src/dispatch/net/recverr.rs:77,82` | `STATE`, `BOUND` | keyed by host fd / host `addr:port`; the host's own scope |
| `crates/carrick-runtime/src/dispatch/net/reuseport.rs:104` | `GROUPS` | Linux scopes reuseport groups per net-ns; host sockets make carrier scope the only realizable one today — Phase H revisits |
| `crates/carrick-runtime/src/dispatch/net/sctp.rs:48` | `STREAMS` | host-socket keyed |
| `crates/carrick-runtime/src/dispatch/net/support.rs:1474` | `REG` (unix path registry) | keyed by host path; per-container scratch dirs already partition it |
| `crates/carrick-runtime/src/dispatch/fifo_beacon.rs:48` | `STATE` | keyed by host `(dev, ino)` |
| `crates/carrick-runtime/src/dispatch/epoll_shim.rs:9` | `GLOBAL_EPOLL_WAKE_FDS` | host fds |
| `crates/carrick-runtime/src/dispatch/mod.rs:9212` | `AR_MAGIC_WRITES` | host-fd keyed archive-write forensics |

### Monotonic id / generation allocators (carrier-wide by design, like `alloc_ns_id`)

`namespace/process.rs:300 NEXT_NS_ID`; `kernel/objects.rs:33 NEXT_FILE_SLOT_GENERATION`; `kernel/ids.rs:10 NEXT_FILE_DESCRIPTION_ID`; `vcpu_loop/continuation.rs:32-35 NEXT_CONTINUATION_ID/NEXT_REGISTRATION_GENERATION/NEXT_RESOURCE_GENERATION/NEXT_RUNNER_JOB_ID`; `vcpu_loop/mod.rs:160 NEXT_AUTHORITY_ID`, `:702 NEXT_DIRECTORY`; `dispatch/fs/pipe.rs:16 NEXT_PIPE_ID`; `dispatch/mod.rs:769 NEXT_INTERNAL_WAIT`; `dispatch/net/support.rs:171 EPOLL_REG_GEN`, `:1436 CTR`; `dispatch/perf.rs:157 NEXT`; `fs_backend.rs:1526 ANON_FD_COUNTER`, `:1531 SCRATCH_TRASH_COUNTER`; `network/socket_namespace.rs:1413 SEQUENCE`; `dispatch/mod.rs:9214 AR_MAGIC_SEQ`; and, from Task 15, `kernel/container.rs NEXT_CONTAINER_ID`. Uniqueness across the carrier is the property; none is container state.

### Config / debug hatches read from the process environment

All stay host-process configuration. Those marked † are candidates for a `ContainerBuilder` option in Phase C; the rest are debug hatches.

`execute.rs:129 CARRICK_FS_CACHED_LOWER†`, `:160-161 ROSETTA_ACCEPT_ENV / CARRICK_NO_ROSETTA_NOTICE†`, `:652 CARRICK_SEED_APT_MIRRORS†`; `runtime.rs:161 CARRICK_DISABLE_TSO`, `:653 VM_LIFECYCLE_ARTIFACT_PATH_ENV`; `lib.rs:349 CARRICK_ROSETTA_PATH†`; `apfs.rs:299,302 CARRICK_HOME/HOME`; `fs_backend.rs:1879,1888,1902 CARRICK_FAST_FS / CARRICK_FS_STATCACHE / CARRICK_FS_OVERLAY`, `:7161-7163 HOME/TMPDIR`; `dispatch/fs.rs:1401 CARRICK_FS_TRUSTED_LANE`; `dispatch/fs/sendfile.rs:16 CARRICK_DARWIN_COPYFILE_FAST_PATH`; `dispatch/fs/state.rs:297 CARRICK_STRICT_DURABILITY`; `dispatch/mem.rs:1434 CARRICK_MMAP_FILE_BACKED`; `vdso_policy.rs:31-32 CARRICK_DISABLE_VDSO / CARRICK_VDSO_MODE†`; `vcpu_loop/mod.rs:7557 CARRICK_MAX_WALL_MS†`; `kernel/control/endpoint.rs:55 CARRICK_CONTROL_DIR`; `kernel/debug/endpoint.rs:279 BASE_DIR_ENV`; `exec_helpers.rs:409 CARRICK_DEBUG_STOP_ON_SIGNAL`; `core_dump.rs:1326,1407 CARRICK_CORE_EMIT_PATH / _PN_XNUM_PATH`; `dispatch/mod.rs:4754 CARRICK_CORE_FAILPOINT`, `:8610 CARRICK_WATCH_ADDR` (cfg `watchpoint`); `vcpu_loop/mod.rs:339 CARRICK_EXECVE_TRACE`, `:6426 CARRICK_TRACE_TRAPS`, `:6536-6945 CARRICK_CORE_FAILPOINT`; `vcpu_loop/exec.rs:223 CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE`, `:1488 CARRICK_HVPATCH_VERIFY_EXEC_CODE`; `CARRICK_SIG_DEBUG` (`kernel/operations.rs:1892,2015`; `dispatch/proc.rs:3350,3365`; `vcpu_loop/threads.rs:303`; `vcpu_loop/exec.rs:769`; `vcpu_loop/continuation.rs:1543`; `vcpu_loop/mod.rs:848,4895,5369`); `CARRICK_FAULT_DEBUG` (`dispatch/mem.rs:4212,4869`; `vcpu_loop/signal.rs:289`; `vcpu_loop/exec.rs:787`; `vcpu_loop/mod.rs:5935,5961`); `CARRICK_FORK_DEBUG_VA` (`dispatch/mem.rs:491,592,1310,2319,2692`); `CARRICK_MMAP_GRANT_DEBUG` (`dispatch/mem.rs:2295`); `CARRICK_NET_DEBUG` (`dispatch/net.rs:2332,2391,6183,6188,6528,6672,6742`); `CARRICK_SCTP_DEBUG` (`dispatch/net/sctp.rs:90,96,181`); `CARRICK_FICLONE_DEBUG` (`dispatch/fs.rs:4497,8510`); `CARRICK_RUNSTATE_DEBUG` (`run_state.rs:224,589,601`; `crates/carrick-kernel/src/process.rs:351`).

### Thread-locals and test-only cells

Per host thread, never container state: `dispatch/resources.rs:59-63`, `dispatch/lock_order.rs:36`, `fanotify.rs:66`, `dispatch/fs/pathres.rs:20`, `fs_backend.rs:130`, `dispatch/sysv.rs:1395`, `vcpu_loop/signal.rs:357` (each is the cell inside a `thread_local!` that opens one to three lines earlier). `cfg(test)` only: `dispatch/fs.rs:1192,1195`, `vcpu_loop/executor.rs:1284`, `vcpu_loop/mod.rs:2837,2840`, `dispatch/fs/fd_helpers.rs:811`, and the test locks at `host_tty.rs:1232`, `network/socket_namespace.rs:2552`, `dispatch/signal.rs:3612`, `dispatch/time.rs:1356`, `vcpu_loop/signal.rs:702`.

## Adjacent crates the survey named (outside this grep's scope)

| file:line | item | verdict |
|---|---|---|
| `crates/carrick-mem/src/vdso.rs:55` | `static REALTIME_OFF_NS: AtomicU64` (vvar realtime stamp mirror) | container-state: per-container vvar page stamp. A1 leaves the offset static in `dispatch/mod.rs` and exposes the single word function `carrick_mem::vdso::vvar_realtime_off_ns(host_off_ns, delta_ns)`; the VMM stampers keep stamping host calibration only — **B3** re-stamps per container from `Container.clock` (`ClockDomain::publish_vvar_realtime_offset`, `sync_vvar_realtime_offset` keyed on `ClockDomain::epoch`); Phase F adds the mode word |
| `crates/carrick-timer-core/src/posix.rs:94` | `static BASE_INSTANT: OnceLock<Instant>` (the survey's "posix-timer `BASE_INSTANT`"; `now_ns()` stamps every POSIX-timer arm as ns since it) | carrier-infra: the host MONOTONIC reference for timer arm stamps, one instant per carrier exactly like `dispatch/perf.rs:147 BASE`; Phase F routes timer arms through the container's `ClockDomain`, the base instant itself does not become container state |
| `crates/carrick-mem/src/memory.rs:664` | `init_alias_ipa_allocator` (MAP_SHARED alias-IPA counter) | carrier-infra: global-IPA allocator of the one VM; its idempotent one-time call moves from the CLI into `Runtime::prepare` in C2 Task 28 |
| `crates/carrick-vmm-hvf/src/host_signal.rs:1113` | `INSTALLED: AtomicU8` host signal dispositions | carrier-infra (spec) |
| `crates/carrick-hal/src/signal_pump.rs:68` (`:83` installs) | `SIGCHLD_INSTALLED` and the pump's dispositions | carrier-infra (spec) |
| `crates/carrick-signal-core/src/host_glue.rs:87` | routed per-signal `sigaction` installs | carrier-infra (spec) |
| `crates/carrick-runtime/src/dispatch/proctitle.rs:160,170,198,225` | `set_host_process_name` (host argv buffer + `pthread_setname_np` at `:170`) | carrier-infra: names the carrier |
