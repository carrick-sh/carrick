# carrick-embed Plan — Phase B — Container as a kernel-graph object

> Part of [`2026-08-25-carrick-embed-phase-a-c-plan.md`](2026-08-25-carrick-embed-phase-a-c-plan.md); read that index and the spec first. Line numbers verified at `39426141`; quoted existing text is the authority.


<!-- cluster B1-census-and-container -->
## Cluster B1-census-and-container

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 12; notes: Fix 6 vs the draft's run-id precedence: the draft's from_process_env used the registry id as a middle fallback (RUN_ID, else CONTAINER_ID, else pid-<pid>, mirroring kernel_arena_run_scope/sysv_run_scope). The fix text mandates absent/empty CARRICK_RUN_ID -> pid-<pid> directly, so I dropped the registry-id middle step and rewrote the test that asserted it; this is a behaviour change for a detached carrier launched with CARRICK_CONTAINER_ID but no CARRICK_RUN_ID (it now gets pid-<pid> instead of the registry id). The CLI's run_detached_carrier should be checked to confirm it always stamps CARRICK_RUN_ID; if not, the middle step should be restored and the fix text amended. | SyscallDispatcher::container() -> Arc<Container> (infallible, per FINAL SIGNATURES) needs a fallback when nothing was installed; I made it lazily install Container::for_reference_model() and added a pub(crate) installed_container() -> Option<Arc<Container>> for the hvpatch fallback that reads the env fail-closed. This avoids a second std::process::id call (keeps Step 15's delta at exactly +1/-1) but is not in the FINAL SIGNATURES list; the orchestrator may want to add installed_container() there or have B4/C2 use container() only after set_container. | Fix 8 vs FINAL SIGNATURES: the final ClockDomain shows `{ realtime_offset_ns: AtomicI64, epoch: AtomicU64 }` and system()/epoch()/etc.; per fix 8 and fix 11, B1 produces only the realtime_offset_ns skeleton and B3 adds epoch and the rest. I followed the fixes ).

### Task 14: Embed census of process-global container state in `carrick-runtime` / `carrick-kernel`

**Files:**
- Create: `docs/identity-and-scope-domains-embed-census.md`
- Modify: `docs/identity-and-scope-domains.md:95-100` (append a pointer paragraph after the "What the audits found" table, whose last row is line 100)
- Test: grep-based assertions (doc task; no Rust test)

**Interfaces:** Consumes: `docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md` MUST already be committed (it is untracked at `3dc6cc72` and at `ea0dac4c`; the census links it, and a dangling link in a committed doc is a `just doc`-class defect even though rustdoc does not check it — land the Phase A spec commit first or add the spec to this commit). Produces: the census document that Tasks 15–21 (B1 Task 15 `Container` on the kernel graph; B2 Tasks 16–19 pid namespaces / arena; B3 Tasks 20–21 clock, capabilities, UTS/net namespaces) cite for every static they move; the "Phase-B destination" column is the contract for B2/B3.

- [ ] **Step 1: Prove the census does not exist yet (red), and that the spec it links is tracked**

```sh
cd /Volumes/CaseSensitive/carrick
test -f docs/identity-and-scope-domains-embed-census.md; echo "exists=$?"
grep -c 'identity-and-scope-domains-embed-census' docs/identity-and-scope-domains.md; echo "linked=$?"
git ls-files --error-unmatch docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md; echo "spec_tracked=$?"
```
Expected: `exists=1` and `0` / `linked=1` (both red). `spec_tracked` MUST be `0` before Step 6; at `ea0dac4c` it is `1` (untracked) — commit the spec (Phase A) or include it in this task's `git add`.

- [ ] **Step 2: Re-run the census grep and confirm the anchor lines below still hold**

The census cites exact lines. Before writing, confirm every load-bearing anchor still matches (this is the check the adversarial reviewer will run). The loop is pattern-based on purpose: it prints the LIVE `file:line` of each anchor, and the table you write must cite those lines, not the ones below.

```sh
cd /Volumes/CaseSensitive/carrick
# Comment-only hits are filtered on the text AFTER the `path:line:` prefix
# (a bare `grep -v '^\s*//'` filters nothing against `rg -n` output).
rg -n 'static [A-Z_]+:|OnceLock|std::env::var' crates/carrick-runtime/src crates/carrick-kernel/src | grep -vE '^[^:]+:[0-9]+:\s*//' | wc -l
for t in \
 'crates/carrick-runtime/src/namespace/pid.rs|static REGION: AtomicPtr<ProcessSection>' \
 'crates/carrick-runtime/src/namespace/pid.rs|static REQUESTED: std::sync::atomic::AtomicBool' \
 'crates/carrick-runtime/src/namespace/pid.rs|std::env::var("CARRICK_CONTAINER_ID")' \
 'crates/carrick-runtime/src/namespace/pid.rs|std::env::var_os(ARENA_PATH_ENV)' \
 'crates/carrick-runtime/src/dispatch/mod.rs|static GUEST_REALTIME_OFFSET_NS' \
 'crates/carrick-runtime/src/namespace/process.rs|static LAUNCH_GRANTED_CAPS' \
 'crates/carrick-runtime/src/kernel/netns.rs|static ROOT: OnceLock<Arc<NetNs>>' \
 'crates/carrick-runtime/src/kernel/netns.rs|static ROOT: OnceLock<Arc<UtsNs>>' \
 'crates/carrick-runtime/src/execute.rs|std::env::var("CARRICK_CONTAINER_ID")' \
 'crates/carrick-runtime/src/execute.rs|std::env::var("CARRICK_JOIN_REGION")' \
 'crates/carrick-runtime/src/execute.rs|std::env::var("CARRICK_EXEC_OVERLAY")' \
 'crates/carrick-runtime/src/runtime.rs|std::env::var("CARRICK_CONTAINER_ID")' \
 'crates/carrick-runtime/src/runtime.rs|std::env::var_os(carrick_kernel::arena::ARENA_PATH_ENV)' \
 'crates/carrick-runtime/src/runtime.rs|std::env::var("CARRICK_RUN_ID")' \
 'crates/carrick-runtime/src/threaded_loop.rs|std::env::var("CARRICK_CONTAINER_ID")' \
 'crates/carrick-runtime/src/threaded_loop.rs|std::env::var("CARRICK_LAUNCH_AUTHORIZATION")' \
 'crates/carrick-runtime/src/dispatch/sysv.rs|static SYSV_FALLBACK_ROOT_PID' \
 'crates/carrick-runtime/src/dispatch/sysv.rs|std::env::var("CARRICK_RUN_ID")' \
 'crates/carrick-runtime/src/dispatch/proctitle.rs|static RUN_ID: OnceLock<Option<String>>' \
 'crates/carrick-runtime/src/kernel/debug/endpoint.rs|std::env::var("CARRICK_RUN_ID")' \
 'crates/carrick-kernel/src/arena.rs|static GLOBAL: OnceLock<KernelArena>' \
 'crates/carrick-kernel/src/arena.rs|std::env::var_os(ARENA_PATH_ENV)' \
 'crates/carrick-runtime/src/dispatch/pty_registry.rs|static MASTERS' \
 'crates/carrick-runtime/src/fs_resolve_cache.rs|static CELL: std::sync::OnceLock<usize>' \
 'crates/carrick-runtime/src/pty_relay.rs|static WINCH_PIPE_WRITE' \
 'crates/carrick-runtime/src/deadlock_watchdog.rs|static ARMED' \
 'crates/carrick-runtime/src/dispatch/time.rs|libc::setrlimit(libc::RLIMIT_NOFILE' \
 'crates/carrick-runtime/src/vfs/proc.rs|static OOM_SCORE_ADJ_SINGLE_PROCESS' \
 'crates/carrick-runtime/src/dispatch/mod.rs|static HVPATCH_LANE' \
 'crates/carrick-timer-core/src/posix.rs|static BASE_INSTANT' \
 ; do f=${t%%|*}; p=${t#*|}; hits=$(grep -nF -- "$p" "$f" | cut -d: -f1 | tr '\n' ' '); [ -n "$hits" ] && echo "ok   $f:${hits}-> $p" || echo "MISS $f -> $p"; done
```
Expected: `228` matching lines (the count at `3dc6cc72` and at `ea0dac4c`; any other number means the tree moved — re-run the grep and refresh the table before writing), and every one of the 30 anchors prints `ok` with its live line(s). At `3dc6cc72` the lines are the ones cited in the table below; at `ea0dac4c` only `dispatch/mod.rs` moved (+49: `GUEST_REALTIME_OFFSET_NS` 7480→7529, `HVPATCH_LANE` 3700→3749). A `MISS` means the tree moved under the census — fix the row, do not ship a stale citation. NOTE: Phase A lands before this task (A1 adds `realtime_duration` callers around `GUEST_REALTIME_OFFSET_NS` in `dispatch/mod.rs`, mqueue, sysv and proc; A5 deletes `--raw`), so the `dispatch/mod.rs` anchors WILL have moved again by the time you run this — the loop prints the live lines; cite those.

- [ ] **Step 3: Write the census document**

Create `docs/identity-and-scope-domains-embed-census.md` with exactly this content (the tables are the deliverable; keep them complete; substitute the live line numbers Step 2 printed where they differ):

````markdown
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
````

- [ ] **Step 4: Link the census from the parent document**

In `docs/identity-and-scope-domains.md`, the audit table ends with this exact line (line 100; the table spans lines 95–100):

```markdown
| address space | 4 sites + 1 missing capability | `/proc/<pid>/mem` returned the caller's memory |
```

Insert immediately after it (before the blank line and "Two are worth stating in full…"):

```markdown

The carrier-global row is re-counted per static for the embed program in
[`identity-and-scope-domains-embed-census.md`](identity-and-scope-domains-embed-census.md):
every `static`/`OnceLock`/`std::env::var` in `carrick-runtime` and
`carrick-kernel`, classified container-state versus carrier-infra, each with
its Phase-B destination.
```

- [ ] **Step 5: Verify (green)**

```sh
cd /Volumes/CaseSensitive/carrick
test -f docs/identity-and-scope-domains-embed-census.md && echo exists
grep -c 'identity-and-scope-domains-embed-census' docs/identity-and-scope-domains.md
for sym in GUEST_REALTIME_OFFSET_NS LAUNCH_GRANTED_CAPS 'static REGION' 'static REQUESTED' root_uts_ns root_net_ns CARRICK_EXEC_OVERLAY CARRICK_LAUNCH_AUTHORIZATION CARRICK_JOIN_REGION ARENA_PATH_ENV 'GLOBAL: OnceLock<KernelArena>' WINCH_PIPE_WRITE RLIMIT_NOFILE BASE_INSTANT; do grep -qF "$sym" docs/identity-and-scope-domains-embed-census.md && echo "ok $sym" || echo "MISSING $sym"; done
git ls-files --error-unmatch docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md >/dev/null && echo spec_tracked
```
Expected: `exists`, `1`, fourteen `ok` lines, and `spec_tracked` (if it is not, add the spec to the commit below).

- [ ] **Step 6: Commit**

```sh
cd /Volumes/CaseSensitive/carrick
git add docs/identity-and-scope-domains-embed-census.md docs/identity-and-scope-domains.md
# Only if Step 5 did not print spec_tracked:
# git add docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md
git commit -m "docs(runtime): census per-container statics for the embed program

Why: Phase B of the carrick-embed design puts a Container object on the
kernel graph and moves every static that models ONE container's state
onto it. The 2026-08-16 identity/scope audit counted 11 of 197 statics
as carrier-global but did not list them, so B2/B3 had no contract for
what moves and what stays. Under HVPatch each of these cells is correct
while exactly one container exists and aliases the moment a second one
appears, and the single-process smoke lane cannot see that class.

What: docs/identity-and-scope-domains-embed-census.md lists every
static/OnceLock/std::env::var line in carrick-runtime and carrick-kernel
at 3dc6cc72 (228 non-comment lines), classified container-state (pid
region and REQUESTED, GUEST_REALTIME_OFFSET_NS, LAUNCH_GRANTED_CAPS, the
root net/UTS OnceLocks, the CARRICK_* identity env reads, the SysV run
scope) versus carrier-infra (host signal dispositions, SIGWINCH pipe,
deadlock watchdog, RLIMIT_NOFILE, the KernelArena singleton, the devpts
master table, host-fd-keyed tables, id allocators, debug hatches), each
with its Phase-B destination: pid region / arena / SysV scope to B2,
clock domain / granted caps / UTS+net namespaces to B3. It also records
that CARRICK_JOIN_REGION has no setter anywhere in the tree, and
classifies the survey's posix-timer BASE_INSTANT
(carrick-timer-core/src/posix.rs) as the carrier's monotonic base, not
container state. identity-and-scope-domains.md links the census from its
audit table.

Verified: every cited file:line re-read by hand; the anchor loop in the
plan's Step 2 prints ok for all 30 load-bearing rows.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 15: `Container` on the kernel graph, `LaunchContext`, and one container per run

**Files** (line numbers as of `3dc6cc72`; where the current HEAD `ea0dac4c` differs it is given in parentheses — anchor on the quoted text, not the number; Phase A (Tasks 1–13) lands before this task, so re-derive every anchor against the post-Phase-A tree):
- Create: `crates/carrick-runtime/src/kernel/container.rs`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs:6-20,32-46` (module + re-exports)
- Modify: `crates/carrick-runtime/src/kernel/netns.rs:28,144-190` (`NsProxy` carries the container)
- Modify: `crates/carrick-runtime/src/kernel/objects.rs:30,2809-2848,3029-3031,6690-6724` (`ea0dac4c`: 30, 2813-2852, 3033-3035, 6689-6728) (`Task::new` takes the container; `Task::container`; test fixture)
- Modify: `crates/carrick-runtime/src/kernel/core.rs:8-18,71-93,269-307,313-338,794-909,1593-1611,1645-1660` (`RootBootstrap.container`, `Kernel.containers`, `bootstrap_root`, `KernelContext::container`, `KernelError` variants, tests)
- Modify: `crates/carrick-runtime/src/kernel/operations.rs:619-626` (`ea0dac4c`: 639-646) (fork passes the parent's container)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:2570-2575,4231-4232,4403-4404,4548-4555` (`ea0dac4c`: 2619-2624, 4280-4281, 4452-4453, 4597-4604) (`container` slot on the dispatcher)
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs:1179-1187` (`ea0dac4c`: 1296-1304, inside `initialize_root_process` at 1282) (root bootstrap takes the dispatcher's container). NOTE: this file has THREE `RootBootstrap::with_mm_backend` sites — `"hvpatch-test-root"` (:56), `"hvpatch-root"` (:1179 / :1296) and `"adapter-root"` (:1560 / :1736). Only the `"hvpatch-root"` one changes; the other two keep the reference-model default container.
- Modify: `crates/carrick-runtime/src/execute.rs:74-92,196-236,264-286,321-324,424` (build one `LaunchContext` and one `Arc<Container>`, delete the dead `CARRICK_JOIN_REGION` branch, install the container on the dispatcher)
- Modify: `crates/carrick-runtime/src/namespace/pid.rs:101-118,604-617` (delete dead `attach_region` / `join_existing` — this task is the ONLY cluster that deletes them; B2 Tasks 16–19 and C2 Task 28 do not touch them)
- Modify: `scripts/migrate/host-authority-transition-inventory.json`, `scripts/migrate/host-authority-macos-capture.json` (reconcile the coordinate-keyed host-authority census — Step 15)
- Test: `crates/carrick-runtime/src/kernel/core.rs` (tests module), `crates/carrick-runtime/src/kernel/objects.rs` (tests module), `crates/carrick-runtime/src/kernel/container.rs` (tests module); run with `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::` (the exact per-crate line `just test` runs, `justfile:196`), then `just test`

**Interfaces:**
- Consumes: `crate::kernel::objects::TaskKey`; `crate::run_result::RuntimeError::Configuration(String)` (`run_result.rs:49`); `crate::container::is_safe_id(&str) -> bool` (`container.rs:319`, rejects the empty string); `crate::kernel::netns::{root_net_ns, root_uts_ns}` (still OnceLocks until B3 Tasks 20–21 move them onto `Container`); `parking_lot::{Mutex, RwLock}`; `camino::Utf8PathBuf` (already a `carrick-runtime` dependency, `Cargo.toml:120`).
- Produces (all `pub` under `carrick_runtime::kernel`, re-exported from `kernel/mod.rs`; these are the FINAL shared names — B2 Tasks 16–19, B3 Tasks 20–21, B4 Tasks 22–23, C2 Tasks 28–29 and C3 Tasks 30–31 consume them as written):
  - `pub struct ContainerId(u64)` with `pub fn allocate() -> Self`, `pub const fn raw(self) -> u64`
  - `pub struct RunId(String)` with `pub fn new(stamp: impl Into<String>) -> Self`, `pub fn as_str(&self) -> &str`, `pub fn scope_component(&self) -> String` (consumed by B2 Task 16, which replaces `dispatch::sysv::sysv_run_scope` with `task.container().run_id().scope_component()`; `runtime::kernel_arena_run_scope` is deleted by B2 and has no successor)
  - `pub struct RegistryContainerId(String)` with `pub fn new(id: impl Into<String>) -> Result<Self, RuntimeError>`, `pub fn as_str(&self) -> &str`
  - `pub struct LaunchAuthorization(String)` with `pub fn new(ticket: impl Into<String>) -> Self`, `pub fn ticket(&self) -> &str`
  - `#[derive(Clone, Debug, Eq, PartialEq)] pub struct LaunchContext { pub container_id: ContainerId, pub run_id: RunId, pub exec_overlay: Option<camino::Utf8PathBuf>, pub launch_authorization: Option<LaunchAuthorization>, pub registry_id: Option<RegistryContainerId> }` with `pub fn unmanaged(run_id: RunId) -> Self` (allocates the `ContainerId`; `exec_overlay`/`launch_authorization`/`registry_id` = `None` — C3 Task 30's `embedded_launch_context()` builds through this, never a struct literal), `pub fn from_process_env() -> Result<Self, RuntimeError>` (absent OR empty `CARRICK_RUN_ID` → `RunId::new(format!("pid-{}", std::process::id()))`; `registry_id` from `CARRICK_CONTAINER_ID` only when set; `exec_overlay`/`launch_authorization` from env only when set; `Err` ONLY on an unsafe `CARRICK_CONTAINER_ID` — so it SUCCEEDS with no identity env at all, which is what C2 Task 28's foreground/in-lib tests, B4 Task 22's `Runtime::execute` and this task's `run-elf` fallback rely on), and `pub fn registry_id(&self) -> Option<&str>` (delegates to `RegistryContainerId::as_str`; consumed by C2 Task 28)
  - `#[derive(Debug, Default)] pub struct ClockDomain { realtime_offset_ns: AtomicI64 }` with `pub fn realtime_offset_ns(&self) -> i64`, `pub fn set_realtime_offset_ns(&self, delta_ns: i64)` — the SKELETON in B3's shape; B3 Tasks 20–21 add `epoch: AtomicU64` (`set_realtime_offset_ns` bumps it; `epoch()`), `system()`, `realtime_base_now`, `realtime_now`, `publish_vvar_realtime_offset`, and rewire `GUEST_REALTIME_OFFSET_NS` to it. Nothing reads this cell in B1.
  - `pub struct Container { /* private */ }` with `pub(crate) fn new(launch: LaunchContext) -> Container`, `pub fn for_reference_model() -> Container` (un-`Arc`'d so B3 can chain `.with_launch_capabilities(..)`; the caller wraps in `Arc`), `pub fn id(&self) -> ContainerId`, `pub fn run_id(&self) -> &RunId`, `pub fn launch(&self) -> &LaunchContext`, `pub fn pid_root(&self) -> Option<TaskKey>`, `pub(super) fn publish_pid_root(&self, key: TaskKey) -> Result<(), KernelError>`, `pub fn clock(&self) -> &Arc<ClockDomain>` (field `clock: Arc<ClockDomain>` — `Arc` because B3's `TimerFdState::new(clock: Arc<ClockDomain>, ..)` holds the domain with no `KernelContext`). B2 adds `pid_ns: OnceLock<Arc<NsSharedRegion>>` beside `pid_root` (both fields exist); B3 adds `granted_caps`, `uts_ns`, `net_ns`; B4 Task 22 adds `retire`.
  - `impl Kernel { pub fn root_container(&self) -> &Arc<Container>; pub fn container(&self, id: ContainerId) -> Option<Arc<Container>>; pub fn create_container(&self, container: Arc<Container>) -> Result<(), KernelError>; pub fn container_count(&self) -> usize }` (`create_container` registers a caller-built `Arc<Container>`; `DuplicateContainer` on repeat)
  - `impl RootBootstrap { pub fn with_container(self, container: Arc<Container>) -> Self }` (B3 Task 20 consumes this for its reference-model chaining)
  - `impl KernelContext { pub fn container(&self) -> Arc<Container> }`; `impl Task { pub fn new(key, parent, process_group, session, shared, process_credentials, container: Arc<Container>) -> Self; pub fn container(&self) -> Arc<Container> }`
  - `impl NsProxy { pub(crate) fn for_container(container: Arc<Container>) -> Self; pub(crate) fn container(&self) -> &Arc<Container> }` (the `Default` impl is removed)
  - `KernelError::{DuplicateContainer(ContainerId), ContainerRootAlreadyPublished(ContainerId)}` (no exhaustive `match` over `KernelError` exists in the tree at `3dc6cc72`/`ea0dac4c` — only `Err(KernelError::X(_))` patterns in `kernel/exec.rs:986` and `dispatch/mod.rs:4358` — so adding variants breaks nothing)
  - `impl SyscallDispatcher { pub fn set_container(&self, container: Arc<Container>); pub fn container(&self) -> Arc<Container>; pub(crate) fn installed_container(&self) -> Option<Arc<Container>> }` (B2 Task 16's `container.install_pid_ns`, B3 and B4 Task 22's `dispatcher.container()` read this slot; `execute.rs` builds `let container = Arc::new(Container::new(launch))` BEFORE the `SyscallDispatcher` and installs it)
  - The `HA-000536` inventory row retirement and the ONE new `HA-CATALOG-PROCESS-ID` row (`from_process_env`) — Step 15.

- [ ] **Step 1: Write the failing kernel-graph tests (red)**

Append to the `mod tests` in `crates/carrick-runtime/src/kernel/core.rs` (after the `root_adapter_preserves_observed_pid_and_all_associations` test, i.e. after the line `    }` that closes it, around line 1690):

```rust
    /// Two containers on ONE kernel. With one container every id in the
    /// carrier coincides and aliasing is invisible; the second one is what
    /// makes `ContainerId` a real domain.
    #[test]
    fn containers_in_one_kernel_have_distinct_ids() {
        let (kernel, _context) = bootstrap(4400);
        let first = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new("first"))));
        let second = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "second",
        ))));
        kernel
            .create_container(Arc::clone(&first))
            .expect("first container");
        kernel
            .create_container(Arc::clone(&second))
            .expect("second container");

        assert_ne!(first.id(), second.id());
        assert_ne!(first.id(), kernel.root_container().id());
        assert_ne!(second.id(), kernel.root_container().id());
        assert_eq!(kernel.container_count(), 3);
        assert!(Arc::ptr_eq(
            &kernel.container(first.id()).expect("registered"),
            &first
        ));
        assert!(matches!(
            kernel.create_container(Arc::clone(&first)),
            Err(KernelError::DuplicateContainer(id)) if id == first.id()
        ));
    }

    /// A captured syscall context reaches its container THROUGH its task —
    /// there is no static to consult, so a second container cannot alias it.
    #[test]
    fn kernel_context_resolves_its_own_container() {
        let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "root-run",
        ))));
        let bootstrap = RootBootstrap::for_reference_model(
            4401,
            ThreadId::synthetic_for_tests(4401),
            "root".to_string(),
        )
        .expect("root bootstrap input")
        .with_container(Arc::clone(&container));
        let (kernel, context) = Kernel::bootstrap_root(bootstrap).expect("root kernel");

        let resolved = context.container();
        assert!(Arc::ptr_eq(&resolved, kernel.root_container()));
        assert!(Arc::ptr_eq(&resolved, &container));
        assert_eq!(resolved.run_id().as_str(), "root-run");
        assert_eq!(resolved.pid_root(), Some(context.task().key()));
        assert_eq!(kernel.container_count(), 1);
    }
```

Append to the `mod tests` in `crates/carrick-runtime/src/kernel/objects.rs`, directly after the `fork_shares_the_uts_namespace_and_unshare_copies_it` test (`objects.rs:6855` at `3dc6cc72`, `:6859` at `ea0dac4c`):

```rust
    /// Container membership is inherited across fork as a SHARE, exactly like
    /// the network and UTS namespaces: the child holds the parent's `Arc`.
    #[test]
    fn fork_child_inherits_parent_container() {
        let parent = Fixture::new();
        let child = Fixture::new();
        assert_ne!(
            child.task.container().id(),
            parent.task.container().id(),
            "two fresh fixtures are two containers"
        );

        child.task.inherit_fork_attributes_from(&parent.task);

        assert!(
            Arc::ptr_eq(&child.task.container(), &parent.task.container()),
            "a fork child is IN its parent's container, not holding a copy"
        );
    }
```

Run:

```sh
cd /Volumes/CaseSensitive/carrick
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::core::tests::containers_in_one_kernel_have_distinct_ids 2>&1 | grep -E 'error\[E0(433|425|599)\]' | head -3
```
Expected: compile errors naming `Container` / `LaunchContext` / `RunId` (E0433 "failed to resolve" or E0425). The E0599 errors for `create_container` / `container` / `with_container` only appear once name resolution succeeds (rustc stops before type-checking), so seeing E0433 alone is the expected red. Red.

- [ ] **Step 2: Create `kernel/container.rs` (identity, `ClockDomain`, `LaunchContext::unmanaged`)**

```rust
//! The container as a kernel-graph object.
//!
//! Linux has no "container" object; a container is a tree of namespaces plus
//! the run identity that created it. Carrick makes that tree explicit because
//! under HVPatch every guest process is a thread of ONE carrier, so anything
//! that used to be "the run's" — the PID-namespace root, the realtime offset,
//! the `--cap-add` grant, the root net/UTS namespaces — is per-container, and a
//! `static` holding it aliases the moment a second container appears in the
//! carrier (`docs/identity-and-scope-domains-embed-census.md`).
//!
//! Phase B1 (this landing) carries IDENTITY only: the typed [`ContainerId`],
//! the [`RunId`] stamp, the [`LaunchContext`] the CLI built from its process
//! environment, the root task key, and an empty [`ClockDomain`]. Nothing here
//! replaces a static yet — B2 moves the pid region and the SysV IPC scope in;
//! B3 moves the realtime offset + vvar epoch, the granted capabilities and the
//! UTS/net namespaces. Every task reaches its container through its
//! `NsProxy`, never through a static.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use camino::Utf8PathBuf;

use super::objects::TaskKey;
use crate::run_result::RuntimeError;

/// Kernel-graph identity of one container.
///
/// Allocated from a carrier-wide monotonic counter — the same class as
/// [`crate::namespace::process::alloc_ns_id`] — so two containers in one
/// carrier can never share an id. Never derived from a host pid: the carrier
/// pid names the host process, which may hold many of these.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ContainerId(u64);

static NEXT_CONTAINER_ID: AtomicU64 = AtomicU64::new(1);

impl ContainerId {
    /// The next unused id in this carrier. Ids are never recycled.
    pub fn allocate() -> Self {
        Self(NEXT_CONTAINER_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The `CARRICK_RUN_ID` stamp: the operator-visible scope every per-run
/// directory, process title and reaper (`scripts/sudo/kill.sh <run-id>`) keys
/// on.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RunId(String);

impl RunId {
    pub fn new(stamp: impl Into<String>) -> Self {
        Self(stamp.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The stamp as ONE filesystem path component: every character outside
    /// `[0-9A-Za-z_-]` becomes `_`. This is the sanitizer
    /// `runtime::kernel_arena_run_scope` (`runtime.rs:723-731`) and
    /// `dispatch::sysv::sysv_run_scope` (`sysv.rs:895-903`) both apply today —
    /// verified byte-identical at `3dc6cc72` — lifted here so B2 (Task 16)
    /// can route the SysV IPC scope through one function without changing a
    /// single path. (`kernel_arena_run_scope` itself is deleted by B2: the
    /// arena becomes an unlinked temp file with no scope path.)
    pub fn scope_component(&self) -> String {
        self.0
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

/// The 64-hex id of an entry in the on-disk lifecycle registry
/// (`crate::container::ContainerState`) — what `CARRICK_CONTAINER_ID` carries
/// for a detached carrier. Distinct from [`ContainerId`], which names the
/// kernel-graph object: a registry entry is what `carrick ps`/`stop`/`rm`
/// address; a foreground run has none.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RegistryContainerId(String);

impl RegistryContainerId {
    /// Accepts only a bare `[0-9A-Za-z_-]+` token (the CWE-22 guard
    /// `crate::container::is_safe_id` enforces before any path join). Refusing
    /// here is fail-closed: the previous readers silently returned `None` for
    /// an unsafe id and let a later `ContainerState::load` fail instead.
    pub fn new(id: impl Into<String>) -> Result<Self, RuntimeError> {
        let id = id.into();
        if !crate::container::is_safe_id(&id) {
            return Err(RuntimeError::Configuration(format!(
                "CARRICK_CONTAINER_ID {id:?} is not a safe registry id"
            )));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The one-shot launch ticket a detached carrier presents to
/// `ManagedCarrierControl::start` to prove it is the exact re-exec allowed to
/// become its registry entry's carrier (`CARRICK_LAUNCH_AUTHORIZATION`).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LaunchAuthorization(String);

impl LaunchAuthorization {
    pub fn new(ticket: impl Into<String>) -> Self {
        Self(ticket.into())
    }

    pub fn ticket(&self) -> &str {
        &self.0
    }
}

/// Everything the runtime used to read from the process environment to know
/// WHICH container it is running, as one typed value the CLI builds and the
/// runtime consumes. An embedding host application builds it with
/// [`LaunchContext::unmanaged`]; the CLI builds it with
/// [`LaunchContext::from_process_env`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchContext {
    /// Kernel-graph identity of the container this run becomes.
    pub container_id: ContainerId,
    /// The run stamp (`CARRICK_RUN_ID`).
    pub run_id: RunId,
    /// An existing overlay to ATTACH instead of extracting the image
    /// (`CARRICK_EXEC_OVERLAY`; a detached carrier's stable scratch).
    pub exec_overlay: Option<Utf8PathBuf>,
    /// The launch ticket for a managed detached carrier
    /// (`CARRICK_LAUNCH_AUTHORIZATION`).
    pub launch_authorization: Option<LaunchAuthorization>,
    /// The lifecycle-registry entry this run is the carrier of
    /// (`CARRICK_CONTAINER_ID`); `None` for a foreground run.
    pub registry_id: Option<RegistryContainerId>,
}

impl LaunchContext {
    /// A run with no registry entry, no overlay to attach and no launch
    /// ticket: the shape of a foreground `carrick run`, of `run-elf`, of an
    /// embedded `PreparedContainer`, and of every in-crate reference-model
    /// kernel. Allocates a fresh [`ContainerId`].
    pub fn unmanaged(run_id: RunId) -> Self {
        Self {
            container_id: ContainerId::allocate(),
            run_id,
            exec_overlay: None,
            launch_authorization: None,
            registry_id: None,
        }
    }

    /// The lifecycle-registry id as a `&str`, for the callers that key the
    /// on-disk registry (`container::mark_exited`, `ContainerState::load`).
    pub fn registry_id(&self) -> Option<&str> {
        self.registry_id.as_ref().map(RegistryContainerId::as_str)
    }
}

/// The container's time authority. Phase B carries `System` mode only and the
/// realtime offset `clock_settime` moves; Phase F adds the mode word,
/// `Frozen`/`Scaled`/`Deterministic`, and the virtual-time scheduler.
///
/// B1 introduces the object as a skeleton nothing reads yet. B3 (Tasks 20–21)
/// adds the vvar `epoch` (bumped by `set_realtime_offset_ns`), `system()`,
/// `realtime_base_now`/`realtime_now` and `publish_vvar_realtime_offset`, and
/// rewires the carrier-wide `GUEST_REALTIME_OFFSET_NS` static
/// (`dispatch/mod.rs`, kept there by A1) to this cell. It is held in an `Arc`
/// on the container because B3's `TimerFdState` keeps the domain with no
/// `KernelContext` to reach it through.
#[derive(Debug, Default)]
pub struct ClockDomain {
    /// Guest `CLOCK_REALTIME` minus host realtime, in nanoseconds.
    realtime_offset_ns: AtomicI64,
}

impl ClockDomain {
    pub fn realtime_offset_ns(&self) -> i64 {
        self.realtime_offset_ns.load(Ordering::SeqCst)
    }

    pub fn set_realtime_offset_ns(&self, delta_ns: i64) {
        self.realtime_offset_ns.store(delta_ns, Ordering::SeqCst);
    }
}

/// One container on the kernel graph.
///
/// Reached from a task through its `NsProxy` (`Task::container`) and from a
/// syscall through `KernelContext::container`. The kernel owns the table of
/// live containers (`Kernel::container`, `Kernel::create_container`); the
/// caller that builds one (`Runtime::execute`, later `Runtime::prepare`)
/// wraps it in an `Arc` and hands that same `Arc` to the dispatcher, the root
/// bootstrap and the kernel table.
#[derive(Debug)]
pub struct Container {
    id: ContainerId,
    launch: LaunchContext,
    /// The task that is this container's PID-namespace init. Published once,
    /// by the bootstrap that creates the root task. B2 adds the pid-namespace
    /// REGION (`pid_ns`) beside it; the two are different domains (a task key
    /// versus an arena slot) and both stay.
    pid_root: OnceLock<TaskKey>,
    clock: Arc<ClockDomain>,
}

impl Container {
    /// Build a container from its launch identity. `pub(crate)`: the
    /// runtime's entry points (`execute.rs`, `hvpatch::initialize_root_process`,
    /// later `prepare.rs`) construct it; embedders go through `LaunchContext`.
    pub(crate) fn new(launch: LaunchContext) -> Self {
        Self {
            id: launch.container_id,
            launch,
            pid_root: OnceLock::new(),
            clock: Arc::new(ClockDomain::default()),
        }
    }

    /// The container every in-crate reference-model kernel and the
    /// `"hvpatch-test-root"` / `"adapter-root"` bootstraps boot into: an
    /// unmanaged launch with a fixed stamp. Returned un-`Arc`'d so builders
    /// can chain further defaults (B3 adds `with_launch_capabilities`).
    pub fn for_reference_model() -> Self {
        Self::new(LaunchContext::unmanaged(RunId::new("reference-model")))
    }

    pub fn id(&self) -> ContainerId {
        self.id
    }

    pub fn run_id(&self) -> &RunId {
        &self.launch.run_id
    }

    pub fn launch(&self) -> &LaunchContext {
        &self.launch
    }

    /// The container's init task, once bootstrapped.
    pub fn pid_root(&self) -> Option<TaskKey> {
        self.pid_root.get().copied()
    }

    /// Publish the init task. A container has exactly one; a second
    /// publication is a graph error, never a silent overwrite.
    pub(super) fn publish_pid_root(&self, key: TaskKey) -> Result<(), super::KernelError> {
        self.pid_root
            .set(key)
            .map_err(|_| super::KernelError::ContainerRootAlreadyPublished(self.id))
    }

    pub fn clock(&self) -> &Arc<ClockDomain> {
        &self.clock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_ids_are_unique_and_never_a_host_pid() {
        let a = ContainerId::allocate();
        let b = ContainerId::allocate();
        assert_ne!(a, b);
        assert!(b.raw() > a.raw());
    }

    #[test]
    fn run_id_scope_component_matches_the_arena_sanitizer() {
        assert_eq!(RunId::new("abc-123_x").scope_component(), "abc-123_x");
        assert_eq!(RunId::new("a b/c:d").scope_component(), "a_b_c_d");
    }

    #[test]
    fn registry_id_refuses_path_traversal() {
        assert!(RegistryContainerId::new("../../etc").is_err());
        assert!(RegistryContainerId::new("").is_err());
        assert_eq!(
            RegistryContainerId::new("deadbeef").expect("safe id").as_str(),
            "deadbeef"
        );
    }

    #[test]
    fn unmanaged_context_has_no_registry_identity() {
        let launch = LaunchContext::unmanaged(RunId::new("r"));
        assert_eq!(launch.run_id.as_str(), "r");
        assert!(launch.registry_id.is_none());
        assert_eq!(launch.registry_id(), None);
        assert!(launch.exec_overlay.is_none());
        assert!(launch.launch_authorization.is_none());
    }

    #[test]
    fn reference_model_container_is_unmanaged_and_fresh() {
        let a = Container::for_reference_model();
        let b = Container::for_reference_model();
        assert_ne!(a.id(), b.id());
        assert!(a.launch().registry_id.is_none());
        assert_eq!(a.clock().realtime_offset_ns(), 0);
    }

    #[test]
    fn a_container_publishes_its_init_exactly_once() {
        let container = Container::new(LaunchContext::unmanaged(RunId::new("once")));
        assert_eq!(container.pid_root(), None);
        let key = TaskKey {
            id: crate::kernel::TaskId::for_root_bootstrap(77).expect("task id"),
            serial: crate::kernel::ObjectIdRegistry::new()
                .task_serial()
                .expect("serial"),
        };
        container.publish_pid_root(key).expect("first publication");
        assert_eq!(container.pid_root(), Some(key));
        assert!(matches!(
            container.publish_pid_root(key),
            Err(super::super::KernelError::ContainerRootAlreadyPublished(id)) if id == container.id()
        ));
    }
}
```

- [ ] **Step 3: Register the module and re-export**

In `crates/carrick-runtime/src/kernel/mod.rs`, after the existing line

```rust
pub mod clone_plan;
```

add

```rust
pub mod container;
```

and after the existing block

```rust
pub use clone_plan::{
    CloneObjectMode, ClonePlan, ClonePlanError, CloneTaskMode, ForkParentMode, ForkPidfdMode,
    VforkMode,
};
```

add

```rust
pub use container::{
    ClockDomain, Container, ContainerId, LaunchAuthorization, LaunchContext, RegistryContainerId,
    RunId,
};
```

- [ ] **Step 4: `NsProxy` carries the container (`kernel/netns.rs`)**

Replace the import line

```rust
use std::sync::{Arc, OnceLock};
```

with

```rust
use std::sync::{Arc, OnceLock};

use super::container::Container;
```

Replace the whole `NsProxy` struct, its `impl`, and its `impl Default` (lines 144–190, beginning `#[derive(Debug, Clone)]\npub(crate) struct NsProxy {` and ending with the `impl Default for NsProxy { … }` block) with:

```rust
#[derive(Debug, Clone)]
pub(crate) struct NsProxy {
    net: Arc<NetNs>,
    uts: Arc<UtsNs>,
    /// The container this task is a member of — the slot Linux's `nsproxy`
    /// reserves for `pid_ns_for_children`/`mnt_ns`, generalized to the
    /// kernel-graph object that owns this task's pid-namespace root, rootfs,
    /// clock domain and run identity. Reached only through the task: there is
    /// no static naming "the" container, because a carrier may hold several.
    container: Arc<Container>,
}

impl NsProxy {
    /// The proxy a fresh task holds: the ROOT network and UTS namespaces (what
    /// Linux gives everything descended from init) as a member of `container`.
    ///
    /// Phase B1 still takes the root net/UTS objects from the carrier-wide
    /// cells below; B3 (Tasks 20–21) moves them onto the container
    /// (`Container::{uts_ns, net_ns}`) and deletes the cells, so this becomes
    /// a pure read of `container`.
    pub(crate) fn for_container(container: Arc<Container>) -> Self {
        Self {
            net: Arc::clone(root_net_ns()),
            uts: Arc::clone(root_uts_ns()),
            container,
        }
    }

    pub(crate) fn net(&self) -> &Arc<NetNs> {
        &self.net
    }

    pub(crate) fn uts(&self) -> &Arc<UtsNs> {
        &self.uts
    }

    pub(crate) fn container(&self) -> &Arc<Container> {
        &self.container
    }

    /// The proxy a task holds after moving into `uts`, keeping every other
    /// namespace it was already in.
    pub(crate) fn entering_uts(&self, uts: Arc<UtsNs>) -> Self {
        Self {
            net: Arc::clone(&self.net),
            uts,
            container: Arc::clone(&self.container),
        }
    }

    /// The proxy a task holds after moving into `net`, keeping every other
    /// namespace it was already in.
    pub(crate) fn entering_net(&self, net: Arc<NetNs>) -> Self {
        Self {
            net,
            uts: Arc::clone(&self.uts),
            container: Arc::clone(&self.container),
        }
    }
}
```

(`NsProxy::default()` has exactly one caller in the tree, `objects.rs` `Task::new`, replaced in Step 5.)

- [ ] **Step 5: `Task::new` takes the container; `Task::container` (`kernel/objects.rs`)**

Replace the import line

```rust
use super::netns::{NetNs, NsProxy, UtsNs};
```

with

```rust
use super::container::Container;
use super::netns::{NetNs, NsProxy, UtsNs};
```

Replace the constructor signature and the `nsproxy` initializer (lines 2809–2816 and 2845 at `3dc6cc72`; 2813–2820 and 2849 at `ea0dac4c`):

```rust
    pub fn new(
        key: TaskKey,
        parent: Option<TaskKey>,
        process_group: ProcessGroupId,
        session: SessionId,
        shared: Arc<TaskShared>,
        process_credentials: Arc<Credentials>,
    ) -> Self {
```
becomes
```rust
    pub fn new(
        key: TaskKey,
        parent: Option<TaskKey>,
        process_group: ProcessGroupId,
        session: SessionId,
        shared: Arc<TaskShared>,
        process_credentials: Arc<Credentials>,
        container: Arc<Container>,
    ) -> Self {
```
and
```rust
            nsproxy: ArcSwap::new(Arc::new(NsProxy::default())),
```
becomes
```rust
            nsproxy: ArcSwap::new(Arc::new(NsProxy::for_container(container))),
```

(`Task::new` has exactly three callers: `kernel/core.rs` `bootstrap_root`, `kernel/operations.rs` fork, and this file's test `Fixture::new` — Steps 6, 7 and below cover all three.)

After the `uts_ns` accessor (the block ending `Arc::clone(self.nsproxy.load().uts())\n    }` at line 3031 / `ea0dac4c` 3035) add:

```rust
    /// The container this process belongs to, read through the task's
    /// `nsproxy` — never a static — so two containers in one carrier cannot
    /// alias. Inherited across `fork` as a share by
    /// [`Self::inherit_fork_attributes_from`] (its `inherit_ns_from` stores
    /// the parent's whole proxy `Arc`).
    pub fn container(&self) -> Arc<Container> {
        Arc::clone(self.nsproxy.load().container())
    }
```

In the tests module, after

```rust
    use super::*;
    use crate::kernel::{ClonePlan, IdRegistry};
```

add

```rust
    use crate::kernel::container::{LaunchContext, RunId};
```

(`Container` is already in scope through `use super::*`, which re-exports this file's private imports the same way it supplies `Arc` to the existing tests; importing it again is redundant.)

and in `Fixture::new` replace

```rust
            let task = Arc::new(Task::new(
                key,
                None,
                ProcessGroupId::from_leader(task_id),
                SessionId::from_leader(task_id),
                shared,
                resources.credentials(),
            ));
```
with
```rust
            let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
                "objects-fixture",
            ))));
            let task = Arc::new(Task::new(
                key,
                None,
                ProcessGroupId::from_leader(task_id),
                SessionId::from_leader(task_id),
                shared,
                resources.credentials(),
                container,
            ));
```

- [ ] **Step 6: `RootBootstrap.container`, `Kernel.containers`, `bootstrap_root`, accessors, errors (`kernel/core.rs`)**

Imports — after

```rust
use super::address::MmBackend;
```
add
```rust
use super::container::{Container, ContainerId};
```

`RootBootstrap` — replace

```rust
pub struct RootBootstrap {
    task_id: TaskId,
    registry_id: ThreadId,
    mm_backend: Option<Arc<dyn MmBackend>>,
    diagnostic_name: String,
}
```
with
```rust
pub struct RootBootstrap {
    task_id: TaskId,
    registry_id: ThreadId,
    mm_backend: Option<Arc<dyn MmBackend>>,
    diagnostic_name: String,
    /// The container this kernel boots its root task into.
    container: Arc<Container>,
}
```

and replace the private constructor body

```rust
    fn new(
        observed_pid: i32,
        registry_id: ThreadId,
        mm_backend: Option<Arc<dyn MmBackend>>,
        diagnostic_name: String,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            task_id: TaskId::for_root_bootstrap(observed_pid)?,
            registry_id,
            mm_backend,
            diagnostic_name,
        })
    }
}
```
with
```rust
    fn new(
        observed_pid: i32,
        registry_id: ThreadId,
        mm_backend: Option<Arc<dyn MmBackend>>,
        diagnostic_name: String,
    ) -> Result<Self, KernelError> {
        // A reference-model kernel boots into the reference-model container.
        // Product bootstraps override this with `with_container`.
        Ok(Self {
            task_id: TaskId::for_root_bootstrap(observed_pid)?,
            registry_id,
            mm_backend,
            diagnostic_name,
            container: Arc::new(Container::for_reference_model()),
        })
    }

    /// Boot the root task inside `container` (the `Arc` `Runtime::execute`
    /// built from the CLI's `LaunchContext` and installed on the dispatcher).
    pub fn with_container(mut self, container: Arc<Container>) -> Self {
        self.container = container;
        self
    }
}
```

`Kernel` struct — replace

```rust
    pub(super) debug_aux_provider: Mutex<Option<Weak<dyn super::debug::KernelDebugAuxProvider>>>,
    pub(super) controlling_tty: Mutex<Option<ControllingTtyState>>,
}
```
with
```rust
    pub(super) debug_aux_provider: Mutex<Option<Weak<dyn super::debug::KernelDebugAuxProvider>>>,
    pub(super) controlling_tty: Mutex<Option<ControllingTtyState>>,
    /// Every live container on this kernel, by id. The root task's container
    /// is registered by `bootstrap_root`; later ones by `create_container`.
    containers: Mutex<BTreeMap<ContainerId, Arc<Container>>>,
    /// The container the root task was booted into.
    root_container: Arc<Container>,
}
```

`bootstrap_root` — replace

```rust
        let task_key = TaskKey {
            id: bootstrap.task_id,
            serial: object_ids.task_serial()?,
        };
        let task = Arc::new(Task::new(
            task_key,
            None,
            process_group_id,
            session_id,
            Arc::clone(&shared),
            resources.credentials(),
        ));
```
with
```rust
        let task_key = TaskKey {
            id: bootstrap.task_id,
            serial: object_ids.task_serial()?,
        };
        let container = bootstrap.container;
        container.publish_pid_root(task_key)?;
        let task = Arc::new(Task::new(
            task_key,
            None,
            process_group_id,
            session_id,
            Arc::clone(&shared),
            resources.credentials(),
            Arc::clone(&container),
        ));
```

(`bootstrap` is consumed by value by `bootstrap_root`; if the surrounding code still reads other `bootstrap.*` fields after this point, bind `let container = Arc::clone(&bootstrap.container);` instead.)

and replace

```rust
            keyrings: crate::keyring::KeyringService::new(),
            debug_aux_provider: Mutex::new(None),
            controlling_tty: Mutex::new(None),
        });
```
with
```rust
            keyrings: crate::keyring::KeyringService::new(),
            debug_aux_provider: Mutex::new(None),
            controlling_tty: Mutex::new(None),
            containers: Mutex::new(BTreeMap::from([(
                container.id(),
                Arc::clone(&container),
            )])),
            root_container: container,
        });
```

Accessors — immediately before

```rust
    pub fn register_debug_aux_provider(
```
insert
```rust
    /// The container the root task was booted into.
    pub fn root_container(&self) -> &Arc<Container> {
        &self.root_container
    }

    pub fn container(&self, id: ContainerId) -> Option<Arc<Container>> {
        self.containers.lock().get(&id).map(Arc::clone)
    }

    pub fn container_count(&self) -> usize {
        self.containers.lock().len()
    }

    /// Register another container on this kernel. The caller built the
    /// `Arc` (so the same allocation is what its dispatcher, pid region and
    /// root bootstrap hold). Phase B1 records identity; B2 hands it a pid
    /// region and B3 its namespaces and granted caps, at which point a second
    /// `PreparedRun` boots its init here.
    pub fn create_container(&self, container: Arc<Container>) -> Result<(), KernelError> {
        let mut containers = self.containers.lock();
        if containers.contains_key(&container.id()) {
            return Err(KernelError::DuplicateContainer(container.id()));
        }
        containers.insert(container.id(), container);
        Ok(())
    }

```

`KernelContext` — after

```rust
    pub fn resources(&self) -> &Arc<ThreadResources> {
        &self.resources
    }
```
add
```rust
    /// The container the captured task belongs to, read through the task so
    /// the answer can never be a carrier-wide one.
    pub fn container(&self) -> Arc<Container> {
        self.task.container()
    }
```

`KernelError` — replace

```rust
    #[error("kernel thread {0:?} is not live")]
    UnknownThread(LinuxTid),
}
```
with
```rust
    #[error("kernel thread {0:?} is not live")]
    UnknownThread(LinuxTid),
    #[error("container {0:?} is already registered on this kernel")]
    DuplicateContainer(ContainerId),
    #[error("container {0:?} already has an init task")]
    ContainerRootAlreadyPublished(ContainerId),
}
```

In the `core.rs` tests module, make sure `Container`, `LaunchContext` and `RunId` are in scope for Step 1's tests (add `use crate::kernel::container::{Container, LaunchContext, RunId};` next to the existing test imports if `use super::*` does not already supply them).

- [ ] **Step 7: Fork passes the parent's container (`kernel/operations.rs`)**

Replace

```rust
        let child = Arc::new(Task::new(
            child_key,
            (!self.external_peer_root).then(|| self.child_parent_task.key()),
            self.caller_task.process_group(),
            self.caller_task.session(),
            Arc::clone(&child_shared),
            child_resources.credentials(),
        ));
```
with
```rust
        let child = Arc::new(Task::new(
            child_key,
            (!self.external_peer_root).then(|| self.child_parent_task.key()),
            self.caller_task.process_group(),
            self.caller_task.session(),
            Arc::clone(&child_shared),
            child_resources.credentials(),
            self.caller_task.container(),
        ));
```

(`inherit_fork_attributes_from` on the next lines still clones the whole `nsproxy`, so the child ends up sharing the parent's proxy — the constructor argument only makes the pre-inheritance state correct rather than "the root container".)

- [ ] **Step 8: Run the kernel tests (green)**

```sh
cd /Volumes/CaseSensitive/carrick
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel:: 2>&1 | tail -5
```
Expected: `test result: ok.` with the three new tests plus the six `kernel::container::tests` cases passing and zero failures.

- [ ] **Step 9: Write the failing `LaunchContext::from_process_env` tests (red)**

Append to `mod tests` in `crates/carrick-runtime/src/kernel/container.rs`:

```rust
    /// The env tests write the process environment, so they take one lock
    /// even though `just test` already runs this crate serially.
    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn with_env<T>(vars: &[(&str, Option<&str>)], body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock();
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| ((*key).to_owned(), std::env::var(key).ok()))
            .collect();
        for (key, value) in vars {
            // SAFETY: serialized by ENV_LOCK; no other thread reads the
            // environment while a test holds it.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        let result = body();
        for (key, value) in saved {
            // SAFETY: as above.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
        result
    }

    const IDENTITY_ENV: [&str; 4] = [
        "CARRICK_RUN_ID",
        "CARRICK_CONTAINER_ID",
        "CARRICK_LAUNCH_AUTHORIZATION",
        "CARRICK_EXEC_OVERLAY",
    ];

    #[test]
    fn from_process_env_reads_a_managed_detached_carrier() {
        with_env(
            &[
                ("CARRICK_RUN_ID", Some("run-7")),
                ("CARRICK_CONTAINER_ID", Some("deadbeefcafe")),
                ("CARRICK_LAUNCH_AUTHORIZATION", Some("ticket-1")),
                ("CARRICK_EXEC_OVERLAY", Some("/tmp/overlay")),
            ],
            || {
                let launch = LaunchContext::from_process_env().expect("managed context");
                assert_eq!(launch.run_id.as_str(), "run-7");
                assert_eq!(launch.registry_id(), Some("deadbeefcafe"));
                assert_eq!(
                    launch
                        .launch_authorization
                        .as_ref()
                        .map(LaunchAuthorization::ticket),
                    Some("ticket-1")
                );
                assert_eq!(
                    launch.exec_overlay.as_deref().map(camino::Utf8Path::as_str),
                    Some("/tmp/overlay")
                );
            },
        );
    }

    #[test]
    fn from_process_env_treats_an_empty_run_id_as_absent() {
        with_env(
            &[
                ("CARRICK_RUN_ID", Some("")),
                ("CARRICK_CONTAINER_ID", Some("deadbeefcafe")),
                ("CARRICK_LAUNCH_AUTHORIZATION", None),
                ("CARRICK_EXEC_OVERLAY", None),
            ],
            || {
                let launch = LaunchContext::from_process_env().expect("managed context");
                assert_eq!(
                    launch.run_id.as_str(),
                    format!("pid-{}", std::process::id()),
                    "an EMPTY run id is absent: the carrier-pid scope, never a \
                     `carrick-kernel//arena`-shaped path"
                );
                assert_eq!(launch.registry_id(), Some("deadbeefcafe"));
            },
        );
    }

    #[test]
    fn from_process_env_falls_back_to_the_carrier_pid_scope() {
        with_env(&IDENTITY_ENV.map(|key| (key, None)), || {
            let launch = LaunchContext::from_process_env().expect("unmanaged context");
            assert_eq!(
                launch.run_id.as_str(),
                format!("pid-{}", std::process::id())
            );
            assert!(launch.registry_id.is_none());
            assert!(launch.launch_authorization.is_none());
            assert!(launch.exec_overlay.is_none());
        });
    }

    #[test]
    fn from_process_env_refuses_an_unsafe_registry_id() {
        with_env(
            &[
                ("CARRICK_RUN_ID", None),
                ("CARRICK_CONTAINER_ID", Some("../../etc")),
                ("CARRICK_LAUNCH_AUTHORIZATION", None),
                ("CARRICK_EXEC_OVERLAY", None),
            ],
            || {
                assert!(matches!(
                    LaunchContext::from_process_env(),
                    Err(RuntimeError::Configuration(message)) if message.contains("CARRICK_CONTAINER_ID")
                ));
            },
        );
    }
```

Run:

```sh
cd /Volumes/CaseSensitive/carrick
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::container 2>&1 | grep -E 'error\[E0599\].*from_process_env' | head -1
```
Expected: `error[E0599]: no function or associated item named `from_process_env`` — red.

- [ ] **Step 10: Implement `LaunchContext::from_process_env`**

In `crates/carrick-runtime/src/kernel/container.rs`, inside `impl LaunchContext` after `registry_id`, add:

```rust
    /// Build the context from the CLI's process environment — the one place
    /// the runtime is allowed to read `CARRICK_*` identity: the CLI (or the
    /// detached carrier's `run_detached_carrier`) stamps these before calling
    /// `Runtime::execute`, and everything downstream takes the typed value.
    ///
    /// This SUCCEEDS with no identity environment at all — a foreground run,
    /// `run-elf`, and the in-crate tests get `pid-<carrier pid>` as their run
    /// id and no registry entry. Run-id precedence: `CARRICK_RUN_ID` when set
    /// and non-empty, else `pid-<carrier pid>`. Two deliberate tightenings
    /// over the readers this replaces (`runtime::kernel_arena_run_scope`,
    /// `dispatch::sysv::sysv_run_scope`): an EMPTY `CARRICK_RUN_ID` counts as
    /// absent (the process-title reader already filtered it; the arena reader
    /// would have built a `carrick-kernel//arena` path from it), and the
    /// registry id is never reused as the run id — the CLI stamps both, and
    /// conflating them made `kill.sh <run-id>` and `carrick rm <id>` share a
    /// namespace they do not share.
    ///
    /// The only error is an unsafe `CARRICK_CONTAINER_ID`.
    ///
    /// The `std::process::id` call is `HA-CATALOG-PROCESS-ID` in
    /// `clippy.toml`; it is reviewed in
    /// `scripts/migrate/host-authority-transition-inventory.json` as
    /// `declared_backing` (the run-scoped fallback run id — the same
    /// classification as `kernel_arena_run_scope`'s call, which B2 deletes,
    /// leaving this as the one surviving row), see Step 15.
    pub fn from_process_env() -> Result<Self, RuntimeError> {
        let registry_id = match std::env::var("CARRICK_CONTAINER_ID") {
            Ok(id) => Some(RegistryContainerId::new(id)?),
            Err(_) => None,
        };
        let run_id = std::env::var("CARRICK_RUN_ID")
            .ok()
            .filter(|stamp| !stamp.is_empty())
            .map(RunId::new)
            .unwrap_or_else(|| RunId::new(format!("pid-{}", std::process::id())));
        let exec_overlay = std::env::var("CARRICK_EXEC_OVERLAY")
            .ok()
            .map(Utf8PathBuf::from);
        let launch_authorization = std::env::var("CARRICK_LAUNCH_AUTHORIZATION")
            .ok()
            .map(LaunchAuthorization::new);
        Ok(Self {
            container_id: ContainerId::allocate(),
            run_id,
            exec_overlay,
            launch_authorization,
            registry_id,
        })
    }
```

Run:

```sh
cd /Volumes/CaseSensitive/carrick
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::container 2>&1 | tail -3
```
Expected: `test result: ok. 10 passed`.

- [ ] **Step 11: A `container` slot on the dispatcher (`dispatch/mod.rs`)**

Struct — replace

```rust
pub struct SyscallDispatcher {
    /// Generation-safe task adapter used to capture the mandatory kernel
    /// context at each backend dispatch boundary. HVPatch replaces the initial
    /// one-task binding when its root/child task is published.
    kernel_binding: RwLock<crate::kernel::KernelTaskBinding>,
```
with
```rust
pub struct SyscallDispatcher {
    /// Generation-safe task adapter used to capture the mandatory kernel
    /// context at each backend dispatch boundary. HVPatch replaces the initial
    /// one-task binding when its root/child task is published.
    kernel_binding: RwLock<crate::kernel::KernelTaskBinding>,
    /// The container `Runtime::execute` built for this run (the same `Arc`
    /// B2 hands a pid region and B4 admits/retires), handed to the HVPatch
    /// root bootstrap so the root task is created inside it. `None` until
    /// execute installs it; C2 Task 28 (`Runtime::prepare`) makes it
    /// mandatory.
    container: RwLock<Option<Arc<crate::kernel::Container>>>,
```

Constructor (`new_with_host_resolver`) — replace

```rust
        Self {
            kernel_binding: RwLock::new(bootstrap_one_task_binding()),
            timer_delivery: RwLock::new(None),
```
with
```rust
        Self {
            kernel_binding: RwLock::new(bootstrap_one_task_binding()),
            container: RwLock::new(None),
            timer_delivery: RwLock::new(None),
```

Fork clone — replace

```rust
        Self {
            kernel_binding: RwLock::new(self.kernel_binding.read().clone()),
            // Linux interval timers are not inherited across fork. The child
```
with
```rust
        Self {
            kernel_binding: RwLock::new(self.kernel_binding.read().clone()),
            container: RwLock::new(self.container.read().clone()),
            // Linux interval timers are not inherited across fork. The child
```

(These are the only two `Self { kernel_binding: ... }` literals in the file at `3dc6cc72` and `ea0dac4c`.)

Setters — immediately before

```rust
    pub fn set_host_resolver_snapshot(&mut self, snapshot: &crate::vfs::HostResolverSnapshot) {
```
insert
```rust
    /// Install the container the root bootstrap boots into.
    pub fn set_container(&self, container: Arc<crate::kernel::Container>) {
        *self.container.write() = Some(container);
    }

    /// The container installed by `Runtime::execute`, if any. The HVPatch
    /// root bootstrap uses this to decide whether to fall back to the process
    /// environment (`run-elf`, in-crate fixtures).
    pub(crate) fn installed_container(&self) -> Option<Arc<crate::kernel::Container>> {
        self.container.read().clone()
    }

    /// The container this dispatcher serves. Every product entry installs
    /// one before the first syscall; a dispatcher that reaches this without
    /// one (a bare in-crate fixture) is given the reference-model container
    /// so callers never see a carrier-wide answer.
    pub fn container(&self) -> Arc<crate::kernel::Container> {
        if let Some(container) = self.installed_container() {
            return container;
        }
        let mut slot = self.container.write();
        Arc::clone(slot.get_or_insert_with(|| {
            Arc::new(crate::kernel::Container::for_reference_model())
        }))
    }

```

- [ ] **Step 12: The HVPatch root bootstrap boots into the run's container (`hvpatch/mod.rs`)**

Inside `initialize_root_process` (the only site whose diagnostic name is `"hvpatch-root"`; leave the `"hvpatch-test-root"` and `"adapter-root"` bootstraps alone — they keep `RootBootstrap`'s reference-model default container), replace

```rust
    let bootstrap = crate::kernel::RootBootstrap::with_mm_backend(
        pid,
        root_tid,
        mm_backend.clone(),
        "hvpatch-root".to_owned(),
    )
    .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let (kernel, root) = crate::kernel::Kernel::bootstrap_root(bootstrap)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
```
with
```rust
    let container = match dispatcher.installed_container() {
        Some(container) => container,
        // `run-elf` and the in-crate fixtures reach this loop without passing
        // through `Runtime::execute`; until C2 Task 28 makes `prepare` the
        // only entry they take the CLI's process environment as their
        // identity (which succeeds with no identity env at all, and refuses
        // only an unsafe CARRICK_CONTAINER_ID).
        None => {
            let container = Arc::new(crate::kernel::Container::new(
                crate::kernel::LaunchContext::from_process_env()?,
            ));
            dispatcher.set_container(Arc::clone(&container));
            container
        }
    };
    let bootstrap = crate::kernel::RootBootstrap::with_mm_backend(
        pid,
        root_tid,
        mm_backend.clone(),
        "hvpatch-root".to_owned(),
    )
    .map_err(|error| RuntimeError::Configuration(error.to_string()))?
    .with_container(container);
    let (kernel, root) = crate::kernel::Kernel::bootstrap_root(bootstrap)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
```

(`initialize_root_process` returns `Result<Option<ProcessContext>, RuntimeError>` and takes `dispatcher: &SyscallDispatcher`, so the `?` and the accessors both type-check as written; `Arc` is already imported in this file.)

- [ ] **Step 13: `Runtime::execute` builds ONE `LaunchContext`, ONE `Arc<Container>`, and installs it (`execute.rs`)**

(a) Replace the helper

```rust
fn detached_stable_scratch() -> Option<PathBuf> {
    let id = std::env::var("CARRICK_CONTAINER_ID").ok()?;
    if !crate::container::is_safe_id(&id) {
        return None;
    }
    let scratch = crate::container::container_dir(&id).join("scratch");
    if let Ok(mut state) = crate::container::ContainerState::load(&id) {
        state.config.scratch_path = Some(scratch.to_string_lossy().into_owned());
        let _ = state.persist();
    }
    Some(scratch)
}
```
with
```rust
fn detached_stable_scratch(registry_id: Option<&str>) -> Option<PathBuf> {
    let id = registry_id?;
    let scratch = crate::container::container_dir(id).join("scratch");
    if let Ok(mut state) = crate::container::ContainerState::load(id) {
        state.config.scratch_path = Some(scratch.to_string_lossy().into_owned());
        let _ = state.persist();
    }
    Some(scratch)
}
```
(the `is_safe_id` check moved into `RegistryContainerId::new`, where it fails closed instead of returning `None`; `detached_stable_scratch` has exactly one caller, `execute.rs:272`).

(b) After the point where Phase A left the top of `execute` (A5 Task 11 deleted the tokio `debug_assert!` block that used to sit here), replace

```rust
        if spec.platform == Platform::Amd64 {
            rosetta_license_notice();
        }
        let execution_plan = crate::page_profile::resolve_execution_plan(spec)?;
```
with
```rust
        // The run's identity, read from the process environment ONCE, here,
        // and carried as a typed value from now on. C2 Task 28 moves this
        // read to the CLI and passes the context into `Runtime::prepare`.
        // The container is built BEFORE the dispatcher so that B2's
        // `install_pid_ns`, B4's `admit_container`/`retire_container` and the
        // dispatcher all hold the one `Arc`.
        let launch = crate::kernel::LaunchContext::from_process_env()?;
        let container = Arc::new(crate::kernel::Container::new(launch));
        if spec.platform == Platform::Amd64 {
            rosetta_license_notice();
        }
        let execution_plan = crate::page_profile::resolve_execution_plan(spec)?;
```

(`use std::sync::Arc;` if `execute.rs` does not already import it.)

(c) Replace the PID placement block

```rust
        match spec.pid {
            PidMode::Host => {} // share the host pid ns — no placement.
            PidMode::Private => {
                if let Ok(region) = std::env::var("CARRICK_JOIN_REGION") {
                    // `carrick exec`: join the running container's namespace as a
                    // member — do NOT fork our own supervisor (it already has one).
                    if !crate::namespace::pid::join_existing(std::path::Path::new(&region)) {
                        return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to join container namespace at {region}"
                        )));
                    }
                } else {
                    crate::namespace::pid::request();
                }
            }
        }
```
with
```rust
        match spec.pid {
            PidMode::Host => {} // share the host pid ns — no placement.
            PidMode::Private => crate::namespace::pid::request(),
        }
```

(`namespace::pid::request` itself is replaced by B2 Task 16 with `NsSharedRegion::allocate(KernelArena::global())` + `container.install_pid_ns(region)`; this task only removes the dead join arm.)

(d) Replace

```rust
                let exec_overlay = std::env::var("CARRICK_EXEC_OVERLAY").ok();
                let mut host = if let Some(scratch) = &exec_overlay {
                    HostFsBackend::attach(std::path::Path::new(scratch)).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to attach container overlay {scratch}: {e}"
                        ))
                    })?
                } else if let Some(scratch) = detached_stable_scratch() {
```
with
```rust
                let exec_overlay = container.launch().exec_overlay.as_deref();
                let mut host = if let Some(scratch) = exec_overlay {
                    HostFsBackend::attach(scratch.as_std_path()).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to attach container overlay {scratch}: {e}"
                        ))
                    })?
                } else if let Some(scratch) =
                    detached_stable_scratch(container.launch().registry_id())
                {
```

(e) Replace

```rust
                let mut dispatcher = SyscallDispatcher::with_network_and_host_resolver(
                    runtime_network.clone(),
                    host_resolver_snapshot.as_ref(),
                );
                if let HostRootLayout::CachedLower(rootfs) = root_layout {
```
with
```rust
                let mut dispatcher = SyscallDispatcher::with_network_and_host_resolver(
                    runtime_network.clone(),
                    host_resolver_snapshot.as_ref(),
                );
                dispatcher.set_container(Arc::clone(&container));
                if let HostRootLayout::CachedLower(rootfs) = root_layout {
```

(f) In the `#[cfg(feature = "fs-memory")] FsBackendKind::Memory` arm, directly after the `let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(` statement's closing `);` (execute.rs:424-427), add:

```rust
                dispatcher.set_launch_context_placeholder_removed();
```

— no: add exactly

```rust
                dispatcher.set_container(Arc::clone(&container));
```

(The two arms are alternatives of one `match`; `container` is an `Arc`, so cloning into each is fine and the borrows taken in (d) end before (e). Keep the `container` binding alive to the end of `execute` — B4 Task 22 retires it there.)

- [ ] **Step 14: Delete the dead `carrick exec` region-join (`namespace/pid.rs`)**

Prove it is dead first:

```sh
cd /Volumes/CaseSensitive/carrick
rg -n 'CARRICK_JOIN_REGION|join_existing\(|attach_region\(' crates
```
Expected after Step 13(c): only `crates/carrick-runtime/src/namespace/pid.rs` definitions (`attach_region` at `:106`, its use inside `join_existing` at `:611`, `join_existing` at `:610`). No setter of `CARRICK_JOIN_REGION` exists anywhere in `crates/` or `scripts/` (`carrick exec` runs over the carrier control endpoint since `af6270ce`, "refactor(kernel): retire guest host-process execution"). The only other mention in the tree is the host-authority census row `HA-000536` for `join_existing`'s `std::process::id` call in `scripts/migrate/host-authority-transition-inventory.json`, which Step 15 retires. This task is the ONLY owner of this deletion: B2 Tasks 16–19 (which delete `KernelArena::attach` and the by-path constructors) and C2 Task 28 must NOT list `join_existing`/`attach_region`/`CARRICK_JOIN_REGION` again, and their grep expectations are computed on the post-Task-15 tree.

Delete the `attach_region` function together with its doc comment (lines 102–118):

```rust
/// Attach an EXISTING file-backed arena (for `carrick exec`) as a new member.
/// Does NOT seed the pid allocator — the arena already holds the container's
/// live state. Returns `false` on any failure (the caller must not run outside
/// the namespace).
pub fn attach_region(path: &std::path::Path) -> bool {
    if !REGION.load(Ordering::Acquire).is_null() {
        return true;
    }
    // SAFETY: exec join happens in the single-threaded CLI/runtime setup before
    // guest threads or forks; it tells the arena singleton to attach this file.
    unsafe {
        std::env::set_var(ARENA_PATH_ENV, path);
    }
    activate_global_arena()
}
```

and the `join_existing` function with its doc comment (lines 604–617):

```rust
/// `carrick exec`: attach the running container's file-backed region and join it
/// as a new member — a fresh ns-pid, parented OUTSIDE the namespace (the
/// `carrick exec` CLI, so the exec'd guest's ns-ppid is 0, matching docker exec).
/// Enables pid translation while the original VM carrier remains namespace
/// init. Returns `false` if the region cannot be mapped — the caller must then
/// refuse to run, rather than silently execute outside the namespace.
pub fn join_existing(path: &std::path::Path) -> bool {
    if !attach_region(path) {
        return false;
    }
    REQUESTED.store(true, Ordering::Relaxed);
    register_child(std::process::id(), 0);
    true
}
```

(`activate_global_arena` and `ARENA_PATH_ENV` keep their other callers at `:99` and `:133` until B2 deletes them; `register_child` is `pub` and keeps its other callers, so no dead-code warning appears.) Then:

```sh
cd /Volumes/CaseSensitive/carrick
rg -n 'CARRICK_JOIN_REGION|join_existing|attach_region' crates; echo "rc=$?"
```
Expected: no output, `rc=1`.

- [ ] **Step 15: Reconcile the host-authority census (required for `just lint-domains`)**

`just lint-domains` is `scripts/lint-domains.sh` (semgrep `.semgrep/*.yml`, `check-host-authority-escape-hatches.py`, `check-carrier-only-process-invariant.py`) FOLLOWED BY `python3 scripts/migrate/check-host-authority-transitions.py --check` (`justfile:106-108`). That last gate runs clippy with `--force-warn clippy::disallowed_methods` and compares every diagnostic against `scripts/migrate/host-authority-transition-inventory.json`, keyed by `diagnostic_identity` = catalog id + operation + EXACT source span. `std::process::id` is `HA-CATALOG-PROCESS-ID` in `clippy.toml`. This task therefore moves the census in three ways: the new `std::process::id()` in `from_process_env` is an unreviewed NEW row (the one surviving `HA-CATALOG-PROCESS-ID` row of this family once B2 deletes `kernel_arena_run_scope` and replaces `sysv_run_scope`); deleting `attach_region`/`join_existing` shifts the twelve `namespace/pid.rs` rows (those after line 118 by −18, after 604 by −32) and retires row `HA-000536` (`pid.rs:615 join_existing`); the `hvpatch/mod.rs` (8 rows) and `dispatch/mod.rs` (5 rows) edits shift the rows after their insertion points. Follow the tree's own recipe (`docs/superpowers/plans/2026-08-22-hvpatch-fork-lifecycle-closure.md`, Task 11 of THAT plan; commits `143c6b54`, `045d5bb5`, `d6269323`):

```sh
cd /Volumes/CaseSensitive/carrick
# 0. Attribute first (AGENTS.md): at ea0dac4c the checked inventory is ALREADY
#    stale for 3 hvpatch/mod.rs and 5 dispatch/mod.rs rows. Confirm the gate's
#    state on the UNMODIFIED base before blaming this task for any drift.
python3 scripts/migrate/check-host-authority-transitions.py --refresh-candidate target/authority-candidate.json > target/authority.log 2>&1; echo "candidate_rc=$?"
python3 - <<'PY'
import json, collections
cand = json.load(open('target/authority-candidate.json'))
inv  = json.load(open('scripts/migrate/host-authority-transition-inventory.json'))
rows = cand.get('rows', cand)
key = lambda r: ((r.get('source') or {}).get('file'), r.get('catalog_id'), r.get('operation'))
ck, ik = collections.Counter(map(key, rows)), collections.Counter(map(key, inv))
print("only in candidate:", sum((ck-ik).values()))
for k, c in (ck-ik).items(): print("   +", c, k)
print("only in inventory:", sum((ik-ck).values()))
for k, c in (ik-ck).items(): print("   -", c, k)
PY
```
Expected position-insensitive delta: exactly ONE `+` (`crates/carrick-runtime/src/kernel/container.rs`, `HA-CATALOG-PROCESS-ID`, `std::process::id`) and exactly ONE `-` (`crates/carrick-runtime/src/namespace/pid.rs`, `HA-CATALOG-PROCESS-ID`, `std::process::id` — the retired `join_existing` row). Everything else is coordinate churn (the dispatcher's `container()` fallback uses `Container::for_reference_model()`, deliberately NOT a second `std::process::id` call). Then:

- Carry every shifted row's review to its new coordinates (review id, classification, evidence, rationale unchanged; update `source` and the `At <file>:<line>` prefix of the rationale).
- Drop `HA-000536`.
- Review the new row — never bulk re-bless: classification `declared_backing`, evidence `{"authority": "authorized_backing", "resource": "run-scoped fallback run id used by `from_process_env`"}`, rationale `At crates/carrick-runtime/src/kernel/container.rs:<line> in `from_process_env`, `std::process::id` accesses only the run-scoped fallback run id used by `from_process_env`; ...` — the same classification the tree gives `runtime.rs:721 kernel_arena_run_scope` and `sysv.rs:888 sysv_run_scope`, whose fallback this mirrors (B2 retires both of those rows when it deletes/replaces them). Assign the next monotonic `HA-` id.
- Re-bind the macOS compiler receipt (`scripts/migrate/host-authority-macos-capture.json`) from the candidate so `validate_inventory_against_receipt` (exact row equality, run first by `--check`) agrees, as the `bind ... compiler receipt` commits do.

```sh
cd /Volumes/CaseSensitive/carrick
python3 scripts/migrate/check-host-authority-transitions.py --static; echo "static_rc=$?"
just lint-domains 2>&1 | tail -3
```
Expected: `static_rc=0`, then `host-authority census complete: all required profiles passed` (or the `subset passed; result is partial` line on a macOS-only box) and `just lint-domains` exit 0.

- [ ] **Step 16: Gate**

```sh
cd /Volumes/CaseSensitive/carrick
just fmt
just clippy 2>&1 | tail -3
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel:: 2>&1 | tail -3
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib execute:: 2>&1 | tail -3
just doc 2>&1 | tail -2
just lint-domains 2>&1 | tail -2
just test 2>&1 | tail -3
```
Expected: clippy `Finished` with no warnings (workspace `disallowed_methods = "allow"`, `Cargo.toml:42`, so the new `std::process::id` is policed by Step 15's census, not by `just clippy`); `kernel::` and `execute::` (which includes the in-process `hvpatch_uses_container_entrypoint_resolution` run through the new `Container` path) both `test result: ok.`; `just doc` clean; `just lint-domains` passes after Step 15 (`check-carrier-only-process-invariant.py` still sees only the five `carrick-cli/src/lifecycle.rs` allowlist entries — this task adds no host-process creation or control op); `just test` `ok`.

- [ ] **Step 17: Live smoke on a signed artifact (needs HVF; uses the signed recipe)**

```sh
cd /Volumes/CaseSensitive/carrick
just build 2>&1 | tail -1
strings target/release/carrick | grep -c 'is not a safe registry id'
CARRICK_RUN_ID=b1-smoke target/release/carrick run --rm ubuntu:24.04 /bin/sh -c 'echo container-b1-smoke; hostname; cat /proc/self/status | grep -E "^(Pid|PPid):"'; echo "rc=$?"
```
Expected: the marker string is present in the signed binary (count ≥ 1); the guest prints `container-b1-smoke`, a hostname, `Pid:\t1` and `PPid:\t0`, and `rc=0` — CLI behaviour on the same seam is unchanged (Gate B's "CLI behavior identical" half; the two-container half — distinct hostnames per container — needs B3 Tasks 20–21's per-container UTS namespace and is measured by B4 Task 23's `carrick debug container-gate`). `--rm` is a real `carrick run` flag (`carrick-cli/src/args.rs:484`).

- [ ] **Step 18: Commit**

```sh
cd /Volumes/CaseSensitive/carrick
git add crates/carrick-runtime/src/kernel/container.rs crates/carrick-runtime/src/kernel/mod.rs crates/carrick-runtime/src/kernel/netns.rs crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/kernel/core.rs crates/carrick-runtime/src/kernel/operations.rs crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/hvpatch/mod.rs crates/carrick-runtime/src/execute.rs crates/carrick-runtime/src/namespace/pid.rs scripts/migrate/host-authority-transition-inventory.json scripts/migrate/host-authority-macos-capture.json
git commit -m "feat(runtime): put the container on the kernel graph

Why: under HVPatch every guest process is a thread of ONE carrier, so
\"the run's\" state — pid-namespace root, realtime offset, --cap-add
grant, root net/UTS namespaces, CARRICK_* identity — has no object to
live on and sits in carrier-wide statics that alias the moment a second
container appears (docs/identity-and-scope-domains-embed-census.md).
carrick-embed needs many containers in one kernel, and a host
application cannot hand the runtime an identity through
std::env::set_var.

What: kernel/container.rs introduces ContainerId (carrier-unique,
never a host pid), RunId, RegistryContainerId, LaunchAuthorization,
LaunchContext (the typed form of CARRICK_RUN_ID / CARRICK_CONTAINER_ID /
CARRICK_EXEC_OVERLAY / CARRICK_LAUNCH_AUTHORIZATION, read from the
environment in exactly one place; from_process_env succeeds with no
identity env, yielding pid-<carrier pid>), ClockDomain (an
Arc-held System-mode skeleton; B3 moves the realtime offset and vvar
epoch onto it), and Container. The Kernel owns a container table and a
root container; RootBootstrap carries the Arc<Container> it boots into;
NsProxy — Linux's nsproxy — carries the container so Task::container
and KernelContext::container answer through the task and fork inherits
it as a share. Runtime::execute builds one LaunchContext and one
Arc<Container> per run BEFORE the dispatcher, installs it with
set_container, and the HVPatch root bootstrap boots into it. The dead
CARRICK_JOIN_REGION branch and namespace::pid::{attach_region,
join_existing} are deleted: nothing in the tree has set that variable
since carrick exec moved to the carrier control endpoint (af6270ce). No
static is moved yet — that is B2/B3. Two deliberate tightenings: an
unsafe CARRICK_CONTAINER_ID now refuses the run as Configuration
instead of silently degrading to a foreground scratch dir, and an EMPTY
CARRICK_RUN_ID counts as absent (the registry id is no longer reused
as a run id). The host-authority census is reconciled: join_existing's
std::process::id row is retired, the shifted pid.rs/hvpatch/dispatch
rows carry their reviews to the new coordinates, and from_process_env's
pid fallback is reviewed as declared_backing (the same class as
kernel_arena_run_scope).

Verified: red-first — containers_in_one_kernel_have_distinct_ids,
kernel_context_resolves_its_own_container and
fork_child_inherits_parent_container failed to compile before the
graph changes and pass after; from_process_env_* were E0599 red before
Step 10. just clippy / doc / lint-domains (including the live
check-host-authority-transitions census) / test green; signed
target/release/carrick runs ubuntu:24.04 with Pid 1 / PPid 0 and the
expected hostname (Step 17).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

<details><summary>Verifier problems fixed in place (14) and claims still unverified (8)</summary>

- fixed: Task 10 Step 2 / census text / commit body: the grep count '164' is wrong. `rg -n ... | grep -v '^\s*//'` never filters anything (rg -n output starts with `path:line:`), so the command as written prints 234 at 3dc6cc72 AND at ea0dac4c; with a working comment filter (`grep -vE '^[^:]+:[0-9]+:\s*//'`) it is 228 at both. Fixed the command, the expected value, the census header and the commit message.
- fixed: Task 10 census 'Not found at HEAD' section is FALSE: `crates/carrick-timer-core/src/posix.rs:94` has `static BASE_INSTANT: std::sync::OnceLock<Instant>` (the POSIX-timer `now_ns()` monotonic base). The commit message repeated the false claim ('BASE_INSTANT does not exist at HEAD'). Replaced the section with a classified row in the adjacent-crates table (carrier-infra, same reasoning as `dispatch/perf.rs:147 BASE`), added it to the Step 5 check (14 symbols), and fixed the commit body.
- fixed: Task 10 census links `superpowers/specs/2026-08-25-carrick-embed-program-design.md`, which is UNTRACKED at 3dc6cc72 and at the current HEAD ea0dac4c (`git ls-files` returns nothing; `git status` shows `??`). Committing the census alone leaves a dangling link. Added a precondition check to Step 1 and a note that the spec commit (Phase A) must land first or be included.
- fixed: Task 10 Step 4 / Files: the audit table's last row `| address space | ... |` is line 100 of docs/identity-and-scope-domains.md (table = lines 95-100), not line 98; 'Modify ...:95-99' corrected to 95-100.
- fixed: Task 10 census minor coordinate errors: `runtime.rs:714` set_var is at 713; `crates/carrick-hal/src/signal_pump.rs:82` -> the static is at 68 (83 is its swap); `proctitle.rs` `pthread_setname_np` is at 170 (198 is `set_host_process_name`'s definition). Fixed.
- fixed: Task 10 Step 2 anchor loop at the CURRENT HEAD (ea0dac4c): two of 29 anchors MISS because `dispatch/mod.rs` grew by 49 lines since 3dc6cc72 (`GUEST_REALTIME_OFFSET_NS` 7480->7529, `HVPATCH_LANE` 3700->3749). All 29 hold at 3dc6cc72. Made the loop pattern-based (grep -nF, prints the live line) so the executor refreshes the table from its output instead of shipping a stale pin, and recorded the ea0dac4c lines in the census.
- fixed: Task 11 Step 15 gate claim is wrong and the task would fail `just lint-domains`: the recipe runs `scripts/lint-domains.sh` (semgrep + `check-host-authority-escape-hatches.py` + `check-carrier-only-process-invariant.py`) AND `python3 scripts/migrate/check-host-authority-transitions.py --check`, which compares live `clippy::disallowed_methods` diagnostics against `scripts/migrate/host-authority-transition-inventory.json` keyed by EXACT source coordinates (`diagnostic_identity` = catalog_id + operation + source span + expansion). `std::process::id` is `HA-CATALOG-PROCESS-ID` in clippy.toml (154 inventoried rows). This task (a) adds a NEW `std::process::id()` in `kernel/container.rs::from_process_env` (unreviewed row), (b) deletes `attach_region`/`join_existing` so the 12 `namespace/pid.rs` rows shift (rows after line 118 by -18, after 604 by -32) and row HA-000536 (`pid.rs:615 join_existing`) disappears, and (c) shifts the 8 `hvpatch/mod.rs` and 5 `dispatch/mod.rs` rows after its edit points. Added a 'Reconcile the host-authority census' step following the tree's own recipe (docs/superpowers/plans/2026-08-22-hvpatch-fork-lifecycle-closure.md Task 11; commits 143c6b54/045d5bb5/d6269323), with the classification for the one surviving new row mirrored from `runtime.rs:721 kernel_arena_run_scope` (`declared_backing` / `authorized_backing`), and added both JSON files to the commit. Also noted that at ea0dac4c the inventory is ALREADY stale for 3 hvpatch/mod.rs and 5 dispatch/mod.rs rows, so the executor must confirm the gate on unmodified HEAD before attributing drift to this task.
- fixed: Task 11 Step 14 verification `rg -n 'CARRICK_JOIN_REGION|join_existing|attach_region' crates scripts; echo rc=$?` expects no output / rc=1, but `scripts/migrate/host-authority-transition-inventory.json:14390,14398` (row HA-000536) contains `join_existing`, so rc=0. Scoped the check to `crates` and handed the inventory row to the new reconcile step.
- fixed: Task 11 Step 1 expected output over-promises: `LaunchContext`/`RunId` are unresolved names (E0433), and rustc aborts before type-checking, so the E0599 for `create_container`/`container` will typically NOT appear in the same run. Softened the expectation.
- fixed: Task 11 Step 5 test-module import `use crate::kernel::container::{Container, LaunchContext, RunId};` re-imports `Container`, which the tests module already reaches through `use super::*` (objects.rs imports `super::container::Container` in Step 5). Redundant (the tests already rely on the glob for `Arc`); trimmed to `{LaunchContext, RunId}`.
- fixed: Task 11 Files/line numbers drifted at the current HEAD ea0dac4c (34 commits after 3dc6cc72): objects.rs `Task::new` 2809->2813, `NsProxy::default()` 2845->2849, `uts_ns` 3031->3033, tests 6690->6689, fork test 6855->6859; operations.rs `Task::new` 619->639; dispatch/mod.rs struct 2570->2619, fork clone 4232->4281, `new` 4404->4453, `set_host_resolver_snapshot` 4549->4598; hvpatch/mod.rs `initialize_root_process` 1165->1282, bootstrap call 1179->1296. core.rs, netns.rs, execute.rs, pid.rs, kernel/mod.rs anchors unchanged. Recorded both revisions in the Files list. Also made explicit that hvpatch/mod.rs has THREE `RootBootstrap::with_mm_backend` sites (`hvpatch-test-root` :56, `hvpatch-root` :1179/:1296, `adapter-root` :1560/:1736) and only the `hvpatch-root` one changes (the quoted anchor is unique at both revisions).
- fixed: Task 11 netns.rs range '145-190 beginning `#[derive(Debug, Clone)]`': the derive is at line 144; struct at 145. Corrected to 144-190.
- fixed: Task 11 Step 10 doc comment claims `RunId::scope_component` matches BOTH `kernel_arena_run_scope` and `sysv_run_scope`; the draft marked this unverified. Verified: the two sanitizers are byte-identical at 3dc6cc72 (runtime.rs:723-731, sysv.rs:895-903). Left the claim, added the citation.
- fixed: Task 11 commit body claimed 'just clippy / doc / lint-domains / test green' without the inventory reconcile; rewritten to describe the census reconcile and to add `scripts/migrate/host-authority-transition-inventory.json` + `host-authority-macos-capture.json` to `git add`.
- UNVERIFIED: That no exhaustive `match` over KernelError exists elsewhere in the tree; adding two variants would make such a match a compile error (grep `match .* KernelError` was not run). If one exists, add the two arms.
- UNVERIFIED: The exact line numbers 1179-1187 of hvpatch/mod.rs and 4231-4232 / 4403-4404 / 4548-4555 of dispatch/mod.rs were read at 3dc6cc72; the quoted text is the anchor, the numbers may shift after Phase A commits land.
- UNVERIFIED: That `dispatch::sysv::sysv_run_scope` applies exactly the same sanitizer as `kernel_arena_run_scope` (only the first lines of its `raw.chars()` map were read); RunId::scope_component copies the arena sanitizer verbatim and the doc comment claims parity for both — verify before B2 routes sysv through it.
- UNVERIFIED: That `just lint-domains` (semgrep typed-domains.yml + check-carrier-only-process-invariant.py) does not flag the new `static NEXT_CONTAINER_ID` or the unsafe env set/remove in the container.rs tests; the semgrep rules listed in AGENTS.md target LINUX_* consts, wait-set complements and host pids in NsPid, none of which this task adds.
- UNVERIFIED: The Step 16 smoke command assumes `ubuntu:24.04` is pullable/cached on the box and that `--rm` is accepted by `carrick run` (it appears in the RunConfig/lifecycle code); adjust the image if the box uses a local registry.
- UNVERIFIED: The adjacent-crate census rows (carrick-vmm-hvf host_signal.rs:1113, carrick-hal signal_pump.rs:82, carrick-signal-core host_glue.rs:87, carrick-mem memory.rs:664, vdso.rs:55) were verified by a 3-line sed read of each cited line, not by reading the surrounding functions.
- UNVERIFIED: The census grep count (164) is the count at 3dc6cc72 after `grep -v '^\s*//'`; Phase A commits that delete env reads or comments will change it — Step 2 tells the executor to re-run and refresh rather than trust the number.
- UNVERIFIED: Whether the fs-memory arm's dispatcher constructor in execute.rs is at exactly lines 424-428 (only a grep hit on `with_rootfs_and_executable` was seen); the instruction anchors on the statement, not the line.

</details>


<!-- cluster B2-pid-region-per-container -->
## Cluster B2-pid-region-per-container

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 7; notes: Task 18 Step 2's 'before' text for the execute.rs placement block is my reconstruction of what B1 (Task 15) leaves after deleting the CARRICK_JOIN_REGION branch (a bare `PidMode::Private => { crate::namespace::pid::request(); }` arm); B1's cluster must confirm the exact post-deletion text, and the step says to re-derive it. | Task 18 Step 5's in-scope test uses a hypothetical Task 15 reference-model helper (`kernel::reference_model::with_container_context`) to run a closure inside a dispatch scope whose active KernelContext belongs to a given Container; I could not find such a helper at HEAD (there is only `dispatch::resources::with_resources`, test-only, which publishes a null context). B1 should either provide it or the test must be built from `SyscallDispatcher::for_reference_model()` + `set_container` + the scope guard; the step states both options. | Line numbers inside namespace/pid.rs and execute.rs are HEAD's; after B1 deletes `attach_region`/`join_existing`/the env branch they shift and the plan says so, but I could not compute the post-B1 numbers without B1's diff. | Verified at HEAD: `sysv_run_scope` callers are sysv.rs:749,756,911,1190,1196,1200,1221 and `init_sysv_run_scope` (free fn :874 and method :2332, both `#[allow(dead_code)]`, no external caller), `SYSV_FALLBACK_ROOT_PID` at :868; the hit list in Task 18 Step 1 reflects that (33 total). | The live-verify SysV check in Task 18 Step 8 assumes a `carrick debug shm-dir` subcommand does NOT exist and falls back).

### Task 16: `carrick-kernel`: per-namespace PID-numbering slots in the arena, and a namespace tag on every process record

Base: verified against HEAD `ea0dac4c` (3dc6cc72 is an ancestor; of the files this cluster touches only `kernel/objects.rs` and `vcpu_loop/exec.rs` moved since then — line numbers below are HEAD's). This cluster lands AFTER Task 15 (B1, the Container task), which already deleted `namespace::pid::{join_existing, attach_region}` and the `CARRICK_JOIN_REGION` env branch in `execute.rs`; line numbers inside `namespace/pid.rs` and `execute.rs` therefore shift slightly from HEAD's — re-derive them after Task 15.

The pid-namespace "region" today is `NsSharedRegion { section: &'static ProcessSection }` — a view over the ONE record table, whose five namespace words (`next_ns_pid`, `init_host_pid`, `init_host_pgid`, `init_host_sid`, `init_sig_handlers`) live in the `ProcessSection` header (`crates/carrick-kernel/src/process.rs:158-165`). Two containers in one carrier would therefore share one `next_ns_pid` counter and both register ns-pid 1. This task adds the carrier-arena structure that lets each container own its numbering: a `PidNamespaceSection` of claim/release slots in `ArenaLayout`, and a `pid_ns` tag on `ProcessRecord` so member lookups can be scoped to one namespace. The old header words stay in place until Task 17 migrates `namespace/pid.rs` onto the slots (each commit keeps the workspace green).

**Files:**
- Create: `crates/carrick-kernel/src/pidns.rs`
- Modify: `crates/carrick-kernel/src/lib.rs:8-12` (module list)
- Modify: `crates/carrick-kernel/src/arena.rs:11-16` (imports/version), `:52-66` (`ArenaLayout`), `:491-518` (`create_publishes_versioned_header` test)
- Modify: `crates/carrick-kernel/src/process.rs:167-185` (`ProcessRecord`), `:410-426` (`clear_body_for_claim`), tests module ends at `:556`
- Test: `crates/carrick-kernel/src/pidns.rs` (unit tests), `crates/carrick-kernel/src/process.rs` (unit test)

**Interfaces:**
- Consumes: `carrick_kernel::arena::{KernelArena, ArenaError}`, `carrick_kernel::domains::ProcessGeneration` (existing; `ProcessGeneration::{new, raw}` exist).
- Produces:
  - `pub const carrick_kernel::pidns::PID_NAMESPACE_SLOTS: usize = 64;`
  - `pub const carrick_kernel::pidns::FIRST_MEMBER_NS_PID: u32 = 2;`
  - `#[repr(C)] pub struct carrick_kernel::pidns::PidNamespaceSlot { pub owner: AtomicU64, pub next_ns_pid: AtomicU32, pub init_host_pid: AtomicU32, pub init_host_pgid: AtomicU32, pub init_host_sid: AtomicU32, pub init_sig_handlers: AtomicU64 }`
  - `#[repr(C)] pub struct carrick_kernel::pidns::PidNamespaceSection { pub slots: [PidNamespaceSlot; PID_NAMESPACE_SLOTS] }`
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct carrick_kernel::pidns::PidNamespaceRef { pub index: usize, pub generation: ProcessGeneration, pub ns_id: NonZeroU32 }`
  - `impl PidNamespaceSection { pub fn claim(&self, ns_id: NonZeroU32, generation: ProcessGeneration) -> Result<(PidNamespaceRef, &PidNamespaceSlot), ArenaError>; pub fn slot(&self, r: PidNamespaceRef) -> Option<&PidNamespaceSlot>; pub fn release(&self, r: PidNamespaceRef) -> bool; pub fn claimed(&self) -> usize; }`
  - `pub pid_namespaces: PidNamespaceSection` field on `carrick_kernel::arena::ArenaLayout`; `ARENA_VERSION = 5`
  - `pub pid_ns: AtomicU32` field on `carrick_kernel::process::ProcessRecord` (0 = untagged)

- [ ] **Step 1: Write the failing slot tests (red)**

Create `crates/carrick-kernel/src/pidns.rs` containing ONLY the test module for now, and register the module. (`clippy.toml` sets `allow-unwrap-in-tests`/`allow-expect-in-tests`/`allow-panic-in-tests`, so the `#[allow]` below only mirrors `arena.rs`'s style.)

```rust
//! Per-namespace PID-numbering slots in the kernel arena (implementation lands
//! in the next step; the tests below define the contract first).

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::arena::{ArenaError, KernelArena};

    fn ns(id: u32) -> NonZeroU32 {
        NonZeroU32::new(id).unwrap()
    }

    #[test]
    fn two_claims_take_disjoint_slots_with_fresh_numbering() {
        let arena = KernelArena::create().unwrap();
        let section = &arena.layout().pid_namespaces;
        let (a, a_slot) = section.claim(ns(2), arena.allocate_generation()).unwrap();
        let (b, b_slot) = section.claim(ns(3), arena.allocate_generation()).unwrap();
        assert_ne!(a.index, b.index);
        assert_eq!(
            a_slot.next_ns_pid.fetch_add(1, Ordering::AcqRel),
            FIRST_MEMBER_NS_PID
        );
        assert_eq!(
            b_slot.next_ns_pid.load(Ordering::Acquire),
            FIRST_MEMBER_NS_PID,
            "b's counter is untouched by a's allocation"
        );
        assert!(std::ptr::eq(section.slot(a).unwrap(), a_slot));
        assert_eq!(section.claimed(), 2);
    }

    #[test]
    fn release_returns_the_slot_for_reuse_and_resets_it() {
        let arena = KernelArena::create().unwrap();
        let section = &arena.layout().pid_namespaces;
        let (a, a_slot) = section.claim(ns(2), arena.allocate_generation()).unwrap();
        let (b, _) = section.claim(ns(3), arena.allocate_generation()).unwrap();
        a_slot.init_host_pid.store(4100, Ordering::Relaxed);
        a_slot.next_ns_pid.store(900, Ordering::Relaxed);
        assert!(section.release(a));
        assert!(section.slot(a).is_none(), "a released ref no longer resolves");
        let (c, c_slot) = section.claim(ns(4), arena.allocate_generation()).unwrap();
        assert_eq!(c.index, a.index, "the freed slot is reused first");
        assert_ne!(c.index, b.index);
        assert_eq!(c_slot.init_host_pid.load(Ordering::Acquire), 0);
        assert_eq!(
            c_slot.next_ns_pid.load(Ordering::Acquire),
            FIRST_MEMBER_NS_PID
        );
        assert!(!section.release(a), "a stale ref cannot free the reused slot");
        assert!(section.slot(c).is_some());
        assert_eq!(section.claimed(), 2);
    }

    #[test]
    fn exhaustion_is_loud() {
        let arena = KernelArena::create().unwrap();
        let section = &arena.layout().pid_namespaces;
        for i in 0..PID_NAMESPACE_SLOTS {
            section
                .claim(ns(2 + i as u32), arena.allocate_generation())
                .unwrap();
        }
        assert!(matches!(
            section.claim(ns(999), arena.allocate_generation()),
            Err(ArenaError::Exhausted {
                section: "pid_namespaces",
                capacity: PID_NAMESPACE_SLOTS
            })
        ));
    }
}
```

In `crates/carrick-kernel/src/lib.rs`, replace

```rust
pub mod arena;
pub mod domains;
pub mod lock;
pub mod process;
pub mod wait;
```

with

```rust
pub mod arena;
pub mod domains;
pub mod lock;
pub mod pidns;
pub mod process;
pub mod wait;
```

- [ ] **Step 2: Run the slot tests and watch them fail to compile**

Run: `cargo test -p carrick-kernel --lib pidns`
Expected: compilation fails with `error[E0609]: no field \`pid_namespaces\` on type \`&ArenaLayout\`` and `error[E0425]: cannot find value \`FIRST_MEMBER_NS_PID\`` / `PID_NAMESPACE_SLOTS` (the contract does not exist yet).

- [ ] **Step 3: Implement the slot section**

Replace the whole of `crates/carrick-kernel/src/pidns.rs` above the `#[cfg(test)]` line with:

```rust
//! Per-namespace PID-numbering slots in the kernel arena.
//!
//! One `ProcessSection` record table serves every container in the carrier —
//! Linux's own model: one process table, per-namespace numbering. Each PID
//! namespace claims one slot here for its numbering state (the `next_ns_pid`
//! counter and the ns-init identity words) and tags its member records with
//! its `ns_id` (`ProcessRecord::pid_ns`), so two containers' `ns_to_host(1)`
//! name two different inits. Slots are claimed by CAS and released only by
//! the exact generation-stamped reference the owner holds, so a stale handle
//! can never free a slot a later namespace has reused.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arena::ArenaError;
use crate::domains::ProcessGeneration;

/// Namespace slots per carrier arena. Exhaustion is loud
/// (`ArenaError::Exhausted`), never a silent fallback to a shared counter.
pub const PID_NAMESPACE_SLOTS: usize = 64;

/// The first ns-pid handed to a member after the init (ns-pid 1).
pub const FIRST_MEMBER_NS_PID: u32 = 2;

/// Set in `owner` while the claimant resets the numbering words; readers treat
/// such a slot as unpublished.
const CLAIMING: u64 = 1 << 63;

#[repr(C)]
pub struct PidNamespaceSlot {
    /// `0` = free. Published value is exactly `pack(ns_id, generation)`;
    /// `pack(..) | CLAIMING` while the claimant is still resetting the slot.
    pub owner: AtomicU64,
    pub next_ns_pid: AtomicU32,
    pub init_host_pid: AtomicU32,
    pub init_host_pgid: AtomicU32,
    pub init_host_sid: AtomicU32,
    pub init_sig_handlers: AtomicU64,
}

#[repr(C)]
pub struct PidNamespaceSection {
    pub slots: [PidNamespaceSlot; PID_NAMESPACE_SLOTS],
}

/// Index + generation + namespace id, so a stale ref cannot touch a reused
/// slot (same discipline as `ProcessRecordRef`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidNamespaceRef {
    pub index: usize,
    pub generation: ProcessGeneration,
    pub ns_id: NonZeroU32,
}

fn pack(ns_id: NonZeroU32, generation: ProcessGeneration) -> u64 {
    (u64::from(generation.raw()) << 32) | u64::from(ns_id.get())
}

impl PidNamespaceSection {
    /// Claim a free slot for `ns_id`, reset its numbering state, and publish
    /// the owner word last. Returns the reference the owner must present to
    /// [`Self::release`] and the slot itself (valid until that release).
    pub fn claim(
        &self,
        ns_id: NonZeroU32,
        generation: ProcessGeneration,
    ) -> Result<(PidNamespaceRef, &PidNamespaceSlot), ArenaError> {
        let packed = pack(ns_id, generation);
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .owner
                .compare_exchange(0, packed | CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            slot.next_ns_pid
                .store(FIRST_MEMBER_NS_PID, Ordering::Relaxed);
            slot.init_host_pid.store(0, Ordering::Relaxed);
            slot.init_host_pgid.store(0, Ordering::Relaxed);
            slot.init_host_sid.store(0, Ordering::Relaxed);
            slot.init_sig_handlers.store(0, Ordering::Relaxed);
            slot.owner.store(packed, Ordering::Release);
            return Ok((
                PidNamespaceRef {
                    index,
                    generation,
                    ns_id,
                },
                slot,
            ));
        }
        Err(ArenaError::Exhausted {
            section: "pid_namespaces",
            capacity: PID_NAMESPACE_SLOTS,
        })
    }

    /// The slot `r` names, or `None` once it was released or reclaimed.
    pub fn slot(&self, r: PidNamespaceRef) -> Option<&PidNamespaceSlot> {
        let slot = self.slots.get(r.index)?;
        (slot.owner.load(Ordering::Acquire) == pack(r.ns_id, r.generation)).then_some(slot)
    }

    /// Release the slot `r` names. `false` if it was already released or has
    /// been reclaimed by a later namespace — a stale ref never frees a reused
    /// slot.
    pub fn release(&self, r: PidNamespaceRef) -> bool {
        let Some(slot) = self.slots.get(r.index) else {
            return false;
        };
        slot.owner
            .compare_exchange(
                pack(r.ns_id, r.generation),
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Slots currently owned — the number of live PID namespaces.
    pub fn claimed(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.owner.load(Ordering::Acquire) != 0)
            .count()
    }
}
```

- [ ] **Step 4: Carve the section into `ArenaLayout` and bump the version**

In `crates/carrick-kernel/src/arena.rs`, replace

```rust
use crate::domains::{HostPid, ProcessGeneration};
use crate::process::ProcessSection;

pub const ARENA_MAGIC: u32 = 0x434b_4131;
pub const ARENA_VERSION: u32 = 4;
```

with

```rust
use crate::domains::{HostPid, ProcessGeneration};
use crate::pidns::PidNamespaceSection;
use crate::process::ProcessSection;

pub const ARENA_MAGIC: u32 = 0x434b_4131;
/// Bumped to 5 when `pid_namespaces` was appended and `ProcessRecord` gained
/// `pid_ns`; a version-4 file is refused by `attach` (fail closed).
pub const ARENA_VERSION: u32 = 5;
```

and replace

```rust
    /// (docs/2026-07-09-mt-residency-lease-evidence.md, Next Track 1).
    pub vm_slots: PermitSection,
}
```

with

```rust
    /// (docs/2026-07-09-mt-residency-lease-evidence.md, Next Track 1).
    pub vm_slots: PermitSection,
    /// Per-PID-namespace numbering slots (`pidns.rs`): one claimed per live
    /// container / pid namespace. Member records in `processes` carry the
    /// owning namespace id in `ProcessRecord::pid_ns`. Zero-filled by the
    /// `ftruncate` in `create_with_path`, so every slot starts free.
    pub pid_namespaces: PidNamespaceSection,
}
```

In the `create_publishes_versioned_header` test, replace

```rust
        assert_eq!(
            l.processes
                .next_ns_pid
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
```

with

```rust
        assert_eq!(
            l.processes
                .next_ns_pid
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(l.pid_namespaces.claimed(), 0, "a fresh arena has no namespace");
    }
```

- [ ] **Step 5: Tag every process record with its namespace (red test first)**

Append to the `tests` module at the end of `crates/carrick-kernel/src/process.rs` (before its closing `}` at line 556; the module already imports `super::*`, `crate::arena::KernelArena` and `crate::domains::HostPid`, and `Ordering` comes from `super::*`):

```rust
    #[test]
    fn claim_clears_the_namespace_tag() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let r = s
            .claim(Some(HostPid::new(700)), arena.allocate_generation(), |rec| {
                rec.pid_ns.store(9, Ordering::Relaxed);
            })
            .unwrap();
        assert_eq!(s.records[r.index].pid_ns.load(Ordering::Acquire), 9);
        assert!(s.release(r));
        let again = s
            .claim(Some(HostPid::new(700)), arena.allocate_generation(), |_| {})
            .unwrap();
        assert_eq!(again.index, r.index);
        assert_eq!(
            s.records[again.index].pid_ns.load(Ordering::Acquire),
            0,
            "a reused record must not inherit a namespace tag"
        );
    }
```

Run: `cargo test -p carrick-kernel --lib claim_clears_the_namespace_tag`
Expected: `error[E0609]: no field \`pid_ns\` on type \`&ProcessRecord\``.

Then in `crates/carrick-kernel/src/process.rs` replace

```rust
    pub ptrace_control: AtomicU64,
    pub exit_ready: AtomicU32,
    pub guest_ns: AtomicU64,
}
```

with

```rust
    pub ptrace_control: AtomicU64,
    pub exit_ready: AtomicU32,
    /// The PID namespace this record is a member of (`PidNamespaceRef::ns_id`),
    /// or 0 while it carries no namespace identity (run-state/guest-CPU only).
    /// Placed in the padding after `exit_ready`, so the `#[repr(C)]` record
    /// stays 88 bytes (10×u32 + 4×u64 = 72, `exit_ready` at 72, this at 76,
    /// `guest_ns` at 80).
    pub pid_ns: AtomicU32,
    pub guest_ns: AtomicU64,
}
```

and replace

```rust
        self.exit_ready.store(0, Ordering::Relaxed);
        self.guest_ns.store(0, Ordering::Relaxed);
    }
}
```

with

```rust
        self.exit_ready.store(0, Ordering::Relaxed);
        self.pid_ns.store(0, Ordering::Relaxed);
        self.guest_ns.store(0, Ordering::Relaxed);
    }
}
```

(`release_claimed` at `process.rs:350-367` calls `clear_body_for_claim`, so a released record loses its tag too.)

- [ ] **Step 6: Run the crate's tests green**

Run: `cargo test -p carrick-kernel --lib`
Expected: `test result: ok.` with the three `pidns::tests::*` cases and `claim_clears_the_namespace_tag` listed as `ok`; the existing `attach_rejects_wrong_magic` still passes (a zero file is not version 5).

Run: `cargo test -p carrick-kernel --test prefork_registration`
Expected: `test result: ok.` (the fork test only touches `processes`).

- [ ] **Step 7: Format and gate**

Run: `just fmt && just clippy`
Expected: no diff left by fmt; clippy exits 0 (no `unwrap`/`expect`/`panic` outside test modules).

Run: `just test`
Expected: every lane ends `test result: ok.`; the runtime lane still passes because `namespace/pid.rs` still reads the (retained) `ProcessSection` header words.

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-kernel/src/pidns.rs crates/carrick-kernel/src/lib.rs crates/carrick-kernel/src/arena.rs crates/carrick-kernel/src/process.rs
git commit -F- <<'EOF'
feat(kernel): add per-namespace pid slots to the arena

Why: the pid-namespace region is one view over the arena's single
`ProcessSection`, and that section's header holds the ONLY `next_ns_pid`
counter and ns-init words in the carrier. Two containers in one carrier
(the Phase B model of docs/superpowers/specs/2026-08-25-carrick-embed-
program-design.md) would share one pid counter and both claim ns-pid 1,
and `ns_to_host(1)` could not say whose init it named.

What: `carrick_kernel::pidns` adds `PidNamespaceSection` — 64 CAS-claimed,
generation-stamped slots each holding one namespace's numbering words —
carved into `ArenaLayout` after `vm_slots`, and `ProcessRecord` gains a
`pid_ns` tag (in the padding after `exit_ready`, so the record stays 88
bytes) that member lookups will scope on. `ARENA_VERSION` goes to 5 so a
stale attacher fails closed. The old header words stay until
`namespace/pid.rs` migrates onto the slots in the next commit; nothing
reads the new section yet.

Verified: red-first `pidns::tests` (disjoint claims, release-then-reuse
with a stale ref refused, loud exhaustion) and
`process::tests::claim_clears_the_namespace_tag` failed to compile
before the types existed and pass after; `just test` and `just clippy`
green.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 17: `namespace::pid`: an owned, per-container `NsSharedRegion` over a namespace slot; delete the `REGION`/`REQUESTED` process statics

`namespace/pid.rs` keeps `static REGION: AtomicPtr<ProcessSection>` and `static REQUESTED: AtomicBool` (`crates/carrick-runtime/src/namespace/pid.rs:69,75` at HEAD), set once per process and never reset, and every translation function reads them through `region()` (`:193-204`). This task makes `NsSharedRegion` an OWNED object (one per container, released on drop or by an explicit `retire`) that scopes every member lookup to its own namespace id, and makes `region()` resolve through the calling task's `Container` instead of a static. The five header words move from `ProcessSection` onto the container's `PidNamespaceSlot`.

**This task and Task 18 (Wire the run path) land as ONE commit** (Task 18 Step 9): deleting the statics here removes run-path call sites that only Task 18 rewires, so the tree is red between the two. Do not commit at the end of this task.

**Files:**
- Modify: `crates/carrick-runtime/src/namespace/pid.rs:1-32` (doc + imports), `:61-212` (region type, statics, `region()`/`enabled()`; the range is shorter after Task 15 removed `attach_region`), `:241-294` (pgid/sid words), `:420-451` (init handler words), `:540-617` (child/exec helpers; `join_existing` is already gone after Task 15), `:619-663` (`alloc_ns_pid`, `init_host_pid`, `register`), `:697-707` (`slot_of`), `:807-838` (`unregister_reaped`), `:875-948` (`sweep_dead_owner_records`), `:967-976` (`member_records`), `:1017-1044` (`fill_member`), tests `:1082-1527`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs:3027-3029` (add `Task::pid_ns_region` after `net_ns`)
- Modify: `crates/carrick-runtime/src/kernel/container.rs` (Task 15's file — does not exist at HEAD: add the `pid_ns` slot on `Container`)
- Modify: `crates/carrick-kernel/src/process.rs:157-165` (delete the five header words), `:259-261` (delete `allocate_ns_pid`), test `:529-534`
- Modify: `crates/carrick-kernel/src/arena.rs:458` (stop seeding `processes.next_ns_pid`), test `:512-518`
- Test: `crates/carrick-runtime/src/namespace/pid.rs` tests module

**Interfaces:**
- Consumes: `carrick_kernel::pidns::{PID_NAMESPACE_SLOTS, PidNamespaceRef, PidNamespaceSlot}` (Task 16); `crate::namespace::process::alloc_ns_id() -> NsId` (existing, `namespace/process.rs:299`; `NsId = u32`, `namespace/mod.rs:24`); `crate::dispatch::resources::with_active_context` (existing `pub(crate)`, `dispatch/resources.rs:166`, closure takes `&crate::kernel::KernelContext`); `KernelContext::task(&self) -> &TaskRef` (`kernel/core.rs:75`, `TaskRef = Arc<Task>`); from Task 15 (the Container task): `Task::container(&self) -> Arc<crate::kernel::container::Container>`, `pub(crate) fn Container::new(launch: LaunchContext) -> Container`, `pub fn Container::for_reference_model() -> Container`, and the `Container` struct in `crates/carrick-runtime/src/kernel/container.rs` with its `pid_root: OnceLock<TaskKey>` field (NEITHER exists at HEAD — this task cannot compile before Task 15 lands). Task 15 has already deleted `namespace::pid::{join_existing, attach_region}`; this task does not touch them.
- Produces:
  - `pub struct crate::namespace::pid::NsSharedRegion { /* private: arena, section, ns, claim, released */ }` — `Send + Sync`, `Debug`, `Drop` releases the slot (safety net)
  - `impl NsSharedRegion { pub fn allocate(arena: &'static KernelArena) -> Result<Arc<Self>, ArenaError>; pub fn ns_id(&self) -> NsId; pub fn set_init(&self, init_host_pid: u32); pub(crate) fn retire(self: Arc<Self>) -> bool; }` (all existing `&self` translation methods keep their signatures). `retire` is the explicit member-retire + slot-release consumed by Task 23 (B4, `retire_container`); it returns `true` the first time the slot is released, `false` afterwards, and `Drop` releases only what `retire` did not.
  - `pub fn crate::namespace::pid::region() -> Option<Arc<NsSharedRegion>>` (calling task's container; `None` outside a dispatch scope or under `PidMode::Host`)
  - `pub fn crate::namespace::pid::region_for(context: &crate::kernel::KernelContext) -> Option<Arc<NsSharedRegion>>`
  - `pub fn crate::namespace::pid::host_to_ns_or_self_for(context: &KernelContext, host_pid: u32) -> u32`
  - `pub fn crate::namespace::pid::mark_self_execed_for(context: &KernelContext)`
  - `impl Task { pub fn pid_ns_region(&self) -> Option<Arc<NsSharedRegion>> }`
  - `impl Container { pub(crate) fn install_pid_ns(&self, region: Arc<NsSharedRegion>) -> Result<(), Arc<NsSharedRegion>>; pub(crate) fn pid_region(&self) -> Option<Arc<NsSharedRegion>> }` and the field `pid_ns: OnceLock<Arc<NsSharedRegion>>` on `Container` (alongside Task 15's `pid_root: OnceLock<TaskKey>` — both fields exist)
  - Deleted: `pid::{request, requested, alloc_region, init, set_init (free fn), region_over, mark_self_execed, notify_child_registered}`, `static REGION`, `static REQUESTED`, `ProcessSection::{next_ns_pid, init_host_pid, init_host_pgid, init_host_sid, init_sig_handlers, allocate_ns_pid}`

- [ ] **Step 1: Write the failing region tests (red)**

Append to the `tests` module at the end of `crates/carrick-runtime/src/namespace/pid.rs` (before its final `}` at line 1527), and change the existing helper `test_region()` (lines 1310-1315) as shown:

Replace

```rust
    fn test_region() -> NsSharedRegion {
        let arena = Box::leak(Box::new(KernelArena::create().unwrap()));
        NsSharedRegion {
            section: &arena.layout().processes,
        }
    }
```

with

```rust
    fn test_arena() -> &'static KernelArena {
        Box::leak(Box::new(KernelArena::create().expect("create test arena")))
    }

    fn test_region() -> Arc<NsSharedRegion> {
        NsSharedRegion::allocate(test_arena()).expect("claim test namespace")
    }

    #[test]
    fn two_regions_in_one_arena_are_disjoint_and_pid_1_names_each_own_init() {
        let arena = test_arena();
        let a = NsSharedRegion::allocate(arena).expect("claim namespace a");
        let b = NsSharedRegion::allocate(arena).expect("claim namespace b");
        assert_ne!(a.ns_id(), b.ns_id());
        assert_ne!(a.claim.index, b.claim.index);

        a.set_init(4100);
        b.set_init(4200);
        assert_eq!(a.ns_to_host(NS_INIT_PID), Some(4100));
        assert_eq!(b.ns_to_host(NS_INIT_PID), Some(4200));
        assert_eq!(a.host_to_ns(4200), None, "b's init is not a member of a");
        assert_eq!(b.host_to_ns(4100), None, "a's init is not a member of b");

        let a_child = a.alloc_ns_pid();
        let b_child = b.alloc_ns_pid();
        assert_eq!((a_child, b_child), (2, 2), "each namespace numbers from 2");
        assert!(a.register(4101, a_child, 4100).is_some());
        assert_eq!(a.host_to_ns(4101), Some(2));
        assert_eq!(a.ns_ppid_for_host(4101), Some(NS_INIT_PID));
        assert_eq!(b.host_to_ns(4101), None, "a's child is invisible in b");
        assert_eq!(b.ns_to_host(2), None, "ns-pid 2 is unassigned in b");
        assert_eq!(
            b.register(4101, b_child, 4200),
            None,
            "a task belongs to exactly one pid namespace"
        );
    }

    #[test]
    fn dropping_a_region_releases_its_slot_and_members_for_reuse() {
        let arena = test_arena();
        let a = NsSharedRegion::allocate(arena).expect("claim namespace a");
        let b = NsSharedRegion::allocate(arena).expect("claim namespace b");
        let a_claim = a.claim;
        let a_ns_id = a.ns_id();
        let section = a.section;
        a.set_init(4100);
        assert!(a.register(4101, a.alloc_ns_pid(), 4100).is_some());
        assert_eq!(arena.layout().pid_namespaces.claimed(), 2);

        drop(a);

        assert!(
            arena.layout().pid_namespaces.slot(a_claim).is_none(),
            "drop released the namespace slot"
        );
        assert_eq!(arena.layout().pid_namespaces.claimed(), 1);
        assert!(
            section
                .records
                .iter()
                .all(|record| record.pid_ns.load(Ordering::Acquire) != a_ns_id),
            "no record still carries the dropped namespace's tag"
        );
        assert!(section.find(HostPid::new(4101)).is_none(), "untagged member record released");

        let c = NsSharedRegion::allocate(arena).expect("claim namespace c");
        assert_eq!(c.claim.index, a_claim.index, "the released slot is reused");
        assert_ne!(c.claim.index, b.claim.index);
        assert_ne!(c.ns_id(), a_ns_id);
        assert_eq!(c.ns_to_host(NS_INIT_PID), None, "c starts with no init");
        assert_eq!(c.host_to_ns(4101), None, "a's members were retired on drop");
        assert_eq!(c.alloc_ns_pid(), 2, "c's counter is fresh");
        assert_eq!(b.ns_to_host(NS_INIT_PID), None, "b was never touched");
    }

    #[test]
    fn explicit_retire_releases_once_and_drop_is_then_a_no_op() {
        let arena = test_arena();
        let a = NsSharedRegion::allocate(arena).expect("claim namespace a");
        let a_claim = a.claim;
        let a_ns_id = a.ns_id();
        let section = a.section;
        a.set_init(4100);
        assert!(a.register(4101, a.alloc_ns_pid(), 4100).is_some());
        // A second holder, as a live task's `Container` would be at teardown.
        let holder = Arc::clone(&a);

        assert!(a.retire(), "the first retire releases the slot");
        assert!(
            arena.layout().pid_namespaces.slot(a_claim).is_none(),
            "retire released the namespace slot while another Arc is still held"
        );
        assert!(
            section
                .records
                .iter()
                .all(|record| record.pid_ns.load(Ordering::Acquire) != a_ns_id),
            "retire retired the members"
        );
        assert!(!Arc::clone(&holder).retire(), "a second retire reports nothing to release");

        let c = NsSharedRegion::allocate(arena).expect("claim namespace c");
        assert_eq!(c.claim.index, a_claim.index, "the retired slot is reused");
        drop(holder);
        assert!(
            arena.layout().pid_namespaces.slot(c.claim).is_some(),
            "dropping the last Arc of a retired region does not free c's slot"
        );
    }
```

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib namespace::pid::tests`
Expected: compilation fails with `error[E0599]: no function or associated item named \`allocate\` found for struct \`NsSharedRegion\`` (plus follow-on errors for `ns_id`/`claim`/`retire` once `allocate` exists; the exact set depends on inference order — the point is that the owned-region API does not exist yet).

- [ ] **Step 2: Replace the module header and imports**

In `crates/carrick-runtime/src/namespace/pid.rs`, replace lines 1-32:

```rust
//! PID namespace translation: a host-pid ↔ ns-pid table backed by the
//! carrick-kernel arena process section so it is coherent across `fork`
//! (design §3.3, §5.2, §5.6).
//!
//! The arena is allocated **before the first guest fork** and inherited by
//! every descendant: all processes map the same physical pages, so a
//! `fetch_add`/`compare_exchange` on an atomic in one process is visible to all
//! others (Apple-Silicon hardware atomics operate on physical addresses).
//!
//! Only the *initial* root PID namespace is modeled by the global region for
//! now — the common `docker run` case (one fresh pid ns whose init is pid 1).
//! Nested guest-created namespaces (Phase 4) extend this; the slot model already
//! carries enough to distinguish them by `init_host_pid` if needed later.
//!
//! NOTE: the translation/shared-region API below is wired into the fork path,
//! `getpid`/`getppid`, `wait4`/`kill`, and `/proc` in Phase 2. Until then the
//! items are unused; the module-level `allow(dead_code)` is removed once Phase 2
//! lands.
#![allow(dead_code)]

use std::sync::atomic::{AtomicPtr, Ordering};

use carrick_kernel::arena::{ARENA_PATH_ENV, KernelArena};
use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::process::{
    FLAG_ALIVE, FLAG_DEAD, FLAG_ORPHANED, PROCESS_RECORDS, ProcessRecord, ProcessRecordRef,
    ProcessRecordTransitionAction, ProcessRecordTransitionError, ProcessSection, REGISTERING,
};
#[cfg(test)]
use carrick_kernel::process::{VirtualPtraceControl, VirtualPtraceState};

use super::NsId;
```

with

```rust
//! PID namespace translation: a host-pid ↔ ns-pid table over the carrier's
//! kernel-arena process section (design §3.3, §5.2, §5.6).
//!
//! One record table serves every container in the carrier; each PID namespace
//! owns one [`NsSharedRegion`], which claims a numbering slot in the arena
//! (`carrick_kernel::pidns`) and tags its member records with its namespace
//! id. There is no process-global region: a task reaches its namespace through
//! its `Container` (`Task::pid_ns_region`), the free functions below resolve
//! the CALLING task's region from the active dispatch context, and callers
//! outside a dispatch scope that still hold the exact task pass it explicitly
//! (`*_for(context, ..)`). Retiring (or dropping) a container's region retires
//! its members and returns the slot for the next container.
//!
//! Only the container's root PID namespace is modeled; nested guest-created
//! namespaces (Phase 4) extend the same slot model.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_kernel::arena::{ArenaError, KernelArena};
use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::pidns::{PID_NAMESPACE_SLOTS, PidNamespaceRef, PidNamespaceSlot};
use carrick_kernel::process::{
    FLAG_ALIVE, FLAG_DEAD, FLAG_ORPHANED, PROCESS_RECORDS, ProcessRecord, ProcessRecordRef,
    ProcessRecordTransitionAction, ProcessRecordTransitionError, ProcessSection, REGISTERING,
};
#[cfg(test)]
use carrick_kernel::process::{VirtualPtraceControl, VirtualPtraceState};

use super::NsId;
```

(If Task 15's deletion of `attach_region` already dropped the `ARENA_PATH_ENV` import, the "before" text differs only by that item — match on what Task 15 left.)

- [ ] **Step 3: Replace the region type, the statics and the resolver**

Replace lines 61-212 (HEAD numbering; shorter after Task 15) — everything from

```rust
/// Active PID namespace view over the arena's process section.
#[derive(Clone, Copy)]
pub struct NsSharedRegion {
    section: &'static ProcessSection,
}
```

through the end of

```rust
pub fn enabled() -> bool {
    !REGION.load(Ordering::Acquire).is_null()
}
```

(after Task 15 removed `attach_region`, this range holds `static REGION`, `static REQUESTED`, `request`, `requested`, `alloc_region`, `activate_global_arena`, `persist_detached_arena_path` — the only in-runtime writer of `RunConfig.region_path`, which Task 19 deletes — the free `set_init`, `init`, `region_over`, `region`, `enabled`) with:

```rust
/// One PID namespace's view of the carrier's process table: the arena's
/// shared record section plus this namespace's own numbering slot.
///
/// OWNED, not global. A container allocates one at launch and holds it in an
/// `Arc`; every task in the container reaches it through its `Container`
/// (`Task::pid_ns_region`), never through a static. Container teardown calls
/// [`NsSharedRegion::retire`] to retire the namespace's member tags and
/// release the slot for reuse; dropping the last `Arc` does the same as a
/// safety net if nobody retired explicitly.
pub struct NsSharedRegion {
    arena: &'static KernelArena,
    section: &'static ProcessSection,
    /// This namespace's numbering words. Borrowed for `'static` because the
    /// arena mapping is process-lifetime and the slot cannot be reclaimed
    /// while this owner holds `claim` (release needs the exact reference).
    ns: &'static PidNamespaceSlot,
    claim: PidNamespaceRef,
    /// Set by whichever of `retire`/`Drop` released the slot first, so the
    /// other is a no-op and a reused slot is never released twice.
    released: AtomicBool,
}

impl std::fmt::Debug for NsSharedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NsSharedRegion")
            .field("ns_id", &self.ns_id())
            .field("slot", &self.claim.index)
            .field("init_host_pid", &self.init_host_pid())
            .finish()
    }
}

impl NsSharedRegion {
    /// Claim a fresh PID namespace in `arena`. The namespace id comes from the
    /// carrier-wide allocator, so record tags are unambiguous across
    /// containers. Fails loudly when the arena's slot table is full.
    pub fn allocate(arena: &'static KernelArena) -> Result<Arc<Self>, ArenaError> {
        // The carrier-wide id counter starting at FIRST_DYNAMIC_NS (2) reaches
        // 0 only after wrapping u32: report that as the same exhaustion.
        let ns_id = std::num::NonZeroU32::new(super::process::alloc_ns_id()).ok_or(
            ArenaError::Exhausted {
                section: "pid_namespaces",
                capacity: PID_NAMESPACE_SLOTS,
            },
        )?;
        let layout = arena.layout();
        let (claim, ns) = layout
            .pid_namespaces
            .claim(ns_id, arena.allocate_generation())?;
        Ok(Arc::new(Self {
            arena,
            section: &layout.processes,
            ns,
            claim,
            released: AtomicBool::new(false),
        }))
    }

    /// This namespace's id — the `pid:[N]` inode and the member record tag.
    pub fn ns_id(&self) -> NsId {
        self.claim.ns_id.get()
    }

    /// Record `init_host_pid` as the namespace init (ns-pid 1) and pre-register
    /// it as the first member. The init's host process-group/session are
    /// captured so ns-pgid 1 ↔ that group (`host_to_ns_pgid`).
    pub fn set_init(&self, init_host_pid: u32) {
        self.ns
            .init_host_pid
            .store(init_host_pid, Ordering::Relaxed);
        let init_host_pgid = unsafe { libc::getpgrp() };
        if init_host_pgid > 0 {
            self.ns
                .init_host_pgid
                .store(init_host_pgid as u32, Ordering::Relaxed);
        }
        let init_host_sid = unsafe { libc::getsid(0) };
        if init_host_sid > 0 {
            self.ns
                .init_host_sid
                .store(init_host_sid as u32, Ordering::Relaxed);
        }
        let _ = self.register(init_host_pid, NS_INIT_PID, 0);
    }

    /// Container teardown: retire every member this namespace still tags and
    /// release its arena slot NOW, without waiting for the last `Arc` (a
    /// reaped task's `Container` handle may outlive the teardown by a beat).
    /// `true` if this call released the slot; `false` if it was already
    /// released. Consumed by `carrier::retire_container` (Task 23).
    pub(crate) fn retire(self: Arc<Self>) -> bool {
        self.release_slot()
    }

    fn release_slot(&self) -> bool {
        if self.released.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.retire_members();
        self.arena.layout().pid_namespaces.release(self.claim)
    }

    /// Strip this namespace's identity from every record it tagged and release
    /// the ones nothing else owns, so a later namespace reusing the slot can
    /// never inherit stale members. A record whose transition is owned
    /// elsewhere at this instant keeps a tag no live namespace will ever equal.
    fn retire_members(&self) {
        let ns_id = self.ns_id();
        for (index, record) in self.section.records.iter().enumerate() {
            if record.pid_ns.load(Ordering::Acquire) != ns_id {
                continue;
            }
            if !record.try_claim_transition() {
                continue;
            }
            let host_pid = record.host_pid.load(Ordering::Acquire);
            let generation = record.generation.load(Ordering::Acquire);
            let still_ours = record.pid_ns.load(Ordering::Acquire) == ns_id;
            if still_ours {
                record.ns_pid.store(0, Ordering::Release);
                record.pid_ns.store(0, Ordering::Release);
                record.exec_generation.store(0, Ordering::Release);
                record.exit_status.store(0, Ordering::Relaxed);
                record
                    .flags
                    .fetch_and(!(MEMBER_DEAD | MEMBER_ORPHANED), Ordering::AcqRel);
            }
            record.release_transition();
            // A record no run-state owner still holds is this namespace's to
            // return; a live task's record (nonzero run-state word) stays for
            // `run_state::clear_guest_process`.
            if still_ours
                && generation != 0
                && record.run_state.load(Ordering::Acquire) == 0
            {
                let _ = self.section.release_if_namespace_unowned(
                    ProcessRecordRef {
                        index,
                        generation: ProcessGeneration::new(generation),
                    },
                    HostPid::new(host_pid),
                );
            }
        }
    }
}

impl Drop for NsSharedRegion {
    fn drop(&mut self) {
        // Safety net only: `retire` is the intended release.
        let _ = self.release_slot();
    }
}

/// The CALLING task's PID namespace region, or `None` when no guest syscall
/// is in flight on this thread or the task's container shares the host pid
/// namespace (`--pid host`). Every translation below is then the identity.
pub fn region() -> Option<Arc<NsSharedRegion>> {
    crate::dispatch::resources::with_active_context(region_for).flatten()
}

/// The PID namespace region of the exact task `context` names. For callers
/// outside a dispatch scope that still hold the task — signal delivery, exec
/// commit — never a thread- or process-derived surrogate.
pub fn region_for(context: &crate::kernel::KernelContext) -> Option<Arc<NsSharedRegion>> {
    context.task().pid_ns_region()
}

/// `true` if the calling task is in a private PID namespace. When false, every
/// translation below is the identity (the guest pid IS the host pid) so
/// `run-elf` and `--pid host` runs are unchanged.
pub fn enabled() -> bool {
    region().is_some()
}
```

`enabled()` has ~30 callers in `vfs/proc.rs`, `dispatch/{proc,signal,abi_args,creds}.rs` (`rg -n 'pid::enabled\(' crates/carrick-runtime/src`); all of them run inside a guest syscall's dispatch scope, where `with_active_context` is populated. Any caller that runs on a host helper thread now reads identity instead of the old process-global region — the `*_for(context, ..)` variants exist for exactly that case (Task 18 converts the two known ones).

- [ ] **Step 4: Point the pgid/sid and init-handler words at the slot**

Replace (in `host_to_ns_pgid`)

```rust
            let init_pgid = r.section.init_host_pgid.load(Ordering::Acquire);
            if init_pgid != 0 && host_pgid == init_pgid {
                return NS_INIT_PID;
            }
            let init_sid = r.section.init_host_sid.load(Ordering::Acquire);
```

with

```rust
            let init_pgid = r.ns.init_host_pgid.load(Ordering::Acquire);
            if init_pgid != 0 && host_pgid == init_pgid {
                return NS_INIT_PID;
            }
            let init_sid = r.ns.init_host_sid.load(Ordering::Acquire);
```

Replace (in `ns_to_host_pgid`)

```rust
                let init_pgid = r.section.init_host_pgid.load(Ordering::Acquire);
```

with

```rust
                let init_pgid = r.ns.init_host_pgid.load(Ordering::Acquire);
```

Replace (in `refresh_init_host_pgid`)

```rust
        region
            .section
            .init_host_pgid
            .store(pgid as u32, Ordering::Release);
```

with

```rust
        region
            .ns
            .init_host_pgid
            .store(pgid as u32, Ordering::Release);
```

Replace (in `set_init_handler`)

```rust
    if installed {
        r.section
            .init_sig_handlers
            .fetch_or(bits, Ordering::Release);
    } else {
        r.section
            .init_sig_handlers
            .fetch_and(!bits, Ordering::Release);
    }
```

with

```rust
    if installed {
        r.ns.init_sig_handlers.fetch_or(bits, Ordering::Release);
    } else {
        r.ns.init_sig_handlers.fetch_and(!bits, Ordering::Release);
    }
```

Replace (in `init_handles`)

```rust
            carrick_abi::SigSet::from_raw(r.section.init_sig_handlers.load(Ordering::Acquire))
```

with

```rust
            carrick_abi::SigSet::from_raw(r.ns.init_sig_handlers.load(Ordering::Acquire))
```

- [ ] **Step 5: Replace the child/exec free functions**

Replace

```rust
/// Compatibility hook for the retiring host-fork path. Namespace membership is
/// now read directly from the shared kernel arena, so publication needs no
/// registration-pipe wake.
pub fn notify_child_registered() {}

```

with nothing (delete it; `rg -n notify_child_registered crates` finds only this definition).

Replace

```rust
/// Mark the current member as having successfully crossed an `execve(2)` point
/// of no return. Linux uses this to reject a parent changing the process group
/// of its child after the child has executed a new program.
pub fn mark_self_execed() {
    let Some(r) = region() else { return };
    r.mark_execed(std::process::id());
}
```

with

```rust
/// Mark the member `context` names as having crossed an `execve(2)` point of
/// no return. Linux uses this to reject a parent changing the process group of
/// its child after the child has executed a new program. Exec commit runs
/// outside the dispatch scope, so the region comes from the exact task.
pub fn mark_self_execed_for(context: &crate::kernel::KernelContext) {
    let Some(r) = region_for(context) else { return };
    r.mark_execed(std::process::id());
}

/// [`host_to_ns_or_self`] for a caller outside the dispatch scope that holds
/// the exact task (signal delivery in the vCPU loop).
pub fn host_to_ns_or_self_for(context: &crate::kernel::KernelContext, host_pid: u32) -> u32 {
    match region_for(context) {
        Some(r) => r.host_to_ns(host_pid).unwrap_or(0),
        None => host_pid,
    }
}
```

(`join_existing` and `attach_region` are already gone: Task 15 (the Container task) deleted them together with the `CARRICK_JOIN_REGION` branch in `execute.rs`; `rg -n 'join_existing|attach_region|CARRICK_JOIN_REGION' crates --type rust` must print nothing at this point — if it does not, stop and land Task 15 first.)

- [ ] **Step 6: Scope the member table to this namespace**

Replace

```rust
impl NsSharedRegion {
    /// Allocate the next ns-pid (lock-free, monotonic, never recycled — gaps are
    /// harmless, design §8).
    pub fn alloc_ns_pid(&self) -> u32 {
        self.section.next_ns_pid.fetch_add(1, Ordering::SeqCst)
    }

    /// The init's host pid (ns-pid 1), or 0 if unset.
    pub fn init_host_pid(&self) -> u32 {
        self.section.init_host_pid.load(Ordering::Acquire)
    }
```

with

```rust
impl NsSharedRegion {
    /// Allocate the next ns-pid in THIS namespace (lock-free, monotonic, never
    /// recycled — gaps are harmless, design §8).
    pub fn alloc_ns_pid(&self) -> u32 {
        self.ns.next_ns_pid.fetch_add(1, Ordering::SeqCst)
    }

    /// The init's host pid (ns-pid 1), or 0 if unset.
    pub fn init_host_pid(&self) -> u32 {
        self.ns.init_host_pid.load(Ordering::Acquire)
    }
```

In `register`, replace

```rust
        let transition_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if let Some(i) = self.slot_of(host_pid) {
                return Some(i);
            }
            if let Some((i, record)) = self.reusable_record_for(host_pid) {
                fill_member(record, ns_pid, parent_host_pid);
                return Some(i);
            }
```

with

```rust
        let transition_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if let Some(i) = self.slot_of(host_pid) {
                return Some(i);
            }
            // A task belongs to exactly one PID namespace: a host pid that is
            // already a member elsewhere is refused, not waited for.
            if self.is_member_elsewhere(host_pid) {
                return None;
            }
            if let Some((i, record)) = self.reusable_record_for(host_pid) {
                fill_member(record, self.ns_id(), ns_pid, parent_host_pid);
                return Some(i);
            }
```

and replace

```rust
        let generation = KernelArena::global().allocate_generation();
        let claimed = self
            .section
            .claim(Some(HostPid::new(host_pid)), generation, |record| {
                fill_member(record, ns_pid, parent_host_pid);
            })
            .ok()?;
        Some(claimed.index)
    }
```

with

```rust
        let generation = self.arena.allocate_generation();
        let ns_id = self.ns_id();
        let claimed = self
            .section
            .claim(Some(HostPid::new(host_pid)), generation, |record| {
                fill_member(record, ns_id, ns_pid, parent_host_pid);
            })
            .ok()?;
        Some(claimed.index)
    }
```

In `slot_of`, replace

```rust
        self.section.records.iter().position(|s| {
            let ns_pid = s.ns_pid.load(Ordering::Acquire);
            s.host_pid.load(Ordering::Acquire) == host_pid
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
        })
    }
```

with

```rust
        let ns_id = self.ns_id();
        self.section.records.iter().position(|s| {
            let ns_pid = s.ns_pid.load(Ordering::Acquire);
            s.host_pid.load(Ordering::Acquire) == host_pid
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
                && s.pid_ns.load(Ordering::Acquire) == ns_id
        })
    }

    /// Whether `host_pid` is a published member of a DIFFERENT namespace.
    fn is_member_elsewhere(&self, host_pid: u32) -> bool {
        let ns_id = self.ns_id();
        self.section.records.iter().any(|s| {
            let ns_pid = s.ns_pid.load(Ordering::Acquire);
            let tag = s.pid_ns.load(Ordering::Acquire);
            s.host_pid.load(Ordering::Acquire) == host_pid
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
                && tag != 0
                && tag != ns_id
        })
    }
```

In `unregister_reaped`, replace

```rust
            if still_member {
                record.ns_pid.store(0, Ordering::Release);
                record.exec_generation.store(0, Ordering::Release);
```

with

```rust
            if still_member {
                record.ns_pid.store(0, Ordering::Release);
                record.pid_ns.store(0, Ordering::Release);
                record.exec_generation.store(0, Ordering::Release);
```

In `sweep_dead_owner_records`, replace

```rust
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            if ns_pid == NS_PID_REGISTERING || record.transition_claimed() {
                continue;
            }
```

with

```rust
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            if ns_pid == NS_PID_REGISTERING || record.transition_claimed() {
                continue;
            }
            // Another namespace's member is that namespace's to reclaim.
            if ns_pid != 0 && record.pid_ns.load(Ordering::Acquire) != self.ns_id() {
                continue;
            }
```

Replace `member_records`:

```rust
    fn member_records(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.section.records.iter().filter(|record| {
            let host_pid = record.host_pid.load(Ordering::Acquire);
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            host_pid != 0
                && host_pid != HOST_PID_REGISTERING
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
        })
    }
```

with

```rust
    fn member_records(&self) -> impl Iterator<Item = &ProcessRecord> {
        let ns_id = self.ns_id();
        self.section.records.iter().filter(move |record| {
            let host_pid = record.host_pid.load(Ordering::Acquire);
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            host_pid != 0
                && host_pid != HOST_PID_REGISTERING
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
                && record.pid_ns.load(Ordering::Acquire) == ns_id
        })
    }
```

Replace the head of `fill_member`:

```rust
fn fill_member(record: &ProcessRecord, ns_pid: u32, parent_host_pid: u32) {
    record
        .parent_host_pid
        .store(parent_host_pid, Ordering::Relaxed);
```

with

```rust
fn fill_member(record: &ProcessRecord, ns_id: NsId, ns_pid: u32, parent_host_pid: u32) {
    record
        .parent_host_pid
        .store(parent_host_pid, Ordering::Relaxed);
    record.pid_ns.store(ns_id, Ordering::Relaxed);
```

- [ ] **Step 7: Hook the region onto the task through its Container**

In `crates/carrick-runtime/src/kernel/objects.rs` (HEAD `:3027-3029`), replace

```rust
    pub fn net_ns(&self) -> Arc<NetNs> {
        Arc::clone(self.nsproxy.load().net())
    }
```

with

```rust
    pub fn net_ns(&self) -> Arc<NetNs> {
        Arc::clone(self.nsproxy.load().net())
    }

    /// The PID namespace region of this process's container, or `None` when
    /// the container shares the host pid namespace (`--pid host`). This is the
    /// ONLY path from a task to pid translation: `namespace::pid::region()`
    /// resolves the calling task through it, never through a static.
    pub fn pid_ns_region(&self) -> Option<Arc<crate::namespace::pid::NsSharedRegion>> {
        self.container().pid_region()
    }
```

In `crates/carrick-runtime/src/kernel/container.rs` (Task 15's `Container`), add the field and accessors. Task 15 defines `pid_root: OnceLock<TaskKey>` (the ns-init's task key, accessor `pid_root() -> Option<TaskKey>`); the region is a SEPARATE field — both exist, `pid_root` names the init task and `pid_ns` names the numbering region. Add to the struct:

```rust
    /// The PID namespace root's region (`None` = the container shares the
    /// host pid namespace, `PidMode::Host`). Installed once by
    /// `Runtime::execute` before the root task boots; every task reaches it
    /// through `Task::pid_ns_region`. `Container::retire` (Task 23) retires
    /// the namespace's members and releases its arena slot through
    /// `NsSharedRegion::retire`; dropping the last `Arc` is the safety net.
    pid_ns: std::sync::OnceLock<Arc<crate::namespace::pid::NsSharedRegion>>,
```

initialize it as `pid_ns: std::sync::OnceLock::new(),` in BOTH `Container::new(launch: LaunchContext)` and `Container::for_reference_model()` (Task 15's two constructors), and add to `impl Container`:

```rust
    /// Install the container's PID namespace region. Exactly once, before any
    /// task of the container runs; a second install is refused and hands the
    /// region back so the caller cannot silently leak a claimed slot.
    pub(crate) fn install_pid_ns(
        &self,
        region: Arc<crate::namespace::pid::NsSharedRegion>,
    ) -> Result<(), Arc<crate::namespace::pid::NsSharedRegion>> {
        self.pid_ns.set(region)
    }

    /// The container's PID namespace region, `None` under `PidMode::Host`.
    pub(crate) fn pid_region(&self) -> Option<Arc<crate::namespace::pid::NsSharedRegion>> {
        self.pid_ns.get().cloned()
    }
```

- [ ] **Step 8: Delete the old header words from `ProcessSection`**

In `crates/carrick-kernel/src/process.rs`, replace

```rust
#[repr(C)]
pub struct ProcessSection {
    pub next_ns_pid: AtomicU32,
    pub init_host_pid: AtomicU32,
    pub init_host_pgid: AtomicU32,
    pub init_host_sid: AtomicU32,
    pub init_sig_handlers: AtomicU64,
    pub records: [ProcessRecord; PROCESS_RECORDS],
}
```

with

```rust
/// The carrier's ONE process-record table. Namespace numbering words live per
/// namespace in `crate::pidns`; a record's `pid_ns` tag names its owner.
#[repr(C)]
pub struct ProcessSection {
    pub records: [ProcessRecord; PROCESS_RECORDS],
}
```

Delete

```rust
    pub fn allocate_ns_pid(&self) -> u32 {
        self.next_ns_pid.fetch_add(1, Ordering::AcqRel)
    }

```

and delete the test

```rust
    #[test]
    fn ns_pids_are_monotonic_from_2() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        assert_eq!(s.allocate_ns_pid(), 2);
        assert_eq!(s.allocate_ns_pid(), 3);
    }

```

(`rg -n '\.next_ns_pid|\.init_host_pid\b|init_host_pgid|init_host_sid|init_sig_handlers|allocate_ns_pid' crates` confirms no reader of these words outside `process.rs`, `arena.rs` and `namespace/pid.rs`.)

In `crates/carrick-kernel/src/arena.rs`, delete the line

```rust
        layout.processes.next_ns_pid.store(2, Ordering::Relaxed);
```

from `publish_fresh_header`, and in `create_publishes_versioned_header` replace

```rust
        assert_eq!(
            l.processes
                .next_ns_pid
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(l.pid_namespaces.claimed(), 0, "a fresh arena has no namespace");
```

with

```rust
        assert_eq!(l.pid_namespaces.claimed(), 0, "a fresh arena has no namespace");
```

- [ ] **Step 9: Migrate the existing pid.rs tests onto the owned region**

In the `tests` module of `crates/carrick-runtime/src/namespace/pid.rs`:

Replace each of the four occurrences of

```rust
        region.section.init_host_pid.store(100, Ordering::Relaxed);
```

(in `shared_region_alloc_register_translate`, `sweep_releases_records_of_gone_owners_with_no_live_waiter`, `sweep_keeps_records_awaiting_a_live_guest_reap`, `sweep_skips_live_owners_and_tid_entries`) with

```rust
        region.ns.init_host_pid.store(100, Ordering::Relaxed);
```

In `fill_member_preserves_generation_scoped_ptrace_state` (the direct `fill_member` call now needs the tag), replace

```rust
        fill_member(record, 42, 998);
```

with

```rust
        fill_member(record, region.ns_id(), 42, 998);
```

In `public_register_waits_for_in_progress_adoption_instead_of_duplicating`, replace

```rust
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            tx.send(region.register(pid, 43, 998)).unwrap();
        });
```

with

```rust
        let (tx, rx) = std::sync::mpsc::channel();
        let registrar = Arc::clone(&region);
        let join = std::thread::spawn(move || {
            tx.send(registrar.register(pid, 43, 998)).unwrap();
        });
```

and, in the same test, replace

```rust
        record.ns_pid.store(42, Ordering::Release);
        record.release_transition();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("waiting registrar completes after publication"),
            Some(claimed.index)
        );
```

with

```rust
        // Publication now carries the namespace tag: `slot_of` only sees a
        // record tagged with this region's id, so an untagged publish would
        // leave the waiting registrar spinning to its deadline.
        record.pid_ns.store(region.ns_id(), Ordering::Relaxed);
        record.ns_pid.store(42, Ordering::Release);
        record.release_transition();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("waiting registrar completes after publication"),
            Some(claimed.index)
        );
```

In `unregister_reaped_waits_for_member_publication_transition`, replace

```rust
        let claimed = section
            .claim(Some(HostPid::new(pid)), generation, |record| {
                record.ns_pid.store(42, Ordering::Release);
                record.flags.fetch_or(MEMBER_DEAD, Ordering::Relaxed);
            })
            .expect("claim reaped namespace member");
```

with

```rust
        let ns_id = region.ns_id();
        let claimed = section
            .claim(Some(HostPid::new(pid)), generation, |record| {
                record.pid_ns.store(ns_id, Ordering::Relaxed);
                record.ns_pid.store(42, Ordering::Release);
                record.flags.fetch_or(MEMBER_DEAD, Ordering::Relaxed);
            })
            .expect("claim reaped namespace member");
```

and replace

```rust
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            tx.send(region.unregister_reaped(pid)).unwrap();
        });
```

with

```rust
        let (tx, rx) = std::sync::mpsc::channel();
        let reaper = Arc::clone(&region);
        let join = std::thread::spawn(move || {
            tx.send(reaper.unregister_reaped(pid)).unwrap();
        });
```

In `in_progress_registration_slot_is_not_visible`, replace

```rust
        slot.ns_pid.store(2, Ordering::Relaxed);
        slot.parent_host_pid.store(100, Ordering::Relaxed);
        slot.flags.store(MEMBER_ALIVE, Ordering::Relaxed);
```

with

```rust
        slot.pid_ns.store(region.ns_id(), Ordering::Relaxed);
        slot.ns_pid.store(2, Ordering::Relaxed);
        slot.parent_host_pid.store(100, Ordering::Relaxed);
        slot.flags.store(MEMBER_ALIVE, Ordering::Relaxed);
```

In `file_backed_arena_is_shared_across_independent_mappings`, replace

```rust
        a.layout()
            .processes
            .next_ns_pid
            .store(4242, Ordering::Relaxed);
        let b = KernelArena::attach(&path).expect("attach the arena file");
        assert_eq!(
            b.layout().processes.next_ns_pid.load(Ordering::Relaxed),
            4242
        );
```

with

```rust
        a.layout().pid_namespaces.slots[0]
            .next_ns_pid
            .store(4242, Ordering::Relaxed);
        let b = KernelArena::attach(&path).expect("attach the arena file");
        assert_eq!(
            b.layout().pid_namespaces.slots[0]
                .next_ns_pid
                .load(Ordering::Relaxed),
            4242
        );
```

(Task 19 deletes this test with the by-path constructors.)

`reusable_record_claim_has_single_winner`, `sweep_preserves_record_owned_by_namespace_transition`, `unregister_stale_ref_cannot_release_same_numeric_pid_reuse`, `reaped_member_slot_can_be_reused_without_recycling_ns_pid` and the three `sweep_*` cases need no change: they either bypass `slot_of` or register through the region.

- [ ] **Step 10: Run the namespace tests green**

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib namespace::pid::tests`
Expected: `test result: ok.` including `two_regions_in_one_arena_are_disjoint_and_pid_1_names_each_own_init`, `dropping_a_region_releases_its_slot_and_members_for_reuse` and `explicit_retire_releases_once_and_drop_is_then_a_no_op`, and every pre-existing case (`shared_region_alloc_register_translate`, the three `sweep_*`, `reaped_member_slot_can_be_reused_without_recycling_ns_pid`, the transition/adoption cases) `ok`. (This command compiles the `carrick-runtime` lib test target only, which still succeeds; the bin-facing call sites below are what `just check` trips on.)

Run: `cargo test -p carrick-kernel --lib`
Expected: `test result: ok.` (no test references `next_ns_pid` on `processes` any more).

- [ ] **Step 11: Compile-check the callers that still use the deleted free functions — expected RED, resolved by Task 18**

Run: `just check`
Expected: FAILS with `cannot find function` errors (rustc reports E0425 or E0599 depending on path form) for `request` at `execute.rs:233` (HEAD numbering; Task 15's deletion of the `CARRICK_JOIN_REGION` branch shifts it up a few lines); `requested`/`init` at `runtime.rs:621-622` and `threaded_loop.rs:236-237`; `mark_self_execed` at `runtime.rs:1035` and `vcpu_loop/exec.rs:1663`. (`enabled()` is retained, so its ~30 callers do not fail.) These are the run-path wiring Task 18 replaces; do NOT re-add shims and do NOT commit here — proceed directly to Task 18, whose Step 9 commits Tasks 17 and 18 together.

### Task 18: Wire the run path: allocate the Container's pid region at launch, delete the arena env keying, the loop-start `pid::init` fallbacks and the SysV env scope

`Runtime::execute` currently sets `REQUESTED` (`execute.rs:233`), and BOTH `run_address_space_with_hvf_and_dispatcher` (`runtime.rs:616-623`) and `run_threaded_loop_inner` (`threaded_loop.rs:236-238`) later call `pid::init(std::process::id())` if the static says so; the arena is created lazily from `CARRICK_KERNEL_ARENA` or a `CARRICK_RUN_ID`/`CARRICK_CONTAINER_ID`-derived path (`runtime.rs:692-732`, `arena.rs:369-381`). `dispatch/sysv.rs:883-903` (`sysv_run_scope`) independently re-reads `CARRICK_RUN_ID`/`CARRICK_CONTAINER_ID` to scope the host `shm_open`/message-queue names — a process-global answer to a per-container question. This task allocates the region where the container is created, hands it to the `Container`, deletes the statics' call sites and the environment keying, and scopes SysV names by the calling task's `Container` run id. The arena file needs no path at all any more: `rg -n 'KernelArena::attach\(' crates` shows the only product attacher was the `carrick exec` joiner (`join_existing`) that Task 15 (the Container task) deleted, so an embedding host's stray `CARRICK_KERNEL_ARENA` can no longer make the runtime map a foreign arena. (`CARRICK_KERNEL_ARENA` appears nowhere else in the repo except two historical plan docs.)

**Files:**
- Modify: `crates/carrick-runtime/src/execute.rs:4-8` (imports), `:213-236` (pid placement; shorter after Task 15 removed the `CARRICK_JOIN_REGION` branch)
- Modify: `crates/carrick-runtime/src/runtime.rs:615-624` (arena/pid init), `:692-732` (delete `ensure_kernel_arena_path_env`, `kernel_arena_run_scope`), `:1031-1035` (exec mark), `:2396` (test anchor in `namespace_supervisor_launch_surface_is_deleted`)
- Modify: `crates/carrick-runtime/src/threaded_loop.rs:233-238`
- Modify: `crates/carrick-runtime/src/vcpu_loop/signal.rs:614-616`, `:636-637` (both inside the fn whose parameter is `context: &crate::kernel::KernelContext`, `signal.rs:473`)
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs:1663` (HEAD; `committed_context: KernelContext` is bound at `:1490`)
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs:745-757` (`private_name`/`key_name`), `:866-903` (`SYSV_FALLBACK_ROOT_PID`, `init_sysv_run_scope`, `sysv_run_scope`), `:911`, `:1187-1200`, `:1221` (msg-queue paths), `:2331-2334` (`SysvIpcService::init_sysv_run_scope`)
- Modify: `crates/carrick-kernel/src/arena.rs:14-16` (`ARENA_PATH_ENV`), `:195-209` (`init_global`/`global`), `:369-381` (`create_or_attach_from_env`)
- Modify: `crates/carrick-host/src/guest_cpu.rs:372-376`, `crates/carrick-runtime/src/run_state.rs:138-146`, `:309-311` (comment)
- Test: grep assertions + `just test` + a signed guest smoke (HVF, macOS only)

**Interfaces:**
- Consumes: `NsSharedRegion::{allocate, set_init}`, `Container::install_pid_ns`, `pid::{region_for, host_to_ns_or_self_for, mark_self_execed_for}` (Task 17); from Task 15 (the Container task): the `Arc<Container>` that `Runtime::execute` builds as `let container = Arc::new(Container::new(launch))` BEFORE the `SyscallDispatcher` (named `container` below), `Container::run_id(&self) -> &RunId`, `RunId::scope_component(&self) -> String`, `Task::container(&self) -> Arc<Container>`, `KernelContext::container(&self) -> Arc<Container>`, and the `KernelContext`-bearing exec/signal sites already in the tree. `RuntimeError::Configuration(String)` exists (`run_result.rs`, already used at `execute.rs:208`). `crate::dispatch::resources::with_active_context` (existing).
- Produces: `pub fn carrick_kernel::arena::KernelArena::global() -> &'static KernelArena` (the only constructor of the carrier singleton; lazily creates an unlinked temp-file arena). SysV host names are scoped by `task.container().run_id().scope_component()` (private `dispatch::sysv::sysv_scope()` resolves the calling task through `with_active_context`; outside a dispatch scope it falls back to `pid-<carrier pid>`, the same stamp `LaunchContext::from_process_env` mints). Deleted: `KernelArena::init_global`, `KernelArena::create_or_attach_from_env`, `ARENA_PATH_ENV`, `runtime::ensure_kernel_arena_path_env`, `runtime::kernel_arena_run_scope`, `dispatch::sysv::{sysv_run_scope, init_sysv_run_scope (free fn and method), SYSV_FALLBACK_ROOT_PID}`. (`CARRICK_JOIN_REGION`/`join_existing`/`attach_region` were deleted by Task 15, not here.)

- [ ] **Step 1: Red grep assertion**

Run:

```bash
rg -n 'namespace::pid::(request|requested|init|mark_self_execed)\(|ARENA_PATH_ENV|ensure_kernel_arena_path_env|kernel_arena_run_scope|KernelArena::init_global\(|sysv_run_scope|SYSV_FALLBACK_ROOT_PID' crates --type rust
```

Expected (red, verified at HEAD with Task 15's deletions and Task 17's pid.rs rewrite applied): 33 hits — `arena.rs:16,370`; `guest_cpu.rs:375`; `threaded_loop.rs:236,237`; `run_state.rs:139,145,310`; `execute.rs:233` (HEAD numbering; a few lines earlier after Task 15); `vcpu_loop/exec.rs:1663`; `runtime.rs:616,620,621,622,692,693,699,713,718,1035` and `runtime.rs:2396` (a string literal inside the test `namespace_supervisor_launch_surface_is_deleted`, handled in Step 3); `dispatch/sysv.rs:749,756,868,874,883,911,1190,1196,1200,1221,2332,2333`. The assertion passes when this command prints nothing.

- [ ] **Step 2: Allocate the region where the container is created**

In `crates/carrick-runtime/src/execute.rs`, replace the imports

```rust
use crate::dispatch::SyscallDispatcher;
#[cfg(feature = "fs-memory")]
use crate::fs_backend::MemoryBackend;
use crate::fs_backend::{FsBackend, HostFsBackend};
use crate::network::NetworkHostsEntry;
```

with

```rust
use crate::dispatch::SyscallDispatcher;
#[cfg(feature = "fs-memory")]
use crate::fs_backend::MemoryBackend;
use crate::fs_backend::{FsBackend, HostFsBackend};
use crate::namespace::pid::NsSharedRegion;
use crate::network::NetworkHostsEntry;
use carrick_kernel::arena::KernelArena;
```

and replace the placement block as Task 15 left it (Task 15 deleted the `CARRICK_JOIN_REGION` branch, so the `PidMode::Private` arm is the bare `request()` call; re-derive the exact text against the post-Task-15 tree)

```rust
        // Container launch (`carrick run <image>`) places the root guest in a
        // fresh PID namespace so its init sees getpid()==1, ns-local child
        // pids, and an ns-filtered /proc — the headline docker-run behavior
        // (docs/namespaces-design.md §1.0, §5.2). `run-elf` bypasses
        // Runtime::execute entirely, so it stays in the identity namespace.
        // `--pid=host` opts out (shares the host pid ns, like docker). Private
        // placement is always initialized inside the single VM carrier; output
        // mode never creates a host namespace-supervisor process.
        match spec.pid {
            PidMode::Host => {} // share the host pid ns — no placement.
            PidMode::Private => {
                crate::namespace::pid::request();
            }
        }
```

with

```rust
        // Container launch (`carrick run <image>`) places the root guest in a
        // fresh PID namespace so its init sees getpid()==1, ns-local child
        // pids, and an ns-filtered /proc — the headline docker-run behavior
        // (docs/namespaces-design.md §1.0, §5.2). `run-elf` bypasses
        // Runtime::execute entirely, so it stays in the identity namespace.
        // `--pid=host` opts out (shares the host pid ns, like docker). The
        // namespace is the CONTAINER's: one region claimed from the carrier
        // arena, released when the container is retired at run end.
        if let PidMode::Private = spec.pid {
            let region = NsSharedRegion::allocate(KernelArena::global()).map_err(|error| {
                RuntimeError::Configuration(format!(
                    "allocate the container's pid namespace region: {error:?}"
                ))
            })?;
            // The ns-init's record key. The kernel graph answers `getpid` for
            // every task in a dispatch scope; this registration serves the
            // out-of-scope fallbacks and ns-pgid 1, exactly as before.
            region.set_init(std::process::id());
            if container.install_pid_ns(region).is_err() {
                return Err(RuntimeError::Configuration(
                    "container already has a pid namespace region".to_owned(),
                ));
            }
        }
```

(`container` is the `Arc<Container>` that Task 15 (the Container task) constructs in this function as `let container = Arc::new(Container::new(launch))` before the `SyscallDispatcher` is built. At HEAD no `Container` type exists, so this block cannot compile before Task 15; if Task 15 constructs the container LATER than this point (line 213 is before the fs-backend/dispatcher setup), move this block to just after that construction rather than constructing a second `Container` or an earlier one. `if let PidMode::Private = spec.pid` does not move out of `spec` — unit-variant pattern on a place expression; `PidMode` is already matched by value at this site today.)

- [ ] **Step 3: Delete the loop-start fallbacks and the arena env keying in the runtime**

In `crates/carrick-runtime/src/runtime.rs`, replace

```rust
    let _ = crate::ulock::preinit_waiter_table();
    ensure_kernel_arena_path_env()?;
    // The carrier owns the kernel arena and PID-namespace placement directly.
    // Guest fork/clone creates logical Carrick-kernel tasks, never a host
    // namespace-supervisor process.
    let _ = carrick_kernel::arena::KernelArena::init_global();
    if crate::namespace::pid::requested() && !crate::namespace::pid::enabled() {
        let _ = crate::namespace::pid::init(std::process::id());
    }
    let container_id = std::env::var("CARRICK_CONTAINER_ID").ok();
```

with

```rust
    let _ = crate::ulock::preinit_waiter_table();
    // The carrier owns the kernel arena; the container's PID-namespace region
    // was claimed from it by `Runtime::execute` before this image was built.
    let _ = carrick_kernel::arena::KernelArena::global();
    let container_id = std::env::var("CARRICK_CONTAINER_ID").ok();
```

Delete the two functions verbatim (`AddressSpaceError` stays imported — it is used at `runtime.rs:259,479,500,741`):

```rust
fn ensure_kernel_arena_path_env() -> Result<(), RuntimeError> {
    if std::env::var_os(carrick_kernel::arena::ARENA_PATH_ENV).is_some() {
        return Ok(());
    }

    let dir = std::env::temp_dir()
        .join("carrick-kernel")
        .join(kernel_arena_run_scope());
    std::fs::create_dir_all(&dir).map_err(|err| {
        RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
            err.kind(),
            format!(
                "failed to create kernel arena directory {}: {err}",
                dir.display()
            ),
        )))
    })?;
    let path = dir.join("arena");
    // SAFETY: this runs during runtime preinit, before Carrick starts guest
    // threads. Fork descendants and late exec attachers inherit the path.
    unsafe {
        std::env::set_var(carrick_kernel::arena::ARENA_PATH_ENV, &path);
    }
    Ok(())
}

fn kernel_arena_run_scope() -> String {
    let raw = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| {
        std::env::var("CARRICK_CONTAINER_ID")
            .unwrap_or_else(|_| format!("pid-{}", std::process::id()))
    });
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

```

(The `pid-<pid>` fallback stamp that `kernel_arena_run_scope` minted now lives in exactly one place: `LaunchContext::from_process_env()` from Task 15, which yields `RunId::new(format!("pid-{}", std::process::id()))` when `CARRICK_RUN_ID` is absent or empty.)

The test `namespace_supervisor_launch_surface_is_deleted` (`runtime.rs:2378`) slices the launch function's source by splitting on the literal name of the function that FOLLOWS it; with `ensure_kernel_arena_path_env` gone, `split(..).next()` would silently return the rest of the file. Re-anchor it on the function that now follows (`fn with_hvf_syscall_mailbox`, `runtime.rs:741`): replace

```rust
            .and_then(|tail| tail.split("fn ensure_kernel_arena_path_env").next())
```

with

```rust
            .and_then(|tail| tail.split("fn with_hvf_syscall_mailbox").next())
```

Replace (single-threaded fixture loop, exec commit; `exec_context` is the `crate::kernel::KernelContext` returned by `commit_one_task_kernel_exec`, `dispatch/mod.rs:3968-3971`)

```rust
                        let exec_context = dispatcher
                            .commit_one_task_kernel_exec(prepared_kernel_exec)
                            .map_err(RuntimeError::Configuration)?;
                        prepared_dispatch_mm_exec.commit();
                        crate::namespace::pid::mark_self_execed();
```

with

```rust
                        let exec_context = dispatcher
                            .commit_one_task_kernel_exec(prepared_kernel_exec)
                            .map_err(RuntimeError::Configuration)?;
                        prepared_dispatch_mm_exec.commit();
                        crate::namespace::pid::mark_self_execed_for(&exec_context);
```

In `crates/carrick-runtime/src/threaded_loop.rs`, delete

```rust
    // PID-namespace launch-placement fallback (container path only; a no-op when
    // not requested → kick+futex backends unaffected): if the ns supervisor fork
    // was skipped, identity-init so getpid()==1 still holds.
    if crate::namespace::pid::requested() && !crate::namespace::pid::enabled() {
        let _ = crate::namespace::pid::init(std::process::id());
    }
```

- [ ] **Step 4: Pass the exact task at the two out-of-scope call sites**

In `crates/carrick-runtime/src/vcpu_loop/signal.rs` (`context: &crate::kernel::KernelContext` is the enclosing function's parameter and is already used at `:607`), replace

```rust
                                let ns_pid =
                                    crate::namespace::pid::host_to_ns_or_self(info.host_pid as u32)
                                        as i32;
```

with

```rust
                                let ns_pid = crate::namespace::pid::host_to_ns_or_self_for(
                                    context,
                                    info.host_pid as u32,
                                ) as i32;
```

and replace

```rust
                        let ns_pid =
                            crate::namespace::pid::host_to_ns_or_self(sender_host as u32) as i32;
```

with

```rust
                        let ns_pid = crate::namespace::pid::host_to_ns_or_self_for(
                            context,
                            sender_host as u32,
                        ) as i32;
```

In `crates/carrick-runtime/src/vcpu_loop/exec.rs` (HEAD `:1663`; `committed_context` is bound at `:1490` from `commit_one_task_kernel_exec`), replace

```rust
        crate::namespace::pid::mark_self_execed();
        // execve_into rebuilt a fresh vCPU: re-stamp the identity page
```

with

```rust
        crate::namespace::pid::mark_self_execed_for(&committed_context);
        // execve_into rebuilt a fresh vCPU: re-stamp the identity page
```

- [ ] **Step 5: Scope SysV host names by the calling task's container (red test first)**

`sysv_run_scope()` re-reads `CARRICK_RUN_ID`/`CARRICK_CONTAINER_ID` per call and falls back to a frozen carrier pid; under two containers in one carrier both would name the same `shm_open` prefix. The scope is the container's `RunId` (Task 15, `RunId::scope_component` — the same sanitizer `kernel_arena_run_scope` applied), resolved through the calling task.

Append to the `tests` module at the end of `crates/carrick-runtime/src/dispatch/sysv.rs` (the module already has `use super::*;`):

```rust
    #[test]
    fn sysv_scope_outside_a_dispatch_scope_is_the_carrier_pid_stamp() {
        // No task is in flight on a test thread, so the scope is the same
        // `pid-<carrier>` stamp `LaunchContext::from_process_env` would mint —
        // never an environment read.
        assert_eq!(sysv_scope(), format!("pid-{}", std::process::id()));
    }

    #[test]
    fn sysv_scope_inside_a_dispatch_scope_is_the_container_run_id() {
        let container = std::sync::Arc::new(crate::kernel::Container::new(
            crate::kernel::LaunchContext::unmanaged(crate::kernel::RunId::new("run/one")),
        ));
        let expected = container.run_id().scope_component();
        assert_eq!(expected, "run_one", "RunId::scope_component sanitizes the stamp");
        let observed = crate::kernel::reference_model::with_container_context(
            container,
            sysv_scope,
        );
        assert_eq!(observed, expected);
    }
```

(`with_container_context` is the reference-model helper that runs a closure inside a dispatch scope whose active `KernelContext` names a root task of the given container — use whatever Task 15 named that helper in `kernel/reference_model.rs`; if Task 15 provides none, build the scope with `SyscallDispatcher::for_reference_model()` + `set_container(container)` and the existing `dispatch::resources::with_resources`-style scope guard that publishes a context.)

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::sysv::tests::sysv_scope`
Expected: `error[E0425]: cannot find function \`sysv_scope\` in this scope`.

Then in `crates/carrick-runtime/src/dispatch/sysv.rs` replace

```rust

static SYSV_FALLBACK_ROOT_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Freeze the no-run-id SysV IPC scope before creating the first guest
/// process. Descendants must keep using the top-level runtime pid: recomputing
/// `pid-{getpid()}` after a host fork splits one guest IPC namespace into one
/// directory namespace per process.
#[allow(dead_code)]
pub(crate) fn init_sysv_run_scope() {
    let _ = SYSV_FALLBACK_ROOT_PID.compare_exchange(
        0,
        std::process::id(),
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    );
}

fn sysv_run_scope() -> String {
    let raw = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| {
        std::env::var("CARRICK_CONTAINER_ID").unwrap_or_else(|_| {
            let frozen = SYSV_FALLBACK_ROOT_PID.load(std::sync::atomic::Ordering::Acquire);
            let root_pid = if frozen == 0 {
                std::process::id()
            } else {
                frozen
            };
            format!("pid-{root_pid}")
        })
    });
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
```

with

```rust

/// The host-name scope of the CALLING task's SysV IPC namespace: its
/// container's run id (`RunId::scope_component`), so two containers in one
/// carrier never share a `shm_open`/message-queue prefix. Outside a dispatch
/// scope there is no task to ask; the carrier's own `pid-<pid>` stamp (the
/// one `LaunchContext::from_process_env` mints) is the honest fallback and
/// never an environment read.
fn sysv_scope() -> String {
    crate::dispatch::resources::with_active_context(|context| {
        context.task().container().run_id().scope_component()
    })
    .unwrap_or_else(|| format!("pid-{}", std::process::id()))
}
```

Replace every remaining `sysv_run_scope()` call with `sysv_scope()` — in `private_name` (`:749`), `key_name` (`:756`), `scoped_host_sem_key` (`:911`), `msg_queue_path_for_private` (`:1190`), `msg_queue_path_for_key` (`:1196`), `msg_queue_path_for_id` (`:1200`) and `msg_queue_scope_prefix` (`:1221`) — and delete the method

```rust
    #[allow(dead_code)]
    pub(crate) fn init_sysv_run_scope(&self) {
        init_sysv_run_scope();
    }

```

from `impl SysvIpcService` (`rg -n 'init_sysv_run_scope' crates` finds no caller of either form outside `sysv.rs`).

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::sysv`
Expected: `test result: ok.` including both `sysv_scope_*` cases and every pre-existing `sysv` test.

- [ ] **Step 6: Make `KernelArena::global()` the only constructor and drop the env**

In `crates/carrick-kernel/src/arena.rs`, replace

```rust
pub const ARENA_MAGIC: u32 = 0x434b_4131;
/// Bumped to 5 when `pid_namespaces` was appended and `ProcessRecord` gained
/// `pid_ns`; a version-4 file is refused by `attach` (fail closed).
pub const ARENA_VERSION: u32 = 5;
pub const ARENA_PATH_ENV: &str = "CARRICK_KERNEL_ARENA";
```

with

```rust
pub const ARENA_MAGIC: u32 = 0x434b_4131;
/// Bumped to 5 when `pid_namespaces` was appended and `ProcessRecord` gained
/// `pid_ns`; a version-4 file is refused by `attach` (fail closed).
pub const ARENA_VERSION: u32 = 5;
```

replace

```rust
    /// Process-wide singleton. Must be initialized before the first guest fork;
    /// repeated calls return the same inherited mapping.
    #[allow(clippy::panic)]
    pub fn init_global() -> &'static KernelArena {
        GLOBAL.get_or_init(|| match KernelArena::create_or_attach_from_env() {
            Ok(arena) => arena,
            Err(err) => {
                panic!("carrick-kernel arena creation failed: {err}");
            }
        })
    }

    pub fn global() -> &'static KernelArena {
        Self::init_global()
    }
```

with

```rust
    /// The carrier's ONE arena: created on first use as an unlinked temp file
    /// and shared by every container that runs in this process. Nothing
    /// outside the carrier attaches to it (the `carrick exec` joiner is gone),
    /// so its identity is the carrier, never an environment variable.
    /// `OnceLock` serializes concurrent first callers (two `Runtime::execute`
    /// calls racing in one carrier get the same arena; Task 23 relies on this
    /// instead of any env-setting wrapper).
    #[allow(clippy::panic)]
    pub fn global() -> &'static KernelArena {
        GLOBAL.get_or_init(|| match KernelArena::create() {
            Ok(arena) => arena,
            Err(err) => {
                panic!("carrick-kernel arena creation failed: {err}");
            }
        })
    }
```

and delete

```rust
    fn create_or_attach_from_env() -> std::io::Result<KernelArena> {
        match std::env::var_os(ARENA_PATH_ENV) {
            Some(path) => {
                let path = Path::new(&path);
                if path.exists() {
                    Self::attach(path)
                } else {
                    Self::create_at(path)
                }
            }
            None => Self::create(),
        }
    }

```

(`use std::path::Path` stays: `create_at`, `attach` and `create_with_path` still take it until Task 19.)

In `crates/carrick-host/src/guest_cpu.rs`, replace

```rust
pub fn init_child_table() {
    let _ = KernelArena::init_global();
}
```

with

```rust
pub fn init_child_table() {
    let _ = KernelArena::global();
}
```

In `crates/carrick-runtime/src/run_state.rs`, replace

```rust
fn processes() -> &'static ProcessSection {
    &KernelArena::init_global().layout().processes
}

/// Ensure the arena exists before the first guest fork (so every descendant
/// inherits the SAME mapping). Idempotent. Called once at loop start.
pub fn init_table() {
    let _ = KernelArena::init_global();
}
```

with

```rust
fn processes() -> &'static ProcessSection {
    &KernelArena::global().layout().processes
}

/// Ensure the arena exists before the first guest fork (so every descendant
/// inherits the SAME mapping). Idempotent. Called once at loop start.
pub fn init_table() {
    let _ = KernelArena::global();
}
```

and replace the comment lines

```rust
    // This `ProcessSection` is SHARED with the PID-namespace member table —
    // `namespace/pid.rs` takes `&KernelArena::init_global().layout().processes`,
    // the same object `processes()` returns — and `claim_record` will happily
```

with

```rust
    // This `ProcessSection` is SHARED with the PID-namespace member table —
    // every container's `NsSharedRegion` holds `&KernelArena::global()
    // .layout().processes`, the same object `processes()` returns, scoped by
    // the record's `pid_ns` tag — and `claim_record` will happily
```

- [ ] **Step 7: Green grep assertion, compile, and host tests**

Run the Step 1 command again.
Expected: no output.

Run: `just check`
Expected: exit 0 (this is where Task 17's Step 11 failures resolve).

Run: `just test`
Expected: every lane `test result: ok.` — in particular `carrick-runtime`'s `namespace::pid::tests::*`, `dispatch::sysv::tests::*`, `run_state::*`, `runtime::tests::namespace_supervisor_launch_surface_is_deleted` (re-anchored), and `execute::tests::hvpatch_uses_container_entrypoint_resolution` (`execute.rs:894`; it uses `PidMode::Host`, so no region is claimed and exit 127 is still classified).

Run: `just clippy && just lint-domains`
Expected: both exit 0 (`scripts/migrate/check-carrier-only-process-invariant.py`, run by `scripts/lint-domains.sh`, stays green — no new process-creation site).

- [ ] **Step 8: Live-verify on a signed artifact (macOS/HVF only)**

Requires the codesigned binary (Rule 0). `--pid` is a clap `value_enum` over `PidMode` (`carrick-cli/src/args.rs:421`), so `--pid host` is the spelling. Run:

```bash
just build
CARRICK_RUN_ID=b2-pidns-smoke target/release/carrick run ubuntu:24.04 sh -c 'echo pid=$$; grep -E "^(Pid|PPid):" /proc/$$/status; sh -c "echo child=\$\$"'
```

Expected: `pid=1`, then `Pid:\t1` and `PPid:\t0` (the shell's OWN status — `/proc/self/status` would be `grep`'s, a child with pid > 1), then `child=<n>` with `n > 1` (ns-local child numbering); exit 0. Then:

```bash
CARRICK_RUN_ID=b2-pidns-smoke-host target/release/carrick run --pid host ubuntu:24.04 sh -c 'echo pid=$$'
```

Expected: a value other than `1` (identity namespace, unchanged behaviour). Then run the first command a second time and confirm `pid=1` again (a fresh region per run), and confirm the runtime no longer reads `CARRICK_KERNEL_ARENA`:

```bash
CARRICK_KERNEL_ARENA=/nonexistent/arena CARRICK_RUN_ID=b2-pidns-smoke-env target/release/carrick run ubuntu:24.04 sh -c 'echo pid=$$'
```

Expected: `pid=1`, exit 0 (before this task, `create_or_attach_from_env` would have tried `create_at(/nonexistent/arena)` and the `init_global` panic killed the run). Then confirm SysV names are scoped by the container's run id rather than the environment:

```bash
CARRICK_RUN_ID=b2-sysv-smoke target/release/carrick run ubuntu:24.04 sh -c 'ipcmk -M 4096 >/dev/null && ipcs -m | tail -n +4 | grep -c .'
ls /dev/shm 2>/dev/null | grep -c 'b2-sysv-smoke' || ls "$(target/release/carrick debug shm-dir 2>/dev/null || echo /tmp/carrick-shm)" | grep -c 'b2-sysv-smoke'
```

Expected: the guest prints `1` (one segment visible) and the host-side segment name is prefixed `b2-sysv-smoke-` (the `RunId::scope_component` of the run id); if the SHM directory lookup line does not apply on this host, read `SHM_DIR` from `dispatch/sysv.rs` and list it directly. Reap with `scripts/sudo/kill.sh b2-pidns-smoke` (and the `-host`/`-env`/`b2-sysv-smoke` ids) if anything is left.

- [ ] **Step 9: Format and commit Tasks 17 + 18 as one change**

```bash
just fmt
git add crates/carrick-runtime/src/namespace/pid.rs crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/kernel/container.rs crates/carrick-kernel/src/process.rs crates/carrick-kernel/src/arena.rs crates/carrick-runtime/src/execute.rs crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/threaded_loop.rs crates/carrick-runtime/src/vcpu_loop/signal.rs crates/carrick-runtime/src/vcpu_loop/exec.rs crates/carrick-runtime/src/dispatch/sysv.rs crates/carrick-runtime/src/run_state.rs crates/carrick-host/src/guest_cpu.rs
git commit -F- <<'EOF'
refactor(runtime): own the pid-namespace region per container

Why: `namespace::pid` kept `static REGION`/`REQUESTED`, set once per
process and never reset, and every ns-pid translation read them;
`Runtime::execute` requested placement through that static and two
loop-start sites initialised it with the carrier pid, over an arena
created from `CARRICK_KERNEL_ARENA` or a `CARRICK_RUN_ID`/
`CARRICK_CONTAINER_ID` temp path, and `dispatch/sysv.rs` re-read the
same variables to scope host SysV names. All of that was true under
one-host-process-per-guest and is wrong the moment a second container
runs in the carrier: both would share one `next_ns_pid`, both would
register ns-pid 1, `ns_to_host(1)` could name either init, and both
would `shm_open` under one prefix (docs/identity-and-scope-domains.md,
the scope domain). The env read also let an embedding host's stray
variable point the runtime at a foreign arena.

What: `NsSharedRegion` is now an owned object — one per container,
claiming a `carrick_kernel::pidns` slot for its numbering words and
tagging its member records with its namespace id — so member lookups
(`host_to_ns`, `ns_to_host`, `slot_of`, the sweep) are scoped to one
namespace and a host pid can belong to exactly one. It is allocated
from the carrier arena where the container is created (`PidMode::
Private` only), the ns-init is registered there, and the `Arc` is
installed on the `Container` next to its `pid_root`; container
teardown calls `NsSharedRegion::retire` (explicit member retire + slot
release, consumed by `carrier::retire_container`) and `Drop` is the
safety net. `region()` resolves the CALLING task's region through
`Task::pid_ns_region` → `Container::pid_region` from the active
dispatch context; signal delivery and exec commit, which run outside
that scope, pass their exact `KernelContext` (`region_for`,
`host_to_ns_or_self_for`, `mark_self_execed_for`). SysV host names are
scoped by `task.container().run_id().scope_component()`
(`sysv_scope`), replacing `sysv_run_scope` and its frozen carrier pid.
The five namespace words leave `ProcessSection`; the loop-start
`pid::init` fallbacks, `notify_child_registered`, the arena path env
and its scope helper are deleted; `KernelArena::global()` is the one
constructor and always maps an unlinked temp file — the only
cross-process attacher (`carrick exec`'s joiner) was retired in
af6270ce and its `join_existing` removed with the Container.

Verified: red-first unit tests — two regions in one arena are disjoint
and ns-pid 1 names each region's own init; dropping a region releases
its slot, retires its members and a third region reuses the slot with
fresh numbering; an explicit `retire` releases exactly once while
another holder is alive; `sysv_scope` yields the container run id in
scope and the carrier pid stamp outside — failed to compile against the
static design and pass now; every pre-existing `namespace::pid` and
`dispatch::sysv` case passes (four were re-tagged for the scoped
`slot_of`). The grep assertion over `pid::{request,init,
mark_self_execed}`, `ARENA_PATH_ENV`, `init_global` and
`sysv_run_scope` is empty; `just test`, `just clippy`,
`just lint-domains` green; on the signed artifact `carrick run
ubuntu:24.04 sh -c 'echo $$'` prints 1 with a >1 child and `--pid host`
does not, a bogus `CARRICK_KERNEL_ARENA` in the environment no longer
affects the run, and a guest `ipcmk` segment is named by the run id.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 19: Delete the dead arena attach/reexec surface and the registry `region_path`

With no attacher left, `KernelArena::{create_at, attach, reexec_authority, init_global_from_reexec, attach_reexec}` and `KernelArenaReexecAuthority` have zero product callers (`rg -n 'KernelArenaReexecAuthority|init_global_from_reexec\(|KernelArena::attach\(|KernelArena::create_at\(' crates` finds only `arena.rs` and one `pid.rs` test; the `*_reexec_authority` names in `carrick-host/src/ulock.rs` and `fs_backend.rs` are DIFFERENT types and stay), and `RunConfig.region_path` — persisted so `carrick exec` could attach — is only ever set to `None` and cleared (its one runtime writer, `persist_detached_arena_path`, went in Task 17). Per AGENTS.md ("delete it; git is the version control"), remove them.

**Files:**
- Modify: `crates/carrick-kernel/src/arena.rs:27-34` (`KernelArenaReexecAuthority`), `:132-138` (`create_at`), `:139-193` (`attach`), `:211-363` (`reexec_authority`, `init_global_from_reexec`, `attach_reexec`), `:383` (`create_with_path` signature; line shifts after Task 18's deletions), tests `:583-634`
- Modify: `crates/carrick-runtime/src/container.rs:192-193`, `:282`, tests `:1001`, `:1027`, `:1044`
- Modify: `crates/carrick-cli/src/lifecycle.rs:50-54`, `:444-445`, `:498`, `:903-907`, `:1027-1028`, `:1037`, `:2555`, `:3048`
- Modify: `crates/carrick-runtime/src/namespace/pid.rs` test `file_backed_arena_is_shared_across_independent_mappings`
- Test: grep assertion + `just test`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub fn KernelArena::create() -> io::Result<KernelArena>` remains the only constructor besides `global()`. Deleted: `KernelArena::{create_at, attach, reexec_authority, init_global_from_reexec, attach_reexec}`, `KernelArenaReexecAuthority`, `RunConfig.region_path`.

- [ ] **Step 1: Red grep assertion**

Run:

```bash
rg -n 'region_path|KernelArenaReexecAuthority|init_global_from_reexec|fn attach_reexec|fn create_at|KernelArena::attach\(|fn attach\(path: &Path\) -> std::io::Result<KernelArena>' crates --type rust
```

(The pattern names the kernel signature exactly: a bare `pub fn attach\(` would also match the unrelated `HostFsBackend::attach` at `fs_backend.rs:2491` and the assertion could never go green.)

Expected (red): hits in `arena.rs` (struct `:28`, `create_at` `:135`, `attach` `:140`, `reexec_authority` `:211,221`, `init_global_from_reexec` `:233-234`, `attach_reexec` `:281`, tests `:588,593,610,616-623`), `container.rs` (`:193,282,1001,1027,1044`), `lifecycle.rs` (`:51,444,498,905,1027,1037,2555,3048`), `pid.rs` (`:1323,1328`, the file-backed test). Passes when empty.

- [ ] **Step 2: Delete the attach/reexec surface from the arena**

In `crates/carrick-kernel/src/arena.rs` delete, verbatim: the `KernelArenaReexecAuthority` struct (lines 27-34); `create_at` with its doc comment (132-138) and `attach` (139-193); `reexec_authority` (211-231), `init_global_from_reexec` (233-279) and `attach_reexec` (281-363); and the tests `attach_joins_an_existing_arena`, `attach_rejects_wrong_magic`, `reexec_authority_reattaches_exact_unlinked_arena_and_rejects_identity_change`. Then replace

```rust
    pub fn create() -> std::io::Result<KernelArena> {
        let serial = ARENA_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "carrick-kernel-arena-{}-{serial}",
            std::process::id()
        ));
        Self::create_with_path(&path, true)
    }
```

with

```rust
    pub fn create() -> std::io::Result<KernelArena> {
        let serial = ARENA_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "carrick-kernel-arena-{}-{serial}",
            std::process::id()
        ));
        Self::create_with_path(&path)
    }
```

and replace

```rust
    fn create_with_path(path: &Path, unlink_on_success: bool) -> std::io::Result<KernelArena> {
```

with

```rust
    fn create_with_path(path: &Path) -> std::io::Result<KernelArena> {
```

and replace

```rust
        if unlink_on_success {
            unsafe {
                libc::unlink(cpath.as_ptr());
            }
        }
```

with

```rust
        // Nothing attaches by path: the mapping is the only handle.
        unsafe {
            libc::unlink(cpath.as_ptr());
        }
```

(`use std::path::Path` and `use std::os::unix::ffi::OsStrExt` remain used by `create_with_path`.)

Delete the test `file_backed_arena_is_shared_across_independent_mappings` from `crates/carrick-runtime/src/namespace/pid.rs` (it exercised the deleted `create_at`/`attach` pair for the retired exec joiner).

- [ ] **Step 3: Delete `region_path`**

In `crates/carrick-runtime/src/container.rs` delete

```rust
    /// File-backed PID region path, `mmap`'d by `exec` to join the namespace.
    pub region_path: Option<String>,
```

and the default `region_path: None,` at line 282, and in the tests delete the line `assert!(s.config.region_path.is_none());` (`:1001`), the line `s2.config.region_path = Some("/p/region".into());` (`:1027`), and the line `assert_eq!(round.config.region_path.as_deref(), Some("/p/region"));` (`:1044`).

In `crates/carrick-cli/src/lifecycle.rs`: delete `region_path: None,` (line 498) and `state.config.region_path = None;` (line 1037); delete

```rust
    // A relaunch creates a FRESH carrier + region; unlink the stale region file
    // so alloc_region maps a clean, seeded one (a reused file keeps dead members).
    if let Some(region) = &state.config.region_path {
        let _ = std::fs::remove_file(region);
    }
```

delete `region_path: Some("/r".into()),` (line 2555) and `assert_eq!(s.config.region_path, None);` (line 3048); and replace the module doc lines

```rust
//! entrypoint. `reset_for_relaunch` clears volatile state (status/pids and the
//! stale `exit_code` and `region_path`) while preserving the overlay path and
//! the stop config. A relaunch creates a *fresh* carrier + compatibility region
//! over the *same* overlay, which is why the stale region file is unlinked first (a
//! reused region keeps dead members).
```

with

```rust
//! entrypoint. `reset_for_relaunch` clears volatile state (status/pids and the
//! stale `exit_code`) while preserving the overlay path and the stop config. A
//! relaunch creates a *fresh* carrier, whose kernel arena and pid-namespace
//! region are private to it, over the *same* overlay.
```

and replace

```rust
/// relaunch inputs into RunConfig. scratch_path/region_path are filled in by the
/// runtime once the launched child sets up its overlay + region.
```

with

```rust
/// relaunch inputs into RunConfig. `scratch_path` is filled in by the runtime
/// once the launched carrier sets up its overlay.
```

and replace

```rust
/// `Some(code)` would otherwise persist into the new Running entry; region_path
/// is cleared because the relaunch maps a fresh region.
```

with

```rust
/// `Some(code)` would otherwise persist into the new Running entry.
```

- [ ] **Step 4: Green assertion and gates**

Run the Step 1 grep again.
Expected: no output.

Run: `just check && cargo test -p carrick-kernel --lib && env RUST_MIN_STACK=8388608 cargo test -p carrick-cli --bin carrick lifecycle`
Expected: all exit 0 (that is how the `justfile`'s `test` recipe already runs the CLI's in-file tests, `justfile:181`; the bin target is `carrick`); the `lifecycle` tests (`reset_for_relaunch*`, `build_created_state*`) pass without the field.

Run: `just ci`
Expected: the full gate `fmt-check → clippy → lint-domains → deny → check-matrix → check → doc → test → test-integration` exits 0.

- [ ] **Step 5: Commit**

```bash
just fmt
git add crates/carrick-kernel/src/arena.rs crates/carrick-runtime/src/container.rs crates/carrick-runtime/src/namespace/pid.rs crates/carrick-cli/src/lifecycle.rs
git commit -F- <<'EOF'
refactor(kernel): delete the arena attach and reexec surface

Why: `KernelArena::{create_at, attach}` existed so a `carrick exec`
process could map the container's region file, and the reexec
authority existed for the host self-re-exec. Both consumers are gone
(af6270ce, 36d141d6) and `rg` finds no product caller; `RunConfig
.region_path` was persisted for that same attacher and is now only
ever `None`. A path nobody attaches to is a leaked file per run and a
second answer to "which arena is this" that every reader has to
reconcile with the carrier singleton.

What: remove the by-path constructors, the reexec authority and their
tests; `create()` always unlinks its file after mapping; drop
`region_path` from the registry schema and the CLI's stale-file unlink
on relaunch.

Verified: the grep assertion over the deleted names is empty; `just
ci` green.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```


<details><summary>Verifier problems fixed in place (10) and claims still unverified (6)</summary>

- fixed: Base revision: the draft cites HEAD as 3dc6cc72 but the checkout's HEAD is ea0dac4c (35 commits ahead; 3dc6cc72 is an ancestor). Of the cited files only crates/carrick-runtime/src/kernel/objects.rs and crates/carrick-runtime/src/vcpu_loop/exec.rs changed: `Task::net_ns` is now at objects.rs:3027-3029 (draft: 3018-3025) and `crate::namespace::pid::mark_self_execed()` is at vcpu_loop/exec.rs:1663 (draft: 1499). Line references updated to HEAD; every quoted code block was re-verified byte-exact at HEAD.
- fixed: Task 13 Step 9 misses four pre-existing pid.rs tests that break once `fill_member` gains an `ns_id` parameter and `slot_of`/`member_records` require the `pid_ns` tag: (a) `fill_member_preserves_generation_scoped_ptrace_state` calls `fill_member(record, 42, 998)` (pid.rs:1123) — compile error; (b) `public_register_waits_for_in_progress_adoption_instead_of_duplicating` publishes `ns_pid = 42` with no tag, so the waiting `register` never matches `slot_of`, spins to its 1 s deadline and returns `None` instead of `Some(claimed.index)`; (c) `unregister_reaped_waits_for_member_publication_transition` claims a record with `ns_pid = 42` and no tag, so `unregister_reaped` returns `false` immediately and the 'must not report success while publication owns the record' assertion fails; (d) `in_progress_registration_slot_is_not_visible` hand-builds an untagged slot so `host_to_ns(200)` stays `None` after publication. Step 10's claim that every pre-existing case passes unchanged was therefore false. Fixed by tagging the records with `region.ns_id()` and passing it to `fill_member`.
- fixed: Task 14 deletes `ensure_kernel_arena_path_env` but the test `namespace_supervisor_launch_surface_is_deleted` (runtime.rs:2378, anchor at :2396) slices the launch source with `tail.split("fn ensure_kernel_arena_path_env").next()`; `split().next()` always yields something, so the assertion silently widens to the rest of runtime.rs, and the Step 1 grep assertion can never print nothing (the string literal still matches). Added the re-anchor onto `fn with_hvf_syscall_mailbox` (the function that follows the two deleted ones) to Task 14 Step 3.
- fixed: Task 14 Step 1 expected hit list is wrong: it says 12 hits, cites runtime.rs:700 (actual 699) and omits runtime.rs:718 (`fn kernel_arena_run_scope`) and runtime.rs:2396 (the test literal). Verified live: 23 hits after Task 13 (arena.rs:16,370; guest_cpu.rs:375; threaded_loop.rs:236,237; run_state.rs:139,145,310; execute.rs:224,227,233; vcpu_loop/exec.rs:1663; runtime.rs:616,620,621,622,692,693,699,713,718,1035,2396). Corrected.
- fixed: Task 15 Step 1 grep pattern `pub fn attach\(` also matches the unrelated `HostFsBackend::attach` at crates/carrick-runtime/src/fs_backend.rs:2491, so the 'passes when empty' condition is unreachable. Narrowed the pattern to `KernelArena::attach\(` plus the exact kernel signature.
- fixed: Task 14 Step 7 smoke reads `/proc/self/status` from `grep`, i.e. grep's OWN status (a child with pid > 1, PPid 1) — the expected `Pid: 1`/`PPid: 0` lines cannot appear. Changed to `/proc/$$/status` and stated the exact expected lines.
- fixed: Task 13 Step 12 would commit Task 13's files alone while the workspace is red (Step 11 documents the compile failures), contradicting Task 12's own 'each commit keeps the workspace green' and AGENTS.md's sequential-CI rule; the draft's 'commit both if the executor insists' hedge leaves it ambiguous. Restructured: Task 13 ends without a commit and Task 14 Step 8 commits Tasks 13+14 as ONE commit with a merged body and a `git add` covering both file sets.
- fixed: Task 13 Step 11 expected-error list cites vcpu_loop/exec.rs:1499 (HEAD: 1663) and lumps `pid::enabled` sites in; `enabled()` is retained, so only `request`/`requested`/`init`/`join_existing`/`mark_self_execed` sites fail. Corrected the list and softened the rustc error-code claims (E0425 vs E0599 depends on path form).
- fixed: Task 15 Step 2 line refs: `create_at` is at arena.rs:132-138 (doc 132-135, fn 136-138), not 131-137; `attach` 139-193 is right. Corrected.
- fixed: Dependencies on Task 11 remain unverifiable at HEAD (no `crates/carrick-runtime/src/kernel/container.rs`, no `Task::container()`, no `Container` type exists yet — `rg` finds none); the draft already flags this. Added an explicit note in Task 14 Step 2 that the `container` binding must exist BEFORE the pid-placement block at execute.rs:213 or the block must move after Task 11's construction; nothing else in the tree can be substituted.
- UNVERIFIED: Task 11's actual shapes: the name and construction of the `Arc<Container>` in Runtime::execute, `Task::container()`, and how the root task is bound to its Container — all assumed from the shared contract; the container.rs Modify step cannot quote existing lines because the file does not exist at 3dc6cc72.
- UNVERIFIED: Whether the workspace lint configuration allows `.expect(..)` inside `#[cfg(test)]` modules of carrick-runtime without an explicit `#[allow]` — pid.rs tests already use `.expect` (line 1153) so it is assumed to compile; if not, add `#[allow(clippy::expect_used)]` on the tests module.
- UNVERIFIED: Which id the ns-init should be registered under once two containers share a carrier: today `set_init(std::process::id())` registers the CARRIER pid in every container (preserved verbatim in Task 14); with `register` refusing a host pid already a member elsewhere, the SECOND concurrent container's init registration would be refused (set_init ignores the result). Gate B must pass a carrier-unique root task id from Task 11 instead; the kernel graph already answers getpid/getppid inside a dispatch scope (root_bootstrap_identity gives pid = LINUX_BOOTSTRAP_PID = 1), so single-container behaviour is unchanged.
- UNVERIFIED: The exact expected `just check` error list in Task 13 Step 11 (function names are verified; rustc may report them as E0425 or E0433 depending on path form).
- UNVERIFIED: `sweep_dead_owner_records` has no production caller (`rg` finds only its tests) — left in place as pre-existing dead code under the module's `#![allow(dead_code)]`; not deleted because it is outside the brief.
- UNVERIFIED: The signed smoke in Task 14 Step 7 assumes `ubuntu:24.04` is available locally and that `carrick run` prints guest stdout to the terminal (raw streaming is the current default per the spec); exact `PPid:` rendering for pid 1 is `0` per pid.rs `ns_ppid_for_host` but was not run here (read-only planning session).

</details>


<!-- cluster B3-clock-caps-per-container -->
## Cluster B3-clock-caps-per-container

> **Status: RECONCILIATION PENDING.** Verifier-corrected against `39426141`; task headings were renumbered mechanically (headings renumbered 14..15 -> 20..21), but by-number cross-references inside the text still use the DRAFT numbering (see the renumber table in the index) and the cross-cluster fixes below have NOT been applied. A future session must apply each item, then remove this block.
>
> - [ ] TASK-NUMBER COLLISIONS (5) + one unnumbered cluster: A3 Task 6 (syscall-map doc row) vs A4 Task 6 (net.rs test module); A4 Task 7/8 vs A5 Task 7/8; B2 Task 14/15 vs B3 Task 14/15; C1 Task 21 (host-authority census reconcile, added in review) vs C2 Task 21 (prepare.rs). A2 carries no task number at all. FIX: renumber globally in dependency order and rewrite every cross-reference ('Task 11', 'Task 18', 'Task 19', 'Task 21/22', 'Task 23', 'Task 25/26') to the new numbers: A1=1-3, A2=4, A3=5-7, A4=8-10, A5=11-13, B1=14-15, B2=16-19, B3=20-21, B4=22-23, C1=24-27, C2=28-29, C3=30-31, C4=32-33, C5=34-35. (All consumers below are stated with the ORIGINAL numbers; the renumbering must be applied on top.)
> - [ ] `Container` construction/handle seam: B1 creates the Container INSIDE the kernel (`Container::new` is pub(super), `Kernel::create_container(LaunchContext)`, `RootBootstrap::with_launch(LaunchContext)`, dispatcher carries only `set_launch_context/launch_context()`), but B2 consumes 'the Arc<Container> binding named `container` built in Runtime::execute BEFORE the SyscallDispatcher' (for `container.install_pid_ns`), B3 consumes the same binding plus `RootBootstrap::with_container(Arc<Container>)` and `Container::for_reference_model() -> Container` (un-Arc'd for builder chaining), and B4 consumes `SyscallDispatcher::container(&self) -> Arc<Container>`. None of those exist in B1. FIX: B1 changes to: `pub(crate) fn Container::new(launch: LaunchContext) -> Container` and `pub fn Container::for_reference_model() -> Container` (caller wraps in Arc), `Kernel::create_container(&self, container: Arc<Container>) -> Result<(), KernelError>` (registers, DuplicateContainer on repeat), `RootBootstrap::with_container(self, Arc<Container>)` replacing `with_launch`, and `SyscallDispatcher::{set_container(&self, Arc<Container>), container(&self) -> Arc<Container>}` replacing `set_launch_context/launch_context()`; `hvpatch::initialize_root_process` reads `dispatcher.container()` (fallback `Arc::new(Container::new(LaunchContext::from_process_env()?))`). execute.rs builds `let container = Arc::new(Container::new(launch))` before the dispatcher; B2/B3/B4 text unchanged except B3's 'this cluster adds clock/granted_caps to the struct literal' (see next item).
> - [ ] `ClockDomain` is produced TWICE with different shapes: B1 (`clock: ClockDomain`, `Container::clock(&self) -> &ClockDomain`, `Default`, accessors realtime_offset_ns/set_realtime_offset_ns) and B3 (`#[derive(Debug, Default)]`, `clock: Arc<ClockDomain>`, `clock(&self) -> &Arc<ClockDomain>`, plus system()/realtime_base_now/realtime_now/vvar_realtime_off_ns/publish_vvar_realtime_offset), and B3's consumes text says it ADDS the `clock` field to Container ('this cluster adds clock: Arc<ClockDomain> ... to its struct literal') as if B1 had none. B3's Arc is justified (TimerFdState holds the domain with no KernelContext). FIX: B1 produces the skeleton in B3's shape -- `#[derive(Debug, Default)] pub struct ClockDomain { realtime_offset_ns: AtomicI64 }`, field `clock: Arc<ClockDomain>`, `clock(&self) -> &Arc<ClockDomain>`; B3's consumes text changes to 'extends B1's ClockDomain with system()/realtime_base_now/realtime_now/publish_vvar_realtime_offset and adds only `granted_caps: CapabilitySet` to Container'.
> - [ ] B1 census misassigns clock and pid/sysv destinations: it says 'B2 consumes: GUEST_REALTIME_OFFSET_NS -> ClockDomain' and 'ClockDomain ... has no consumer until B2 rewires dispatch/mod.rs:7480'; B2 touches no clock code -- B3 does. It also routes `kernel_arena_run_scope`/`sysv_run_scope` to `RunId::scope_component` for B2, but B2 DELETES `kernel_arena_run_scope` (arena becomes an unlinked temp file, no scope path) and never touches `sysv_run_scope`; `RunId::scope_component` therefore has no consumer and `sysv_run_scope` (dispatch/sysv.rs:895-903, still an env read) has no owner. FIX: B1 census rows: GUEST_REALTIME_OFFSET_NS -> B3; kernel_arena_run_scope -> 'deleted by B2'; sysv_run_scope -> B2 Task 14 replaces it with `task.container().run_id().scope_component()` (add to B2 produces/DELETED list) -- otherwise delete `RunId::scope_component` from B1.
> - [ ] B1 census assigns `root_net_ns/root_uts_ns -> Container` and `pty_registry MASTERS` to B3, and B4's Gate B asserts DISTINCT HOSTNAMES per container ('publish_root_nodename today is a process OnceLock, kernel/netns.rs:226-233 ... only B1-B3's de-globalization can make true'), but B3 produces only clock + capabilities. Nobody moves the UTS/net cells or the pty masters, so B4's gate cannot pass. FIX: B3 adds to its produces: `Container { uts_ns: Arc<UtsNamespace>, net_ns: Arc<NetNamespace> }` (existing types behind `root_uts_ns/root_net_ns`), `Container::{uts_ns(), net_ns()}`, `NsProxy::for_container` seeding uts/net from the container, `publish_root_nodename` becoming per-container (`Container::set_hostname` from RunSpec.hostname), deleting the `root_uts_ns`/`root_net_ns` OnceLocks; pty MASTERS row is re-marked 'carrier-infra, unchanged' in the B1 census (B4 does not need it). B4 consumes updates to name these.
> - [ ] vDSO realtime re-stamp is implemented TWICE with incompatible ownership: A1 relocates `GUEST_REALTIME_OFFSET_NS` into `carrick_mem::vdso` (`guest_realtime_offset_ns/set_guest_realtime_offset_ns/guest_realtime_epoch/vvar_realtime_off_ns(host_off_ns)`), makes the four VMM stampers read that carrier-wide delta at vCPU construction, and adds the per-MM epoch re-stamp (`DispatchMmAuthority.vvar_realtime_epoch`, `SyscallDispatcher::{sync_vvar_realtime_offset, set_guest_realtime}`, `realtime_test_support`, `realtime_base_duration`). B3 then DELETES 'static GUEST_REALTIME_OFFSET_NS, get_/set_guest_realtime_offset_ns, realtime_duration (dispatch/mod.rs)' -- by then those are in vdso.rs under A1's names, so B3's deletion list and 'Step 1 grep prints 16' are wrong -- and re-implements the word (`vvar_realtime_word(base_off_ns, offset_ns)`, `ClockDomain::vvar_realtime_off_ns`) and the publish (`ClockDomain::publish_vvar_realtime_offset` at clock_settime/settimeofday/exec) while saying 'if Phase A landed a free helper, delete it'. A per-container delta cannot be read from VMM crates, so A1's VMM-stamper changes are dead the moment B3 lands, and B3's exec-only publish drops A1's cross-process lazy re-stamp that removes the KNOWN_PROBE_GAPS excuse. FIX: A1: keep the static in dispatch/mod.rs (do NOT relocate to carrick_mem, do NOT touch the four VMM stampers -- they keep stamping host calibration only), cover the exec'd-process case by calling `sync_vvar_realtime_offset` from the post-exec identity-stamp site (vcpu_loop/exec.rs `stamp_identity_page_at`, the site B3 names) and keep the per-MM epoch re-stamp; expose exactly one word function `carrick_mem::vdso::vvar_realtime_off_ns(host_off_ns: u64, delta_ns: i64) -> u64`. B3: move offset AND epoch into `ClockDomain { realtime_offset_ns: AtomicI64, epoch: AtomicU64 }` (`set_realtime_offset_ns` bumps epoch; `epoch()`), rewire `sync_vvar_realtime_offset` to compare the MM epoch against `task.container().clock().epoch()`, delete `realtime_duration`, `realtime_base_duration`, `realtime_test_support` (replace with ClockDomain test helpers) and `vvar_realtime_word`/`ClockDomain::vvar_realtime_off_ns` in favour of the single vdso fn; recompute every count/anchor AFTER A1 (A1 adds realtime_duration callers in mqueue, sysv, proc, relative_from_absolute_timespec, now_realtime_timespec that B3 must convert to `ClockDomain::realtime_now`).
> - [ ] C2's `Runtime::prepare` is anchored on the 3dc6cc72 `execute.rs`, but Phase B rewrites that function first: B1 (build `Arc<Container>` from LaunchContext, `dispatcher.set_container`), B2 (`container.install_pid_ns`), B3 (`apply_launch_privileges(policy, &Container)` -- C2 still consumes the old `apply_launch_privileges (:5807)` `&[String]` shape), B4 (`carrier::admit_container`/`retire_container`, `record_container_terminal`). C2's trimmed import lists, Step 5/8 counts and the moved body would drop those seams. FIX: C2 consumes lists add B1 `Container::new`/`set_container`, B2 `install_pid_ns`, B3 `apply_launch_privileges(&mut self, SeccompPolicy, &Container)`, B4 `admit_container/retire_container/record_container_terminal`; Task 21 states it moves the POST-Phase-B body and re-derives every execute.rs anchor after B4.
>
### Task 20: Move the guest realtime offset into the container's `ClockDomain`

**Files:** (line numbers are as of 3dc6cc72 — match on the QUOTED code, not the numbers. At the working-tree HEAD ea0dac4c `dispatch/mod.rs` is +49 lines throughout (static at 7529, `include!` at 10007), `dispatch/tests.rs` closes at 4409, the `vcpu_loop/exec.rs` identity-stamp block is at 1673-1685, and `trap.rs` `populate_vdso_data_page` is at 15707; `time.rs`, `fd_table.rs` and the other files are unchanged.)
- Modify: `crates/carrick-runtime/src/kernel/container.rs` (created by Task 11; this task adds the `ClockDomain` impl, the `clock: Arc<ClockDomain>` field and `Container::clock()`)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:139` (`use std::time::…` shrinks to `Duration`), `:7301-7306` (`linux_clock_duration`), `:7338-7346` (`linux_clock_nanosleep_now`), `:7421-7427` (`adjtimex_bootstrap`), `:7480-7517` (delete `GUEST_REALTIME_OFFSET_NS` / `get_`/`set_guest_realtime_offset_ns` / `realtime_duration`), `:7522` (expose `host_clock_duration`), `:8242` (`read_timerfd`), `:8254-8300` (`refresh_timerfd_locked`, `timerfd_ready_count`, `timerfd_itimerspec`, `timerfd_expirations`)
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs:204-222` (`TimerFdState` gains the creating container's clock)
- Modify: `crates/carrick-runtime/src/dispatch/time.rs:153-160, 190, 196, 220-221, 250, 280, 289, 309-345, 528, 650-652, 738-746, 751, 765, 805-815, 850, 1503-1514`
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs:1509-1521` (re-publish the vvar realtime word after the exec identity stamp)
- Test: `crates/carrick-runtime/src/kernel/container.rs` (`mod clock_domain_tests`), `crates/carrick-runtime/src/dispatch/tests.rs` (new `mod container_clock_tests`, appended after the closing `}` of `container_policy_dispatch_tests` at line 4327)

**Interfaces:**
- Consumes (Task 11): `crate::kernel::container::Container` with private fields; `Task::container(&self) -> Arc<Container>` (reached from a handler as `cx.kernel.task().container()`); every `Kernel::bootstrap_root` — including `RootBootstrap::for_reference_model` and therefore `SyscallDispatcher::new()`'s `bootstrap_one_task_binding()` — attaches its root task to a fresh `Container`.
- Consumes (tree): `carrick_guest_mem::GuestMemory::write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>` (`crates/carrick-guest-mem/src/lib.rs:598`, documented for exactly the vvar case); `carrick_mem::vdso::{realtime_off_ns() -> Option<u64>, LINUX_VVAR_BASE: u64, VVAR_OFF_REALTIME_OFF_NS: usize}` (re-exported as `crate::vdso` by `carrick-runtime/src/lib.rs:156`); `Task::with_caps`, `Task::caps` (`kernel/objects.rs:2961-2973`); `KernelContext::task(&self) -> &TaskRef` (`kernel/core.rs:75`, `TaskRef = Arc<Task>`); `LinuxTfdFlags::TIMER_ABSTIME` (`carrick-abi/src/lib.rs:5098`).
- Produces:
  - `pub struct ClockDomain { realtime_offset_ns: AtomicI64 }` (`#[derive(Debug, Default)]`)
  - `impl ClockDomain { pub fn system() -> Self; pub fn realtime_offset_ns(&self) -> i64; pub fn set_realtime_offset_ns(&self, delta_ns: i64); pub fn realtime_base_now(&self) -> Duration; pub fn realtime_now(&self) -> Duration; pub fn vvar_realtime_off_ns(&self) -> Option<u64>; pub fn publish_vvar_realtime_offset(&self, memory: &mut impl GuestMemory) -> Result<(), MemoryError>; }`
  - `pub fn vvar_realtime_word(base_off_ns: u64, offset_ns: i64) -> u64`
  - `impl Container { pub fn clock(&self) -> &Arc<ClockDomain>; }`
  - `pub(crate) fn host_clock_duration(clock_id: libc::clockid_t) -> Option<Duration>` (dispatch/mod.rs, was private)
  - `fn linux_clock_duration(clock: &ClockDomain, clock_id: u64) -> Option<Duration>` and `fn linux_clock_nanosleep_now(clock: &ClockDomain, clock_id: u64) -> Result<Duration, LinuxErrno>` (dispatch-private)
  - `pub(super) fn TimerFdState::new(clock: Arc<ClockDomain>, clock_id: u64) -> Self` with `pub(super) clock: Arc<ClockDomain>`

- [ ] **Step 1: Red — assert the static is gone (fails now)**

```bash
cd /Volumes/CaseSensitive/carrick && ! rg -n 'GUEST_REALTIME_OFFSET_NS|guest_realtime_offset_ns' crates/ --type rust
```
Expected now: prints the 16 matches (6 in `dispatch/mod.rs`, 10 in `dispatch/time.rs`) and exits 1 (the `!` makes the assertion fail). It must exit 0 at the end of this task.

- [ ] **Step 2: Red — `ClockDomain` unit tests in `kernel/container.rs`**

Append to `crates/carrick-runtime/src/kernel/container.rs`:

```rust
#[cfg(test)]
mod clock_domain_tests {
    use super::{ClockDomain, vvar_realtime_word};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn wall_now() -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }

    #[test]
    fn system_domain_starts_unshifted() {
        let clock = ClockDomain::system();
        assert_eq!(clock.realtime_offset_ns(), 0);
        assert!(
            clock.realtime_now().abs_diff(wall_now()) < Duration::from_secs(5),
            "an unshifted System domain reports the host wall clock"
        );
    }

    #[test]
    fn two_domains_hold_independent_offsets() {
        let a = ClockDomain::system();
        let b = ClockDomain::system();
        a.set_realtime_offset_ns(600_000_000_000);
        b.set_realtime_offset_ns(-600_000_000_000);
        assert_eq!(a.realtime_offset_ns(), 600_000_000_000);
        assert_eq!(b.realtime_offset_ns(), -600_000_000_000);
        let gap = a.realtime_now() - b.realtime_now();
        assert!(
            (Duration::from_secs(1199)..=Duration::from_secs(1201)).contains(&gap),
            "domains are 20 minutes apart, got {gap:?}"
        );
        // The base (host calibration) is shared; only the offset is per domain.
        assert!(a.realtime_base_now().abs_diff(b.realtime_base_now()) < Duration::from_secs(1));
    }

    #[test]
    fn vvar_word_adds_the_signed_offset_with_wrapping() {
        // The vDSO computes realtime_ns = CNTVCT/freq + word (u64 wrapping),
        // so a negative offset must be published as two's complement.
        assert_eq!(vvar_realtime_word(1_000, 5), 1_005);
        assert_eq!(vvar_realtime_word(1_000, -400), 600);
        assert_eq!(vvar_realtime_word(u64::MAX, 1), 0);
    }
}
```

- [ ] **Step 3: Red — two-container dispatch tests**

Append to the end of `crates/carrick-runtime/src/dispatch/tests.rs` (after the closing `}` of `container_policy_dispatch_tests` at line 4327; the file is `include!`d into `dispatch/mod.rs:9958`, so `super::*` is the dispatch scope and private dispatch items such as `timerfd_ready_count`, `TimerFdState` and `open_file` are reachable):

```rust
#[cfg(test)]
mod container_clock_tests {
    //! Two containers in one carrier keep independent CLOCK_REALTIME
    //! authorities. Each `SyscallDispatcher::new()` bootstraps its own root
    //! task and therefore its own `Container`; the clock a handler reads must
    //! be that container's `ClockDomain`, never a process static.
    use super::*;
    use crate::compat::CompatReporter;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const SYS_TIMERFD_CREATE: u64 = 85;
    const SYS_TIMERFD_SETTIME: u64 = 86;
    const SYS_CLOCK_SETTIME: u64 = 112;
    const SYS_CLOCK_GETTIME: u64 = 113;
    const MEM_BASE: u64 = 0x4000_0000;
    const MEM_LEN: usize = 4096;
    const TIMESPEC_ADDR: u64 = MEM_BASE + 0x100;
    const ITIMERSPEC_ADDR: u64 = MEM_BASE + 0x200;
    const SLACK: Duration = Duration::from_secs(5);

    fn wall_now() -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }

    fn assert_within(actual: Duration, expected: Duration, what: &str) {
        let delta = actual.abs_diff(expected);
        assert!(
            delta <= SLACK,
            "{what}: actual {actual:?}, expected {expected:?} (delta {delta:?})"
        );
    }

    fn realtime_via_syscall(dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory) -> Duration {
        let reporter = CompatReporter::default();
        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().expect("task context"),
                SyscallRequest::new(
                    SYS_CLOCK_GETTIME,
                    SyscallArgs([LINUX_CLOCK_REALTIME, TIMESPEC_ADDR, 0, 0, 0, 0]),
                ),
                memory,
                &reporter,
            )
            .expect("dispatch clock_gettime");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(TIMESPEC_ADDR, 16).expect("timespec bytes");
        let secs = i64::from_le_bytes(bytes[0..8].try_into().expect("tv_sec"));
        let nanos = i64::from_le_bytes(bytes[8..16].try_into().expect("tv_nsec"));
        Duration::new(secs as u64, nanos as u32)
    }

    fn write_timespec(memory: &mut LinearMemory, address: u64, value: Duration) {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&(value.as_secs() as i64).to_le_bytes());
        bytes[8..16].copy_from_slice(&i64::from(value.subsec_nanos()).to_le_bytes());
        memory.write_bytes(address, &bytes).expect("write timespec");
    }

    #[test]
    fn clock_gettime_realtime_reads_the_callers_container_domain() {
        let mut a = SyscallDispatcher::new();
        let mut b = SyscallDispatcher::new();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        const OFFSET: Duration = Duration::from_secs(3600);
        b.capture_one_task_context()
            .expect("b context")
            .task()
            .container()
            .clock()
            .set_realtime_offset_ns(OFFSET.as_nanos() as i64);

        assert_within(realtime_via_syscall(&mut a, &mut memory), wall_now(), "A follows the wall clock");
        assert_within(realtime_via_syscall(&mut b, &mut memory), wall_now() + OFFSET, "B is shifted by its own domain");
        assert_within(realtime_via_syscall(&mut a, &mut memory), wall_now(), "A is untouched by B's offset");
    }

    #[test]
    fn clock_settime_moves_only_the_callers_container() {
        let mut a = SyscallDispatcher::new();
        let mut b = SyscallDispatcher::new();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let reporter = CompatReporter::default();
        // clock_settime is CAP_SYS_TIME-gated and the Docker default set lacks it.
        let a_context = a.capture_one_task_context().expect("a context");
        a_context
            .task()
            .with_caps(|caps| *caps = crate::namespace::process::CapabilitySet::full());
        const AHEAD: Duration = Duration::from_secs(7200);
        write_timespec(&mut memory, TIMESPEC_ADDR, wall_now() + AHEAD);
        let outcome = a
            .dispatch(
                &a_context,
                SyscallRequest::new(
                    SYS_CLOCK_SETTIME,
                    SyscallArgs([LINUX_CLOCK_REALTIME, TIMESPEC_ADDR, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("dispatch clock_settime");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

        assert_within(realtime_via_syscall(&mut a, &mut memory), wall_now() + AHEAD, "A moved");
        assert_within(realtime_via_syscall(&mut b, &mut memory), wall_now(), "B did not move");
        assert_eq!(
            b.capture_one_task_context()
                .expect("b context")
                .task()
                .container()
                .clock()
                .realtime_offset_ns(),
            0,
            "B's domain never observed A's clock_settime"
        );
    }

    fn armed_absolute_timerfd(
        dispatcher: &mut SyscallDispatcher,
        memory: &mut LinearMemory,
        deadline: Duration,
    ) -> Arc<TimerFdState> {
        let reporter = CompatReporter::default();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let fd = match dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(SYS_TIMERFD_CREATE, SyscallArgs([LINUX_CLOCK_REALTIME, 0, 0, 0, 0, 0])),
                memory,
                &reporter,
            )
            .expect("dispatch timerfd_create")
        {
            DispatchOutcome::Returned { value } => value as u64,
            other => panic!("timerfd_create failed: {other:?}"),
        };
        // struct itimerspec { it_interval (zero); it_value = deadline }
        let mut spec = [0u8; 32];
        spec[16..24].copy_from_slice(&(deadline.as_secs() as i64).to_le_bytes());
        spec[24..32].copy_from_slice(&i64::from(deadline.subsec_nanos()).to_le_bytes());
        memory.write_bytes(ITIMERSPEC_ADDR, &spec).expect("write itimerspec");
        assert_eq!(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(
                        SYS_TIMERFD_SETTIME,
                        SyscallArgs([fd, LinuxTfdFlags::TIMER_ABSTIME.bits(), ITIMERSPEC_ADDR, 0, 0, 0]),
                    ),
                    memory,
                    &reporter,
                )
                .expect("dispatch timerfd_settime"),
            DispatchOutcome::Returned { value: 0 }
        );
        let open_file = dispatcher.open_file(fd as i32).expect("timerfd open file");
        let open = open_file.description.read();
        let OpenDescription::TimerFd { state, .. } = &*open else {
            panic!("fd {fd} is not a timerfd");
        };
        Arc::clone(state)
    }

    #[test]
    fn timerfd_deadline_is_bound_to_the_creating_containers_clock() {
        let mut a = SyscallDispatcher::new();
        let mut b = SyscallDispatcher::new();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let deadline = wall_now() + Duration::from_secs(3600);
        let timer_a = armed_absolute_timerfd(&mut a, &mut memory, deadline);
        let timer_b = armed_absolute_timerfd(&mut b, &mut memory, deadline);
        assert_eq!(timerfd_ready_count(&timer_a), 0);
        assert_eq!(timerfd_ready_count(&timer_b), 0);

        // Move only A's clock past the deadline.
        a.capture_one_task_context()
            .expect("a context")
            .task()
            .container()
            .clock()
            .set_realtime_offset_ns(Duration::from_secs(7200).as_nanos() as i64);

        assert_eq!(timerfd_ready_count(&timer_a), 1, "A's timerfd follows A's clock");
        assert_eq!(timerfd_ready_count(&timer_b), 0, "B's timerfd is bound to B's clock");
    }
}
```

- [ ] **Step 4: Run the red tests**

`just test` takes ONE `cargo test` name filter per invocation (`cargo test [TESTNAME]`), so run the two modules separately:

```bash
cd /Volumes/CaseSensitive/carrick && just test clock_domain_tests
```
Expected: the `cargo test -p carrick-runtime --lib` step (the last macOS step of the recipe) fails to compile `carrick-runtime` — `error[E0599]: no method named `clock` found for ... Container` (and `E0432`/`E0412` for `ClockDomain`/`vvar_realtime_word`). Red for the right reason: the domain does not exist yet. (`just test container_clock_tests` fails identically; the compile error is filter-independent.)

- [ ] **Step 5: Implement `ClockDomain` on the container**

In `crates/carrick-runtime/src/kernel/container.rs` (Task 11's file), add the imports and the type. If Task 11 left a stub `pub struct ClockDomain { ... }`, replace it with this definition; the `Container` field becomes `clock: Arc<ClockDomain>` (initialized with `Arc::new(ClockDomain::system())` in `Container`'s constructor):

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use carrick_guest_mem::{GuestMemory, MemoryError};

/// The container's time authority. Phase B ships `System` mode only: the
/// host clock plus a per-container CLOCK_REALTIME offset that guest
/// `clock_settime`/`settimeofday` move. It replaces the carrier-wide
/// `GUEST_REALTIME_OFFSET_NS` static, which let one Linux process's
/// `clock_settime` shift every process in the carrier.
///
/// The host-derived base (`carrick_mem::vdso::REALTIME_OFF_NS`,
/// `unix_ns - uptime_ns` published by the VMM's `populate_vdso_data_page`
/// at vCPU construction and at every exec image replace) is a carrier
/// calibration value shared by every domain; only the offset is container
/// state.
#[derive(Debug, Default)]
pub struct ClockDomain {
    realtime_offset_ns: AtomicI64,
}

/// The vvar `VVAR_OFF_REALTIME_OFF_NS` word for a domain: the vDSO computes
/// `realtime_ns = CNTVCT/freq + word` with u64 wrapping arithmetic, so a
/// negative offset is published as its two's complement.
pub fn vvar_realtime_word(base_off_ns: u64, offset_ns: i64) -> u64 {
    base_off_ns.wrapping_add(offset_ns as u64)
}

impl ClockDomain {
    /// The host clock, unshifted.
    pub fn system() -> Self {
        Self {
            realtime_offset_ns: AtomicI64::new(0),
        }
    }

    pub fn realtime_offset_ns(&self) -> i64 {
        self.realtime_offset_ns.load(Ordering::SeqCst)
    }

    pub fn set_realtime_offset_ns(&self, delta_ns: i64) {
        self.realtime_offset_ns.store(delta_ns, Ordering::SeqCst);
    }

    /// CLOCK_REALTIME before this domain's offset: `uptime + vvar base` when
    /// the VMM has calibrated the vvar (so the syscall path and the vDSO agree
    /// to the nanosecond, clock_gettime04), else a live wall-clock read.
    pub fn realtime_base_now(&self) -> Duration {
        #[cfg(not(target_os = "linux"))]
        {
            if let Some(off_ns) = crate::vdso::realtime_off_ns()
                && let Some(uptime) =
                    crate::dispatch::host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW)
            {
                return Duration::from_nanos((uptime.as_nanos() as u64).wrapping_add(off_ns));
            }
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }

    /// CLOCK_REALTIME as this container sees it.
    pub fn realtime_now(&self) -> Duration {
        let offset_ns = self.realtime_offset_ns();
        let base = self.realtime_base_now();
        if offset_ns >= 0 {
            base.saturating_add(Duration::from_nanos(offset_ns as u64))
        } else {
            base.saturating_sub(Duration::from_nanos(offset_ns.unsigned_abs()))
        }
    }

    /// The vvar realtime word this domain wants published, or `None` before
    /// the VMM has calibrated the base (no vDSO in this lane / unit tests).
    pub fn vvar_realtime_off_ns(&self) -> Option<u64> {
        crate::vdso::realtime_off_ns()
            .map(|base| vvar_realtime_word(base, self.realtime_offset_ns()))
    }

    /// Publish this domain's realtime word into the calling process's vvar
    /// page so the userspace vDSO fast path and the syscall path agree. The
    /// vvar is guest-read-only, hence the carrick-internal unchecked writer.
    pub fn publish_vvar_realtime_offset(
        &self,
        memory: &mut impl GuestMemory,
    ) -> Result<(), MemoryError> {
        let Some(word) = self.vvar_realtime_off_ns() else {
            return Ok(());
        };
        memory.write_bytes_unchecked(
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
            &word.to_le_bytes(),
        )
    }
}
```

Add the accessor inside `impl Container` (next to Task 11's other accessors):

```rust
    /// This container's time authority. Every guest-facing time read on the
    /// syscall path resolves through here — never through a static.
    pub fn clock(&self) -> &Arc<ClockDomain> {
        &self.clock
    }
```

- [ ] **Step 6: Replace the static and thread `&ClockDomain` through the dispatch pivot**

In `crates/carrick-runtime/src/dispatch/mod.rs`, replace lines 7301-7306:

```rust
fn linux_clock_duration(clock_id: u64) -> Option<Duration> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_TAI => Some(realtime_duration()),
```
with
```rust
fn linux_clock_duration(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
) -> Option<Duration> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_TAI => Some(clock.realtime_now()),
```

Replace lines 7338-7346:
```rust
fn linux_clock_nanosleep_now(clock_id: u64) -> Result<Duration, LinuxErrno> {
    if matches!(
        clock_id,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID
    ) || dynamic_cpu_clock(clock_id).is_some()
    {
        return Err(LINUX_EOPNOTSUPP);
    }
    linux_clock_duration(clock_id).ok_or(LINUX_EINVAL)
```
with
```rust
fn linux_clock_nanosleep_now(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
) -> Result<Duration, LinuxErrno> {
    if matches!(
        clock_id,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID
    ) || dynamic_cpu_clock(clock_id).is_some()
    {
        return Err(LINUX_EOPNOTSUPP);
    }
    linux_clock_duration(clock, clock_id).ok_or(LINUX_EINVAL)
```

Replace lines 7421-7427:
```rust
fn adjtimex_bootstrap(memory: &mut impl GuestMemory, address: u64) -> DispatchOutcome {
    let timex = match read_kernel_struct::<LinuxTimex>(memory, address) {
        Ok(timex) => timex,
        Err(errno) => return DispatchOutcome::Errno { errno },
    };
    if timex.modes == 0 {
        let current = LinuxTimex::new_read_state(linux_timeval_from_duration(realtime_duration()));
```
with
```rust
fn adjtimex_bootstrap(
    clock: &crate::kernel::container::ClockDomain,
    memory: &mut impl GuestMemory,
    address: u64,
) -> DispatchOutcome {
    let timex = match read_kernel_struct::<LinuxTimex>(memory, address) {
        Ok(timex) => timex,
        Err(errno) => return DispatchOutcome::Errno { errno },
    };
    if timex.modes == 0 {
        let current =
            LinuxTimex::new_read_state(linux_timeval_from_duration(clock.realtime_now()));
```

Delete lines 7480-7517 entirely (the static, both accessors and `realtime_duration`):
```rust
static GUEST_REALTIME_OFFSET_NS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

pub(crate) fn get_guest_realtime_offset_ns() -> i64 {
    GUEST_REALTIME_OFFSET_NS.load(std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn set_guest_realtime_offset_ns(delta_ns: i64) {
    GUEST_REALTIME_OFFSET_NS.store(delta_ns, std::sync::atomic::Ordering::SeqCst);
}

fn realtime_duration() -> Duration {
    let offset_ns = get_guest_realtime_offset_ns();
    let base = {
        #[cfg(not(target_os = "linux"))]
        {
            if let Some(off_ns) = crate::vdso::realtime_off_ns()
                && let Some(uptime) = host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW)
            {
                Duration::from_nanos((uptime.as_nanos() as u64).wrapping_add(off_ns))
            } else {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
            }
        }
        #[cfg(target_os = "linux")]
        {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
        }
    };
    if offset_ns >= 0 {
        base.saturating_add(Duration::from_nanos(offset_ns as u64))
    } else {
        base.saturating_sub(Duration::from_nanos((-offset_ns) as u64))
    }
}
```
and change the signature that follows (line 7522, after the surviving doc comment) from
```rust
fn host_clock_duration(clock_id: libc::clockid_t) -> Option<Duration> {
```
to
```rust
pub(crate) fn host_clock_duration(clock_id: libc::clockid_t) -> Option<Duration> {
```

The four lines just deleted were the ONLY uses of `SystemTime`/`UNIX_EPOCH` in `dispatch/mod.rs`, so `-D warnings` now flags line 139. Replace it:
```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};
```
with
```rust
use std::time::Duration;
```

Replace line 8242 (inside `read_timerfd`, whose `state: &TimerFdState` parameter is in scope):
```rust
        let Some(now) = linux_clock_duration(timer.clock_id) else {
```
with
```rust
        let Some(now) = linux_clock_duration(&state.clock, timer.clock_id) else {
```

Replace lines 8254-8300:
```rust
fn refresh_timerfd_locked(timer: &mut TimerFdInner) -> u64 {
    let (ready, next_deadline) = timerfd_expirations(
        timer.clock_id,
        timer.interval,
        timer.deadline,
        timer.expirations,
    );
    timer.expirations = ready;
    timer.deadline = next_deadline;
    ready
}

fn timerfd_ready_count(state: &TimerFdState) -> u64 {
    let mut timer = state.inner.lock();
    refresh_timerfd_locked(&mut timer)
}

fn timerfd_itimerspec(
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
) -> LinuxItimerspec {
    let now = linux_clock_duration(clock_id).unwrap_or(Duration::ZERO);
    let remaining = deadline.map(|deadline| deadline.saturating_sub(now));
    LinuxItimerspec::new(
        linux_timespec_from_optional_duration(interval),
        linux_timespec_from_optional_duration(remaining),
    )
}

fn timerfd_expirations(
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
) -> (u64, Option<Duration>) {
    let Some(deadline) = deadline else {
        return (expirations, None);
    };
    let Some(now) = linux_clock_duration(clock_id) else {
        return (expirations, Some(deadline));
    };
```
with
```rust
fn refresh_timerfd_locked(
    clock: &crate::kernel::container::ClockDomain,
    timer: &mut TimerFdInner,
) -> u64 {
    let (ready, next_deadline) = timerfd_expirations(
        clock,
        timer.clock_id,
        timer.interval,
        timer.deadline,
        timer.expirations,
    );
    timer.expirations = ready;
    timer.deadline = next_deadline;
    ready
}

fn timerfd_ready_count(state: &TimerFdState) -> u64 {
    let mut timer = state.inner.lock();
    refresh_timerfd_locked(&state.clock, &mut timer)
}

fn timerfd_itimerspec(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
) -> LinuxItimerspec {
    let now = linux_clock_duration(clock, clock_id).unwrap_or(Duration::ZERO);
    let remaining = deadline.map(|deadline| deadline.saturating_sub(now));
    LinuxItimerspec::new(
        linux_timespec_from_optional_duration(interval),
        linux_timespec_from_optional_duration(remaining),
    )
}

fn timerfd_expirations(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
) -> (u64, Option<Duration>) {
    let Some(deadline) = deadline else {
        return (expirations, None);
    };
    let Some(now) = linux_clock_duration(clock, clock_id) else {
        return (expirations, Some(deadline));
    };
```

- [ ] **Step 7: Bind a timerfd to its creating container's clock**

In `crates/carrick-runtime/src/dispatch/fd_table.rs`, replace lines 204-222:
```rust
#[derive(Debug)]
pub(super) struct TimerFdState {
    pub(super) inner: Mutex<TimerFdInner>,
    pub(super) changed: Condvar,
}

impl TimerFdState {
    pub(super) fn new(clock_id: u64) -> Self {
        Self {
            inner: Mutex::new(TimerFdInner {
                clock_id,
                interval: None,
                deadline: None,
                expirations: 0,
            }),
            changed: Condvar::new(),
        }
    }
}
```
with
```rust
#[derive(Debug)]
pub(super) struct TimerFdState {
    pub(super) inner: Mutex<TimerFdInner>,
    pub(super) changed: Condvar,
    /// The time authority of the container that created this timerfd. Linux
    /// binds a timerfd to its creator's time namespace; readiness is
    /// re-evaluated from poll/epoll paths that carry no `KernelContext`, so
    /// the domain is captured here rather than looked up per evaluation.
    pub(super) clock: std::sync::Arc<crate::kernel::container::ClockDomain>,
}

impl TimerFdState {
    pub(super) fn new(
        clock: std::sync::Arc<crate::kernel::container::ClockDomain>,
        clock_id: u64,
    ) -> Self {
        Self {
            inner: Mutex::new(TimerFdInner {
                clock_id,
                interval: None,
                deadline: None,
                expirations: 0,
            }),
            changed: Condvar::new(),
            clock,
        }
    }
}
```

- [ ] **Step 8: Route every `dispatch/time.rs` handler through the caller's container**

Replace lines 153-160:
```rust
        fn timerfd_create(this, cx, clock_id: u64, flags: u64) {
            if linux_clock_duration(clock_id).is_none()
                || flags & !LinuxTfdFlags::CREATE_SUPPORTED != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let description = OpenDescription::TimerFd {
                state: Arc::new(TimerFdState::new(clock_id)),
```
with
```rust
        fn timerfd_create(this, cx, clock_id: u64, flags: u64) {
            let clock = Arc::clone(cx.kernel.task().container().clock());
            if linux_clock_duration(&clock, clock_id).is_none()
                || flags & !LinuxTfdFlags::CREATE_SUPPORTED != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let description = OpenDescription::TimerFd {
                state: Arc::new(TimerFdState::new(clock, clock_id)),
```

In `timerfd_settime` (where `state` is the `Arc<TimerFdState>` cloned at line 185), replace line 190:
```rust
                let previous = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
```
with
```rust
                let previous =
                    timerfd_itimerspec(&state.clock, timer.clock_id, timer.interval, timer.deadline);
```
and line 196:
```rust
            let now = linux_clock_duration(timer.clock_id).unwrap_or(Duration::ZERO);
```
with
```rust
            let now = linux_clock_duration(&state.clock, timer.clock_id).unwrap_or(Duration::ZERO);
```

In `timerfd_gettime`, replace lines 220-221:
```rust
            refresh_timerfd_locked(&mut timer);
            let current = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
```
with
```rust
            refresh_timerfd_locked(&state.clock, &mut timer);
            let current =
                timerfd_itimerspec(&state.clock, timer.clock_id, timer.interval, timer.deadline);
```

In `clock_nanosleep`, replace line 250:
```rust
            let now = match linux_clock_nanosleep_now(clock_id) {
```
with
```rust
            let clock = Arc::clone(cx.kernel.task().container().clock());
            let now = match linux_clock_nanosleep_now(&clock, clock_id) {
```

In `clock_gettime`, replace line 280:
```rust
            let Some(duration) = linux_clock_duration(clock_id) else {
```
with
```rust
            let clock = Arc::clone(cx.kernel.task().container().clock());
            let Some(duration) = linux_clock_duration(&clock, clock_id) else {
```

In `clock_getres`, replace line 289:
```rust
            if linux_clock_duration(clock_id).is_none() {
```
with
```rust
            let clock = Arc::clone(cx.kernel.task().container().clock());
            if linux_clock_duration(&clock, clock_id).is_none() {
```

Replace the whole `clock_settime` handler (lines 309-345):
```rust
        fn clock_settime(this, cx, clock_id: u64, address: GuestPtr) {
            let memory = &*cx.memory;
            if !linux_clock_is_known(clock_id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let timespec = read_timespec(memory, address.0)?;
            let tv_nsec = timespec.tv_nsec;
            if !(0..1_000_000_000).contains(&tv_nsec) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !linux_clock_is_settable(clock_id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !super::creds::has_effective_capability(
                cx.kernel,
                crate::namespace::process::CAP_SYS_TIME,
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if clock_id == LINUX_CLOCK_REALTIME {
                let target_secs = timespec.tv_sec.max(0) as u64;
                let target_nanos = (timespec.tv_nsec as u32).min(999_999_999);
                let target_duration = Duration::new(target_secs, target_nanos);
                let raw_now = {
                    set_guest_realtime_offset_ns(0);
                    realtime_duration()
                };
                let delta_ns = if target_duration >= raw_now {
                    (target_duration - raw_now).as_nanos() as i64
                } else {
                    -((raw_now - target_duration).as_nanos() as i64)
                };
                set_guest_realtime_offset_ns(delta_ns);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }
```
with
```rust
        fn clock_settime(this, cx, clock_id: u64, address: GuestPtr) {
            if !linux_clock_is_known(clock_id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let timespec = read_timespec(&*cx.memory, address.0)?;
            let tv_nsec = timespec.tv_nsec;
            if !(0..1_000_000_000).contains(&tv_nsec) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !linux_clock_is_settable(clock_id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !super::creds::has_effective_capability(
                cx.kernel,
                crate::namespace::process::CAP_SYS_TIME,
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if clock_id == LINUX_CLOCK_REALTIME {
                let clock = Arc::clone(cx.kernel.task().container().clock());
                let target_secs = timespec.tv_sec.max(0) as u64;
                let target_nanos = (timespec.tv_nsec as u32).min(999_999_999);
                let target_duration = Duration::new(target_secs, target_nanos);
                // Delta against the OFFSET-FREE base: the old code zeroed the
                // shared offset for the read, a window every other thread of
                // the container could observe.
                let raw_now = clock.realtime_base_now();
                let delta_ns = if target_duration >= raw_now {
                    (target_duration - raw_now).as_nanos() as i64
                } else {
                    -((raw_now - target_duration).as_nanos() as i64)
                };
                clock.set_realtime_offset_ns(delta_ns);
                // Keep this process's vDSO fast path coherent with the syscall
                // path. Sibling processes of the container pick the word up at
                // their next exec (Phase F publishes it through a seqlocked
                // vvar mode word instead).
                if let Err(error) = clock.publish_vvar_realtime_offset(&mut *cx.memory) {
                    tracing::warn!(%error, "clock_settime: vvar realtime word not republished");
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }
```

In `timer_create`, replace line 528:
```rust
            if linux_clock_duration(clock_id).is_none() {
```
with
```rust
            let clock = Arc::clone(cx.kernel.task().container().clock());
            if linux_clock_duration(&clock, clock_id).is_none() {
```

In `timer_settime`, replace lines 650-652:
```rust
                        let now =
                            linux_clock_duration(crate::posix_timer::clock_id(id) as u64)
                                .unwrap_or(Duration::ZERO);
```
with
```rust
                        let clock = Arc::clone(cx.kernel.task().container().clock());
                        let now =
                            linux_clock_duration(&clock, crate::posix_timer::clock_id(id) as u64)
                                .unwrap_or(Duration::ZERO);
```

Replace lines 738-746:
```rust
        fn adjtimex(this, cx, address: GuestPtr) {
            Ok(adjtimex_bootstrap(&mut *cx.memory, address.0))
        }

        fn clock_adjtime(this, cx, clock_id: u64, address: GuestPtr) {
            let memory = &mut *cx.memory;
            if clock_id != LINUX_CLOCK_REALTIME {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(adjtimex_bootstrap(memory, address.0))
        }
```
with
```rust
        fn adjtimex(this, cx, address: GuestPtr) {
            let clock = Arc::clone(cx.kernel.task().container().clock());
            Ok(adjtimex_bootstrap(&clock, &mut *cx.memory, address.0))
        }

        fn clock_adjtime(this, cx, clock_id: u64, address: GuestPtr) {
            if clock_id != LINUX_CLOCK_REALTIME {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let clock = Arc::clone(cx.kernel.task().container().clock());
            Ok(adjtimex_bootstrap(&clock, &mut *cx.memory, address.0))
        }
```

In `x86_time`, replace line 751:
```rust
            let seconds = i64::try_from(realtime_duration().as_secs()).unwrap_or(i64::MAX);
```
with
```rust
            let now = cx.kernel.task().container().clock().realtime_now();
            let seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
```

In `gettimeofday`, replace line 765:
```rust
            let now = realtime_duration();
```
with
```rust
            let now = cx.kernel.task().container().clock().realtime_now();
```

In `settimeofday`, replace lines 805-815:
```rust
            let raw_now = {
                set_guest_realtime_offset_ns(0);
                realtime_duration()
            };
            let delta_ns = if target_duration >= raw_now {
                (target_duration - raw_now).as_nanos() as i64
            } else {
                -((raw_now - target_duration).as_nanos() as i64)
            };
            set_guest_realtime_offset_ns(delta_ns);
            Ok(DispatchOutcome::Returned { value: 0 })
```
with
```rust
            let clock = Arc::clone(cx.kernel.task().container().clock());
            let raw_now = clock.realtime_base_now();
            let delta_ns = if target_duration >= raw_now {
                (target_duration - raw_now).as_nanos() as i64
            } else {
                -((raw_now - target_duration).as_nanos() as i64)
            };
            clock.set_realtime_offset_ns(delta_ns);
            if let Err(error) = clock.publish_vvar_realtime_offset(&mut *cx.memory) {
                tracing::warn!(%error, "settimeofday: vvar realtime word not republished");
            }
            Ok(DispatchOutcome::Returned { value: 0 })
```
(`let memory = &*cx.memory;` at line 786 keeps its last use at the `read_bytes` on line 796, so the later `&mut *cx.memory` borrow is valid under NLL.)

In `times`, replace line 850:
```rust
            let secs = realtime_duration().as_secs();
```
with
```rust
            let secs = cx.kernel.task().container().clock().realtime_now().as_secs();
```

Delete the obsolete test at lines 1503-1514:
```rust
    #[test]
    fn guest_realtime_offset_virtual_clock() {
        use crate::dispatch::{get_guest_realtime_offset_ns, set_guest_realtime_offset_ns};

        set_guest_realtime_offset_ns(0);
        assert_eq!(get_guest_realtime_offset_ns(), 0);

        set_guest_realtime_offset_ns(1_000_000_000);
        assert_eq!(get_guest_realtime_offset_ns(), 1_000_000_000);

        set_guest_realtime_offset_ns(0);
    }
```
(its coverage now lives in `clock_domain_tests` and `container_clock_tests`).

- [ ] **Step 9: Re-publish the container's vvar word into a freshly exec'd image**

`populate_vdso_data_page` (`crates/carrick-vmm-hvf/src/trap.rs:15610` at 3dc6cc72, 15707 at HEAD; called from vCPU construction at ~11984 and from the exec image-replace path at ~18734) stamps the new mm's vvar page with the host-only base (and re-publishes it through `set_realtime_off_ns`) at every exec; the container's offset must be layered on top from the runtime, which knows the task's container. In `crates/carrick-runtime/src/vcpu_loop/exec.rs`, directly after the identity-page stamp block (lines 1509-1521 at 3dc6cc72; 1673-1685 at HEAD):
```rust
        if let Err(error) = super::stamp_identity_page_at(
            engine,
            &kernel.dispatcher,
            &committed_context,
            identity_base,
        ) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("stamp HVPatch exec identity page: {error}"),
            )
            .map(Some);
        }
```
insert:
```rust
        // The VMM stamped the new image's vvar with the host-only realtime
        // base; layer this container's offset on so the exec'd process's
        // vDSO CLOCK_REALTIME matches its syscall path from the first read.
        if let Err(error) = committed_context
            .task()
            .container()
            .clock()
            .publish_vvar_realtime_offset(engine)
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("publish HVPatch exec vvar realtime offset: {error}"),
            )
            .map(Some);
        }
```
(`engine: &mut E` with `E: ThreadedEngine`, and `ThreadedEngine: GuestMemory` (`carrick-hal/src/threaded.rs:1378`), so the reborrow satisfies `&mut impl GuestMemory`. Fork children COW-inherit the parent's already-published vvar page and inherit its container, so the fork path needs no stamp.)

- [ ] **Step 10: Green — run the targeted tests, then the gates**

```bash
cd /Volumes/CaseSensitive/carrick && just test clock_domain_tests && just test container_clock_tests
```
Expected: `test kernel::container::clock_domain_tests::system_domain_starts_unshifted ... ok`, `two_domains_hold_independent_offsets ... ok`, `vvar_word_adds_the_signed_offset_with_wrapping ... ok` from the first command; `dispatch::container_clock_tests::clock_gettime_realtime_reads_the_callers_container_domain ... ok`, `clock_settime_moves_only_the_callers_container ... ok`, `timerfd_deadline_is_bound_to_the_creating_containers_clock ... ok` from the second; each ends `test result: ok`.

```bash
cd /Volumes/CaseSensitive/carrick && ! rg -n 'GUEST_REALTIME_OFFSET_NS|guest_realtime_offset_ns|realtime_duration\(\)' crates/ --type rust && just fmt && just clippy && just lint-domains && just test
```
Expected: the grep prints nothing (assertion exit 0), `cargo clippy ... -D warnings` finishes with no warnings, lint-domains reports no findings, `just test` ends with every crate `test result: ok`.

- [ ] **Step 11: Commit**

```bash
cd /Volumes/CaseSensitive/carrick && git add crates/carrick-runtime/src/kernel/container.rs crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/dispatch/time.rs crates/carrick-runtime/src/dispatch/fd_table.rs crates/carrick-runtime/src/dispatch/tests.rs crates/carrick-runtime/src/vcpu_loop/exec.rs && git commit -F - <<'EOF'
refactor(runtime): move guest realtime offset into container ClockDomain

Why: `GUEST_REALTIME_OFFSET_NS` was one process-global `AtomicI64` in
`dispatch/mod.rs`, so a guest `clock_settime`/`settimeofday` in ONE
HVPatch Linux process shifted CLOCK_REALTIME for every process in the
carrier, and two containers in one carrier (Phase B) could not hold
different wall clocks. The vvar word was also never re-stamped after the
offset moved, so `clock_gettime` via the vDSO and via the syscall
disagreed by the offset for the rest of the process's life.

What: `ClockDomain` (System mode only) on `kernel/container.rs` owns
`realtime_offset_ns`; `Container::clock()` is the only way to reach it.
`linux_clock_duration`, `linux_clock_nanosleep_now`, `adjtimex_bootstrap`
and the timerfd readers take `&ClockDomain`; every `dispatch/time.rs`
handler resolves it through `cx.kernel.task().container().clock()`.
A timerfd captures its creating container's domain (`TimerFdState.clock`),
matching Linux's binding of a timerfd to its creator's time namespace.
`clock_settime`/`settimeofday` compute their delta from
`realtime_base_now()` instead of transiently zeroing the shared offset,
and publish `base + offset` into the calling process's
`VVAR_OFF_REALTIME_OFF_NS` through `write_bytes_unchecked`; the HVPatch
exec path re-publishes it into the fresh image's vvar after the identity
stamp. Deliberate approximation: sibling processes of the same container
see the new vvar word at their next exec (their syscall path is exact
immediately); Phase F's seqlock-published vvar mode word closes that gap.
The host-derived base (`carrick_mem::vdso::REALTIME_OFF_NS`) stays a
carrier calibration value, not container state.

Verified: `just test clock_domain_tests` red (E0599: no `clock()`, no
`ClockDomain`) before; `just test clock_domain_tests` and `just test
container_clock_tests` green after (six tests); `just test`, `just
clippy`, `just lint-domains` green; `rg GUEST_REALTIME_OFFSET_NS crates/`
prints nothing.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

### Task 21: Derive launch capability grants from the container

**Files:** (line numbers as of 3dc6cc72; `dispatch/mod.rs` is +49 at HEAD ea0dac4c — `apply_seccomp_policy`/`apply_launch_privileges` at 5792-5825 — and `dispatch/tests.rs` closes at 4409; the other files are unchanged.)
- Modify: `crates/carrick-runtime/src/namespace/process.rs:135-149` (`CapabilitySet::docker_default`), `:194-208` (delete `LAUNCH_GRANTED_CAPS`, `grant_launch_capabilities`, `launch_granted_capabilities` with their doc comments)
- Modify: `crates/carrick-runtime/src/kernel/container.rs` (Task 11's file; add `granted_caps: CapabilitySet`, `Container::with_launch_capabilities`, `Container::granted_caps`)
- Modify: `crates/carrick-runtime/src/kernel/core.rs:823-830` (`Kernel::bootstrap_root` seeds the root task's sets from its container)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:5743-5776` (`apply_seccomp_policy`, `apply_launch_privileges`)
- Modify: `crates/carrick-runtime/src/execute.rs:342, 439`
- Modify: `crates/carrick-cli/src/commands.rs:585`
- Test: `crates/carrick-runtime/src/namespace/process.rs` (`mod tests`), `crates/carrick-runtime/src/dispatch/tests.rs` (new `mod container_caps_tests`)

**Interfaces:**
- Consumes (Task 11): `Container::for_reference_model() -> Container` (the container a `RootBootstrap::for_reference_model` kernel attaches; not yet `Arc`-wrapped so builders can chain); `RootBootstrap::with_container(self, container: Arc<Container>) -> Self`; `Task::container(&self) -> Arc<Container>`; the `Container` value Task 11 constructs in `execute.rs` (both the Host and Memory fs branches) and in the CLI `run-elf` path.
- Consumes (tree): `capability_mask_for_names(&[String]) -> (u64, Vec<String>)` (`namespace/process.rs:101`); `ContainerPolicy::docker_model_with_capabilities(granted: u64)` (`container_policy.rs:181`, `pub(crate)`; it tests only the `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` bits); `ContainerPolicy::denied_errno_for_args(&self, canonical_nr: u64, first_arg: u64) -> Option<LinuxErrno>` (`container_policy.rs:275`); `Task::with_caps` / `Task::caps` (`kernel/objects.rs:2961-2973`); `RootBootstrap::for_reference_model(observed_pid: i32, registry_id: ThreadId, diagnostic_name: String) -> Result<Self, KernelError>` (`kernel/core.rs:278`); `Kernel::bootstrap_root(RootBootstrap) -> Result<(Arc<Kernel>, KernelContext), KernelError>` (`kernel/core.rs:795`); `carrick_hal::ThreadId::synthetic_for_tests(i32)` (re-exported as `crate::thread::ThreadId`; `kernel/tests.rs:17-23` is the pattern).
- Produces:
  - `impl CapabilitySet { pub fn docker_default() -> Self /* now a pure constant */; pub fn docker_default_with_grants(granted: u64) -> Self; }`
  - `impl Container { pub fn with_launch_capabilities(self, cap_add: &[String]) -> Self; pub fn granted_caps(&self) -> CapabilitySet; }` (`CapabilitySet` is the existing five-set `Copy` type at `process.rs:125-132` — the contract's `CapSet`)
  - `impl SyscallDispatcher { pub fn apply_launch_privileges(&mut self, policy: carrick_spec::SeccompPolicy, container: &crate::kernel::container::Container); pub fn apply_seccomp_policy(&mut self, policy: carrick_spec::SeccompPolicy) /* unchanged signature, grant-free */; }`

- [ ] **Step 1: Red — assert the static is gone (fails now)**

```bash
cd /Volumes/CaseSensitive/carrick && ! rg -n 'LAUNCH_GRANTED_CAPS|launch_granted_capabilities|grant_launch_capabilities' crates/ --type rust
```
Expected now: prints the definitions at `namespace/process.rs:198-207` (static at 198, the two accessors through 207; their doc comments begin at 194 and the last closing brace is 208), the reader at `:141` (plus its comment at `:140`) and the writer at `dispatch/mod.rs:5768` (5817 at HEAD); exit 1. Must exit 0 at the end of this task.

- [ ] **Step 2: Red — pure constructor test in `namespace/process.rs`**

Add inside the existing `mod tests` (after the closing `}` of `docker_default_excludes_sys_ptrace`, line 359):

```rust
    #[test]
    fn docker_default_with_grants_raises_effective_permitted_bounding_only() {
        let bit = 1u64 << CAP_SYS_ADMIN;
        let granted = CapabilitySet::docker_default_with_grants(bit);
        assert_eq!(granted.effective, DOCKER_DEFAULT_CAPS | bit);
        assert_eq!(granted.permitted, DOCKER_DEFAULT_CAPS | bit);
        assert_eq!(granted.bounding, DOCKER_DEFAULT_CAPS | bit);
        assert_eq!(granted.inheritable, 0);
        assert_eq!(granted.ambient, 0);
        // The plain default is a constant: no launch grant can leak into it.
        assert_eq!(CapabilitySet::docker_default(), CapabilitySet::docker_default_with_grants(0));
        assert_eq!(CapabilitySet::docker_default().effective, DOCKER_DEFAULT_CAPS);
    }
```

- [ ] **Step 3: Red — two-container capability tests**

Append to the end of `crates/carrick-runtime/src/dispatch/tests.rs` (after `container_clock_tests` from Task 14):

```rust
#[cfg(test)]
mod container_caps_tests {
    //! Launch-time `--cap-add` grants are container state. Two containers in
    //! one carrier must give their root tasks — and their launch policies —
    //! different privilege, which a process-global grant cannot express.
    use super::*;
    use crate::kernel::container::Container;
    use crate::kernel::{Kernel, KernelContext, RootBootstrap};
    use crate::namespace::process::{CAP_SYS_ADMIN, CAP_SYS_PTRACE, DOCKER_DEFAULT_CAPS};
    use carrick_spec::SeccompPolicy;

    /// aarch64 `unshare`: Docker's default profile denies it unless the
    /// container holds CAP_SYS_ADMIN (`container_policy.rs`, `SYS_UNSHARE`).
    const SYS_UNSHARE: u64 = 97;

    fn container_with(cap_add: &[&str]) -> Arc<Container> {
        let names: Vec<String> = cap_add.iter().map(|name| (*name).to_owned()).collect();
        Arc::new(Container::for_reference_model().with_launch_capabilities(&names))
    }

    fn root_context_in(container: Arc<Container>, pid: i32) -> KernelContext {
        let bootstrap = RootBootstrap::for_reference_model(
            pid,
            crate::thread::ThreadId::synthetic_for_tests(pid),
            "container-caps-root".to_owned(),
        )
        .expect("root bootstrap")
        .with_container(container);
        Kernel::bootstrap_root(bootstrap).expect("root kernel").1
    }

    #[test]
    fn root_task_capabilities_come_from_its_container() {
        let plain = root_context_in(container_with(&[]), 7101);
        let ptrace = root_context_in(container_with(&["SYS_PTRACE"]), 7102);
        let bit = 1u64 << CAP_SYS_PTRACE;
        assert_eq!(plain.task().caps().effective, DOCKER_DEFAULT_CAPS);
        assert_eq!(plain.task().caps().effective & bit, 0);
        let granted = ptrace.task().caps();
        assert_ne!(granted.effective & bit, 0);
        assert_ne!(granted.permitted & bit, 0);
        assert_ne!(granted.bounding & bit, 0);
        assert_eq!(granted.inheritable, 0);
        // Bootstrapping the second container never changed the first.
        assert_eq!(plain.task().caps().effective, DOCKER_DEFAULT_CAPS);
    }

    #[test]
    fn launch_policy_follows_the_containers_grant() {
        let mut plain = SyscallDispatcher::new();
        plain.apply_launch_privileges(SeccompPolicy::ContainerDefault, &container_with(&[]));
        let mut admin = SyscallDispatcher::new();
        admin.apply_launch_privileges(
            SeccompPolicy::ContainerDefault,
            &container_with(&["SYS_ADMIN"]),
        );
        assert_eq!(
            plain
                .container_policy
                .as_ref()
                .expect("plain policy")
                .denied_errno_for_args(SYS_UNSHARE, 0),
            Some(LINUX_EPERM),
            "without CAP_SYS_ADMIN the Docker model denies unshare"
        );
        assert_eq!(
            admin
                .container_policy
                .as_ref()
                .expect("admin policy")
                .denied_errno_for_args(SYS_UNSHARE, 0),
            None,
            "the container's own CAP_SYS_ADMIN lifts the denial"
        );
        let bit = 1u64 << CAP_SYS_ADMIN;
        assert_ne!(container_with(&["SYS_ADMIN"]).granted_caps().effective & bit, 0);
        assert_eq!(container_with(&[]).granted_caps().effective & bit, 0);
    }
}
```

- [ ] **Step 4: Run the red tests**

```bash
cd /Volumes/CaseSensitive/carrick && just test container_caps_tests
```
Expected: the `cargo test -p carrick-runtime --lib` step fails to compile — `error[E0599]: no function or associated item named `docker_default_with_grants``, `no method named `with_launch_capabilities``, `no method named `granted_caps``, and `apply_launch_privileges` expected `&[String]`, found `&Arc<Container>` (E0308). Red for the right reason. (`just test docker_default_with_grants` fails with the same compile error; one filter per invocation.)

- [ ] **Step 5: Make `CapabilitySet::docker_default` pure and delete the static**

In `crates/carrick-runtime/src/namespace/process.rs`, replace lines 135-149:
```rust
    /// The default container set (effective=permitted=bounding = Docker
    /// default; inheritable/ambient empty), matching observed `docker run`.
    pub fn docker_default() -> Self {
        // `--cap-add` raises the effective/permitted/bounding sets exactly as
        // docker does; the grant is a launch-time constant (see
        // `grant_launch_capabilities`).
        let caps = DOCKER_DEFAULT_CAPS | launch_granted_capabilities();
        Self {
            effective: caps,
            permitted: caps,
            inheritable: 0,
            bounding: caps,
            ambient: 0,
        }
    }
```
with
```rust
    /// The default container set (effective=permitted=bounding = Docker
    /// default; inheritable/ambient empty), matching observed `docker run`.
    /// A pure constant: launch-time `--cap-add` grants are container state
    /// (`Container::granted_caps`), never folded into this default.
    pub fn docker_default() -> Self {
        Self::docker_default_with_grants(0)
    }

    /// The Docker default raised by a launch-time `--cap-add` grant mask
    /// (bits from `capability_mask_for_names`). `--cap-add` raises the
    /// effective/permitted/bounding sets exactly as docker does and leaves
    /// inheritable/ambient empty.
    pub fn docker_default_with_grants(granted: u64) -> Self {
        let caps = DOCKER_DEFAULT_CAPS | granted;
        Self {
            effective: caps,
            permitted: caps,
            inheritable: 0,
            bounding: caps,
            ambient: 0,
        }
    }
```

Delete lines 194-208 (doc comments through the last closing brace):
```rust
/// Capabilities granted at launch by `--cap-add`, ORed into the container
/// default set every process starts from. A launch-time constant: written
/// once before the guest boots and read-only thereafter, exactly like the
/// container syscall policy it travels with.
static LAUNCH_GRANTED_CAPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record the launch-time `--cap-add` grant. Called once, before boot.
pub fn grant_launch_capabilities(mask: u64) {
    LAUNCH_GRANTED_CAPS.store(mask, std::sync::atomic::Ordering::Release);
}

/// The launch-time grant, for the container default set.
pub fn launch_granted_capabilities() -> u64 {
    LAUNCH_GRANTED_CAPS.load(std::sync::atomic::Ordering::Acquire)
}
```

- [ ] **Step 6: Put the grant on the `Container`**

In `crates/carrick-runtime/src/kernel/container.rs`, add the field to `Container` (initialize it as `granted_caps: CapabilitySet::docker_default()` in Task 11's constructor; if Task 11 declared it with a different type, replace that type with `CapabilitySet`):

```rust
use crate::namespace::process::{CapabilitySet, capability_mask_for_names};

    /// The capability set every process of this container starts from: the
    /// Docker default raised by the launch-time `--cap-add` grant. A launch
    /// constant — set once through `with_launch_capabilities` before the
    /// root task is bootstrapped, then read-only; forks copy it per task.
    granted_caps: CapabilitySet,
```

and inside `impl Container`:

```rust
    /// Record the launch-time `--cap-add` grant. Unknown names are logged and
    /// ignored, exactly as the dispatcher did when the grant was a static.
    pub fn with_launch_capabilities(mut self, cap_add: &[String]) -> Self {
        let (granted, unknown) = capability_mask_for_names(cap_add);
        for name in &unknown {
            tracing::warn!(capability = %name, "ignoring unknown --cap-add name");
        }
        self.granted_caps = CapabilitySet::docker_default_with_grants(granted);
        self
    }

    /// The set this container's root task boots with (and every descendant
    /// inherits by fork copy until it changes its own).
    pub fn granted_caps(&self) -> CapabilitySet {
        self.granted_caps
    }
```

- [ ] **Step 7: Seed the root task from its container in `Kernel::bootstrap_root`**

In `crates/carrick-runtime/src/kernel/core.rs`, after the root task is built (lines 823-830):
```rust
        let task = Arc::new(Task::new(
            task_key,
            None,
            process_group_id,
            session_id,
            Arc::clone(&shared),
            resources.credentials(),
        ));
```
and immediately after Task 11's statement that attaches `task` to `bootstrap`'s container (before `let leader_tid = LinuxTid::for_task_leader(bootstrap.task_id);`, line 831), insert:
```rust
        // The container's launch-time grant is the root task's starting
        // capability set; `Task::new` seeds the grant-free Docker default
        // (`ProcessCredsNs::default()`) and forks copy whatever the parent
        // holds (`inherit_creds_ns_from`).
        let launch_caps = task.container().granted_caps();
        task.with_caps(|caps| *caps = launch_caps);
```

- [ ] **Step 8: Route `apply_launch_privileges` through the container**

In `crates/carrick-runtime/src/dispatch/mod.rs`, replace lines 5743-5776 (5792-5825 at HEAD):
```rust
    /// Apply a launch-time container syscall policy (the `carrick run` /
    /// `--security-opt seccomp=…` resolution). Must be called before the guest
    /// boots — the field is then read-only and inherited across guest
    /// fork/execve like a Linux seccomp filter. `Unconfined` clears it.
    pub fn apply_seccomp_policy(&mut self, policy: carrick_spec::SeccompPolicy) {
        self.apply_launch_privileges(policy, &[]);
    }

    /// Apply the launch-time policy AND the container's `--cap-add` grants
    /// together, because Docker's profile is capability-conditional: the same
    /// `--cap-add SYS_ADMIN` that raises the capability set also lifts the
    /// profile's denial of `bpf`/`unshare`/`setns`/`io_uring`. Applying one
    /// without the other is what left carrick running at a DIFFERENT
    /// privilege from the oracle on the 48 suites that grant capabilities.
    /// Must be called before the guest boots.
    pub fn apply_launch_privileges(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        cap_add: &[String],
    ) {
        let (granted, unknown) = crate::namespace::process::capability_mask_for_names(cap_add);
        for name in &unknown {
            tracing::warn!(capability = %name, "ignoring unknown --cap-add name");
        }
        if granted != 0 {
            crate::namespace::process::grant_launch_capabilities(granted);
        }
        self.container_policy = match policy {
            carrick_spec::SeccompPolicy::ContainerDefault => Some(
                crate::container_policy::ContainerPolicy::docker_model_with_capabilities(granted),
            ),
            carrick_spec::SeccompPolicy::Unconfined => None,
        };
    }
```
with
```rust
    /// Apply a launch-time container syscall policy (the `carrick run` /
    /// `--security-opt seccomp=…` resolution) with no capability grant —
    /// the bare `run-elf`/unit-test shape. Must be called before the guest
    /// boots — the field is then read-only and inherited across guest
    /// fork/execve like a Linux seccomp filter. `Unconfined` clears it.
    pub fn apply_seccomp_policy(&mut self, policy: carrick_spec::SeccompPolicy) {
        self.install_container_policy(
            policy,
            crate::namespace::process::CapabilitySet::docker_default(),
        );
    }

    /// Apply the launch-time policy from the container's OWN capability set,
    /// because Docker's profile is capability-conditional: the same
    /// `--cap-add SYS_ADMIN` that raises the capability set also lifts the
    /// profile's denial of `bpf`/`unshare`/`setns`/`io_uring`. The grant and
    /// the policy now come from one authority (`Container::granted_caps`), so
    /// they cannot disagree the way a static grant applied in a different
    /// order could. Must be called before the guest boots.
    pub fn apply_launch_privileges(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        container: &crate::kernel::container::Container,
    ) {
        self.install_container_policy(policy, container.granted_caps());
    }

    fn install_container_policy(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        caps: crate::namespace::process::CapabilitySet,
    ) {
        // `docker_model_with_capabilities` tests CAP_SYS_ADMIN / CAP_SYS_PTRACE
        // bits; the Docker default set holds neither (pinned by
        // `docker_default_excludes_sys_ptrace`), so the container's effective
        // set is exactly the old grant mask for the profile's purposes.
        self.container_policy = match policy {
            carrick_spec::SeccompPolicy::ContainerDefault => Some(
                crate::container_policy::ContainerPolicy::docker_model_with_capabilities(
                    caps.effective,
                ),
            ),
            carrick_spec::SeccompPolicy::Unconfined => None,
        };
    }
```

- [ ] **Step 9: Feed the grant in at the two runtime call sites and the CLI**

In `crates/carrick-runtime/src/execute.rs`, at the `Container` construction Task 11 added (shared by both fs branches), chain the grant before the value is `Arc`-wrapped:
```rust
        .with_launch_capabilities(&spec.cap_add)
```
Then replace line 342:
```rust
                dispatcher.apply_launch_privileges(spec.seccomp_policy, &spec.cap_add);
```
with
```rust
                dispatcher.apply_launch_privileges(spec.seccomp_policy, &container);
```
and line 439:
```rust
                dispatcher.apply_launch_privileges(spec.seccomp_policy, &spec.cap_add);
```
with
```rust
                dispatcher.apply_launch_privileges(spec.seccomp_policy, &container);
```
(`container` is the `Arc<Container>` local Task 11 introduced in `execute.rs`; `&container` auto-derefs to `&Container`.)

In `crates/carrick-cli/src/commands.rs`, replace line 585:
```rust
            dispatcher.apply_launch_privileges(seccomp_policy, &[]);
```
with
```rust
            dispatcher.apply_launch_privileges(seccomp_policy, &container);
```
where `container` is the grant-free `run-elf` container Task 11's CLI path constructs (`run-elf` has no `--cap-add`, so its `granted_caps()` is the Docker default).

The remaining `apply_seccomp_policy` callers (`dispatch/tests.rs:4100,4184,4215` and `dispatch/perf.rs:1256`) keep compiling unchanged.

- [ ] **Step 10: Green — targeted tests, then the gates**

```bash
cd /Volumes/CaseSensitive/carrick && just test docker_default && just test container_caps_tests
```
Expected: first command — `namespace::process::tests::docker_default_with_grants_raises_effective_permitted_bounding_only ... ok` plus the four existing `docker_default_*` tests (`_status_lines_match_observed`, `_has_setuid_setgid`, `_excludes_sys_resource`, `_excludes_sys_ptrace`) still `ok`; second command — `dispatch::container_caps_tests::root_task_capabilities_come_from_its_container ... ok`, `launch_policy_follows_the_containers_grant ... ok`.

```bash
cd /Volumes/CaseSensitive/carrick && ! rg -n 'LAUNCH_GRANTED_CAPS|launch_granted_capabilities|grant_launch_capabilities' crates/ --type rust && just fmt && just clippy && just lint-domains && just test
```
Expected: grep prints nothing (exit 0), clippy clean under `-D warnings`, lint-domains clean, every `just test` crate `test result: ok` (including `dispatch::container_policy_dispatch_tests::*`, which still go through `apply_seccomp_policy`).

- [ ] **Step 11: Commit**

```bash
cd /Volumes/CaseSensitive/carrick && git add crates/carrick-runtime/src/namespace/process.rs crates/carrick-runtime/src/kernel/container.rs crates/carrick-runtime/src/kernel/core.rs crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/dispatch/tests.rs crates/carrick-runtime/src/execute.rs crates/carrick-cli/src/commands.rs && git commit -F - <<'EOF'
refactor(runtime): derive launch capability grants from the container

Why: `LAUNCH_GRANTED_CAPS` (`namespace/process.rs`) was a process-global
`AtomicU64` read by `CapabilitySet::docker_default()`, so every root task
bootstrapped in the carrier — a second container's included — inherited
whichever `--cap-add` grant was stored last, and the launch policy
(`apply_launch_privileges`) and the task's capability set only agreed by
call-order accident. Two containers in one carrier (Phase B) need their
own grants.

What: `Container.granted_caps: CapabilitySet` is the launch-time
constant, built once by `Container::with_launch_capabilities(cap_add)`
from `capability_mask_for_names`; `Kernel::bootstrap_root` seeds the root
task's five sets from its container and forks copy them as before.
`CapabilitySet::docker_default()` is now a pure constant and
`docker_default_with_grants(mask)` the grant-raising constructor.
`SyscallDispatcher::apply_launch_privileges(policy, &Container)` derives
Docker's capability-conditional deny table from the container's
effective set — equivalent to the old grant mask because the Docker
default holds neither CAP_SYS_ADMIN nor CAP_SYS_PTRACE (pinned by the
existing `docker_default_excludes_*` tests). `apply_seccomp_policy` keeps
its grant-free shape for run-elf and tests. The static and both
accessors are deleted; no compatibility path.

Verified: `just test container_caps_tests` red (E0599
`with_launch_capabilities`/`granted_caps` missing, E0308 on
`apply_launch_privileges`) before; `just test docker_default` and `just
test container_caps_tests` green after; `just test`, `just clippy`,
`just lint-domains` green; `rg LAUNCH_GRANTED_CAPS crates/` prints
nothing.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

<details><summary>Verifier problems fixed in place (16) and claims still unverified (6)</summary>

- fixed: `just test container_clock clock_domain` (Task 14 Steps 4/10, commit body) and `just test container_caps docker_default_with_grants [docker_default]` (Task 15 Steps 4/10, commit body) pass 2-3 positionals to `cargo test`, which accepts exactly ONE `[TESTNAME]` (`cargo test --help`: `cargo test [OPTIONS] [TESTNAME] [-- [ARGS]...]`); the recipe appends `{{ARGS}}` verbatim, so the command errors with `unexpected argument` before compiling and the red step fails for the wrong reason. Split into one `just test <filter>` per module.
- fixed: Task 14 Step 1: the grep prints 16 matches at 3dc6cc72/HEAD (6 in dispatch/mod.rs, 10 in dispatch/time.rs), not 17.
- fixed: Task 14 Files/Step 6: `dispatch/mod.rs:7480-7521` conflates the deletion (7480-7517: static, both accessors, `realtime_duration`) with the doc comment + signature that stay (7519-7522); the `host_clock_duration` signature is at 7522. Fixed the range.
- fixed: Task 14 Step 3: `include!("tests.rs")` is at `dispatch/mod.rs:9958` at 3dc6cc72 (10007 at the working-tree HEAD ea0dac4c), not 9959.
- fixed: Task 14 Step 6 hedged 'If `SystemTime`/`UNIX_EPOCH` become unused'. They DO: `mod.rs:139` is `use std::time::{Duration, SystemTime, UNIX_EPOCH};` and the only uses in mod.rs are the four lines inside `realtime_duration` being deleted, so `-D warnings` fails unless the import shrinks to `use std::time::Duration;`. Made the edit definitive.
- fixed: Task 14 Files (`fd_table.rs:203-231`) and Step 7 (`replace lines 203-220`): `#[derive(Debug)] pub(super) struct TimerFdState` starts at 204 and the `impl TimerFdState` closes at 222; the quoted block is 204-222 (`TimerFdInner` follows at 224-230).
- fixed: Task 14 Step 8 line ranges: `fn timerfd_create` is 153-160 (152 is `define_syscall! {`); the `settimeofday` block quoted (`let raw_now = {` .. `Ok(Returned)`) is 805-815, not 804-815 (804 is `let target_duration`); `memory.read_bytes(timeval.0, 16)` is line 796, not 797. Files list corrected to match.
- fixed: Task 14 Step 9: `populate_vdso_data_page` is at `crates/carrick-vmm-hvf/src/trap.rs:15610` at 3dc6cc72 (15707 at HEAD), not 18636. It is called from vCPU construction (11984) AND the exec image-replace path (18734), and each call recomputes `unix_ns - mono_ns` and re-publishes it via `set_realtime_off_ns`, so the doc comment's 'stamped at vCPU construction' was corrected to 'at vCPU construction and every exec replace'.
- fixed: Task 14 Step 3 test used `LINUX_TIMER_ABSTIME` (the clock_nanosleep flag const) as the `timerfd_settime` flag word; the ABI has the typed `LinuxTfdFlags::TIMER_ABSTIME` (carrick-abi/src/lib.rs:5098, in dispatch scope via mod.rs:604). Switched to `LinuxTfdFlags::TIMER_ABSTIME.bits()` per the typed-domains rule.
- fixed: Task 14 Step 2/3 tests: `assert!(gap >= X && gap <= Y)` trips clippy `manual_range_contains` (warn-by-default, fatal under `just clippy -- -D warnings`); replaced with `(X..=Y).contains(&gap)`. The hand-rolled `abs_diff` helpers were replaced with `Duration::abs_diff` (stable since 1.81; toolchain pin is 1.96.0).
- fixed: Task 14 Step 11 commit subject was 81 chars (`refactor(runtime): move the guest realtime offset into the container clock domain`), over the ~72 guideline; shortened to 72.
- fixed: Task 14 Interfaces: `Task::with_caps`/`Task::caps` are at `kernel/objects.rs:2961-2973` (`caps` 2961-2964, `with_caps` 2971-2973), not 2958-2968.
- fixed: Task 15 Step 1 says the definitions are at `namespace/process.rs:198-207` and Step 5 says 'Delete lines 194-207': the doc comment starts at 194, the static is at 198, and the closing `}` of `launch_granted_capabilities` is at 208. Deleting 194-207 leaves a dangling `}`. Fixed to 194-208.
- fixed: Task 15 Step 2: `docker_default_excludes_sys_ptrace` spans 351-359 (`fn` at 352, closing `}` at 359); inserting 'after line 358' lands inside the function body. Fixed to after 359.
- fixed: Task 15 Step 8: 'replace lines 5741-5776' — 5741 is the closing `}` of `SyscallDispatcher::dispatch` and 5742 is blank; the `apply_seccomp_policy` doc comment starts at 5743. Fixed to 5743-5776 (5792-5825 at HEAD).
- fixed: Base-revision drift: the brief names HEAD as 3dc6cc72 but the working tree is at ea0dac4c (19 commits later). time.rs, fd_table.rs, process.rs, core.rs, execute.rs, commands.rs:585 and guest-mem/vdso/objects line numbers are unchanged; dispatch/mod.rs is +49 (static at 7529, `apply_launch_privileges` at 5797, `include!` at 10007), tests.rs closes at 4409, the exec.rs identity-stamp block is at 1673-1685, trap.rs `populate_vdso_data_page` at 15707. Added a note at the top of each task's Files list so the engineer anchors on the quoted code.
- UNVERIFIED: Task 11's actual surface: `Container` constructor shape, `Container::for_reference_model()`, `RootBootstrap::with_container`, `Task::container()`, and whether reference-model bootstraps (and thus `SyscallDispatcher::new()`) attach a default Container — all assumed from the shared contract; the tests in this cluster depend on them.
- UNVERIFIED: The exact `execute.rs` line where Task 11 constructs the Container (both fs branches) and the CLI run-elf container local in commands.rs — the `.with_launch_capabilities(&spec.cap_add)` chain and `&container` arguments are written against those assumed locals.
- UNVERIFIED: Whether `SyscallDispatcher::dispatch` with a foreign-kernel `KernelContext` would work was NOT relied on: the two-container dispatch tests use two separate `SyscallDispatcher::new()` instances, each with its own kernel/root task, which mirrors existing test patterns but was not executed (read-only brief).
- UNVERIFIED: Under HVF, `write_bytes_unchecked` on the vvar page from the dispatcher's `cx.memory` (clock_settime path) is assumed to reach the calling process's vvar page — the trait doc (carrick-guest-mem/src/lib.rs:590-599) names the vvar as its purpose, but the HVF override was not read; a signed-artifact guest probe (clock_settime then vDSO clock_gettime agreeing with syscall clock_gettime) is the live check and needs the signed recipe.
- UNVERIFIED: Line numbers in dispatch/mod.rs and time.rs are as of 3dc6cc72 and will shift after Tasks 11-13 and Phase A land; the quoted code is what must be matched, not the numbers.
- UNVERIFIED: KVM/x86 lanes never call `set_realtime_off_ns`, so `vvar_realtime_off_ns()` is None there and the vDSO realtime word is not republished after clock_settime on those lanes (unchanged from today, where nothing republishes anywhere).

</details>


<!-- cluster B4-teardown-and-gate -->
## Cluster B4-teardown-and-gate

> **Status: RECONCILIATION PENDING.** Verifier-corrected against `39426141`; task headings were renumbered mechanically (headings renumbered 16..17 -> 22..23), but by-number cross-references inside the text still use the DRAFT numbering (see the renumber table in the index) and the cross-cluster fixes below have NOT been applied. A future session must apply each item, then remove this block.
>
> - [ ] TASK-NUMBER COLLISIONS (5) + one unnumbered cluster: A3 Task 6 (syscall-map doc row) vs A4 Task 6 (net.rs test module); A4 Task 7/8 vs A5 Task 7/8; B2 Task 14/15 vs B3 Task 14/15; C1 Task 21 (host-authority census reconcile, added in review) vs C2 Task 21 (prepare.rs). A2 carries no task number at all. FIX: renumber globally in dependency order and rewrite every cross-reference ('Task 11', 'Task 18', 'Task 19', 'Task 21/22', 'Task 23', 'Task 25/26') to the new numbers: A1=1-3, A2=4, A3=5-7, A4=8-10, A5=11-13, B1=14-15, B2=16-19, B3=20-21, B4=22-23, C1=24-27, C2=28-29, C3=30-31, C4=32-33, C5=34-35. (All consumers below are stated with the ORIGINAL numbers; the renumbering must be applied on top.)
> - [ ] PROBE_SOURCE_COUNT / inventory-denominator collision: A1, A3, A4 and B4 each compute absolute values from the same 465/419/439/878 base (A1 -> 466/440; A3 -> 466,420,440,880 then 467,421,441,882; A4 -> 466 + dedicated 440/880; B4 -> 466). Only the first to land is right; every later one fails `closure_probe_inventory_enforces_authoritative_runners_and_denominator`. FIX (in landing order A1 -> A3 -> A4 -> B4): A1: 466 / generic 420 / 440 / 880 and census line `466 sources {'conformance': 440, ...}`; A3 Task 4: 467/421/441/882, Task 5: 468/422/442/884; A4: PROBE_SOURCE_COUNT 469, DEDICATED == 21, 422+21 == 443, 886; B4: 470, DEDICATED == 22, 444, 888 (and the red-step text 'left 470 / right 469'). Final tree: 470 sources, 422 generic, 22 dedicated.
> - [ ] `LaunchContext::from_process_env()` fallback is required but not produced: C2 requires it to SUCCEED when CARRICK_RUN_ID/CARRICK_CONTAINER_ID are unset (foreground/in-lib tests; 'mirroring runtime.rs:718-722 pid-<pid>'), B4 relies on `Runtime::execute` calling it, and B1's hvpatch fallback calls it for run-elf -- yet B1 only states 'empty CARRICK_RUN_ID counts as absent' and 'unsafe CARRICK_CONTAINER_ID refuses', never what absent yields, and the existing `pid-<pid>` fallback lives in `kernel_arena_run_scope`, which B2 deletes. FIX: B1 produces text: absent/empty CARRICK_RUN_ID -> `RunId::new(format!("pid-{}", std::process::id()))` (this is the one surviving new HA-CATALOG-PROCESS-ID row B1 already reconciles), registry_id None, exec_overlay/launch_authorization from env only when set; Err only on an unsafe registry id.
> - [ ] `Container` construction/handle seam: B1 creates the Container INSIDE the kernel (`Container::new` is pub(super), `Kernel::create_container(LaunchContext)`, `RootBootstrap::with_launch(LaunchContext)`, dispatcher carries only `set_launch_context/launch_context()`), but B2 consumes 'the Arc<Container> binding named `container` built in Runtime::execute BEFORE the SyscallDispatcher' (for `container.install_pid_ns`), B3 consumes the same binding plus `RootBootstrap::with_container(Arc<Container>)` and `Container::for_reference_model() -> Container` (un-Arc'd for builder chaining), and B4 consumes `SyscallDispatcher::container(&self) -> Arc<Container>`. None of those exist in B1. FIX: B1 changes to: `pub(crate) fn Container::new(launch: LaunchContext) -> Container` and `pub fn Container::for_reference_model() -> Container` (caller wraps in Arc), `Kernel::create_container(&self, container: Arc<Container>) -> Result<(), KernelError>` (registers, DuplicateContainer on repeat), `RootBootstrap::with_container(self, Arc<Container>)` replacing `with_launch`, and `SyscallDispatcher::{set_container(&self, Arc<Container>), container(&self) -> Arc<Container>}` replacing `set_launch_context/launch_context()`; `hvpatch::initialize_root_process` reads `dispatcher.container()` (fallback `Arc::new(Container::new(LaunchContext::from_process_env()?))`). execute.rs builds `let container = Arc::new(Container::new(launch))` before the dispatcher; B2/B3/B4 text unchanged except B3's 'this cluster adds clock/granted_caps to the struct literal' (see next item).
> - [ ] B1 census assigns `root_net_ns/root_uts_ns -> Container` and `pty_registry MASTERS` to B3, and B4's Gate B asserts DISTINCT HOSTNAMES per container ('publish_root_nodename today is a process OnceLock, kernel/netns.rs:226-233 ... only B1-B3's de-globalization can make true'), but B3 produces only clock + capabilities. Nobody moves the UTS/net cells or the pty masters, so B4's gate cannot pass. FIX: B3 adds to its produces: `Container { uts_ns: Arc<UtsNamespace>, net_ns: Arc<NetNamespace> }` (existing types behind `root_uts_ns/root_net_ns`), `Container::{uts_ns(), net_ns()}`, `NsProxy::for_container` seeding uts/net from the container, `publish_root_nodename` becoming per-container (`Container::set_hostname` from RunSpec.hostname), deleting the `root_uts_ns`/`root_net_ns` OnceLocks; pty MASTERS row is re-marked 'carrier-infra, unchanged' in the B1 census (B4 does not need it). B4 consumes updates to name these.
> - [ ] B2 vs B4 on the kernel arena: B4 adds `carrier::ensure_arena()` (mutex-serialized wrapper around `ensure_kernel_arena_path_env` + `KernelArena::init_global`) to fix a concurrent `std::env::set_var` race, but B2 (which lands first, Tasks 13-15) deletes `ensure_kernel_arena_path_env`, `init_global`, `create_or_attach_from_env`, `ARENA_PATH_ENV` and replaces them with the lazy singleton `KernelArena::global()` (unlinked temp file, no env). FIX: B4 drops `carrier::ensure_arena()` and the runtime.rs rerouting; concurrent `Runtime::execute` calls use `KernelArena::global()`; B4's carrier.rs doc table names `KernelArena::global` as the arena authority.
> - [ ] B4's `Container::retire` consumes primitives no cluster produces: `pid_root.live_task_count() -> usize`, `pid_root.reap_remaining() -> usize`, `pid_root.release_region() -> bool`, and `Container.mounts (VfsMounts).clear_all()`. B1's `pid_root` is `OnceLock<TaskKey>` (accessor `pid_root() -> Option<TaskKey>`), B2's region is `Container.pid_ns: OnceLock<Arc<NsSharedRegion>>` with `pid_region()` and slot release on Drop, and no Phase-B cluster puts mounts on Container (VfsMounts stays on the dispatcher, vfs/mount.rs). FIX: B4 rewrites `retire_container(container, admission, mounts: &VfsMounts)` (or reads the dispatcher's table) to: task census via the Kernel registry keyed by `container.pid_root()`, `pid_region_released` = `NsSharedRegion::retire(self: Arc<Self>) -> bool` which B2 adds (explicit member retire + slot release; Drop stays as the safety net), `mounts_dropped` from the dispatcher's `VfsMounts::clear_all()` (B4 adds it). B2 adds `pub(crate) fn NsSharedRegion::retire(self: Arc<Self>) -> bool` to its produces; B2's hedge 'if Task 11 defined pid_root as the init TaskKey, keep both fields' becomes definitive: both fields exist.
> - [ ] C2's `Runtime::prepare` is anchored on the 3dc6cc72 `execute.rs`, but Phase B rewrites that function first: B1 (build `Arc<Container>` from LaunchContext, `dispatcher.set_container`), B2 (`container.install_pid_ns`), B3 (`apply_launch_privileges(policy, &Container)` -- C2 still consumes the old `apply_launch_privileges (:5807)` `&[String]` shape), B4 (`carrier::admit_container`/`retire_container`, `record_container_terminal`). C2's trimmed import lists, Step 5/8 counts and the moved body would drop those seams. FIX: C2 consumes lists add B1 `Container::new`/`set_container`, B2 `install_pid_ns`, B3 `apply_launch_privileges(&mut self, SeccompPolicy, &Container)`, B4 `admit_container/retire_container/record_container_terminal`; Task 21 states it moves the POST-Phase-B body and re-derives every execute.rs anchor after B4.
> - [ ] `CliRunRequest -> RunRequest` rename (C1 Task 20, gate `rg CliRunRequest crates/ == 0`) does not cover B4's new consumer: `carrick debug container-gate` (carrick-cli debug.rs) is written against `carrick_engine::CliRunRequest` / `Mount` 'as they exist today'. C1's file list (commands.rs, lifecycle.rs, main.rs, spawn.rs, runtime_util.rs) predates it, so the rename gate and the host-authority census reconcile (C1 Task 21) miss debug.rs. FIX: C1 Task 20 adds `crates/carrick-cli/src/debug.rs` (container-gate constructor -> `RunRequest { stdio: StdioMode::Inherit, host_env: None, bridge_namespace_id: None, ..Default::default() }`) to Files, the rewrite, the rg gate and the Task 21 inventory reconcile; B4 consumes text notes the rename is applied by C1.
> - [ ] C4 consumes a stale Phase-B VM lifecycle: 'sequential PreparedRun::execute calls in ONE carrier process work (the VM is destroyed at run terminal via destroy_persistent_vm_at_run_terminal and re-created)'. B4 renames that fn to `destroy_persistent_vm_at_carrier_exit()` (no alias) and changes the model: the VM persists across containers and is destroyed once at `carrier::shutdown()`/`exit_carrier`. C4's Task 26 red-first step and prose would look for a symbol that no longer exists. FIX: C4 consumes text -> 'B4: VM retained across sequential containers; `destroy_persistent_vm_at_carrier_exit` + `carrier::shutdown()`'; C3 must state that embed never calls `carrier::shutdown()/exit_carrier` (the host process owns exit; VM teardown at process exit is B4's idempotent atexit path) -- add to C3 deviations.
>
### Task 22: Container teardown at run end; the HVF VM and the carrier infrastructure become carrier-lifetime

Line numbers below were verified at tree HEAD `ea0dac4c` (`crates/carrick-vmm-hvf/src/trap.rs` is byte-identical at `39426141`); Tasks 1–15 will shift them — re-anchor on the quoted code, not the numbers.

**Files:**
- Create: `crates/carrick-runtime/src/carrier.rs`
- Modify: `crates/carrick-runtime/src/lib.rs:316-317` (module declaration next to `pub mod threaded_loop;`)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs:2180-2192` (carrier cell beside `rebuilt_vm_cell`), `:4123-4132` (`record_vm_released`), `:4134-4147` (`destroy_persistent_vm_at_run_terminal` → carrier exit), `:4429-4433` (create-funnel Ok arm), `:11772-11786` + `:11814-11836` + `:11985-11987` (`HvfVmState::new_with_plan` reuse lane), `:16611-16627` (`take_persistent_executor_spec` publication), directly before `:6661` (`is_persistent_executor_carrier_mapping`) for the plan audit
- Modify: `crates/carrick-runtime/src/runtime.rs:610-620`, `:647-661` and the closure tail at `:683` (`run_address_space_with_hvf_and_dispatcher`)
- Modify: `crates/carrick-runtime/src/kernel/container.rs` (created by Tasks 1–15; this task appends `Container::retire`)
- Modify: `crates/carrick-runtime/src/execute.rs:892-901` (existing in-process `Runtime::execute` test)
- Modify: `crates/carrick-cli/src/commands.rs:1010-1032`, `:1058`, `:1080`, `:1095`; `crates/carrick-cli/src/lifecycle.rs:601-607`; `crates/carrick-cli/src/main.rs:65-72`
- Modify: `docs/hvpatch-carrier-only-process-plan.md:78` (symbol rename)
- Test: new `#[test]` in `crates/carrick-vmm-hvf/src/trap.rs`; `crates/carrick-runtime/src/carrier.rs` `mod tests`; the extended test in `crates/carrick-runtime/src/execute.rs`

**Interfaces:**
- Consumes (from Tasks 1–15, the shared contract): `crate::kernel::container::{Container, ContainerId}`; `Container::id(&self) -> ContainerId`; a per-run handle to the container reachable from the dispatcher that `Runtime::execute` built — `SyscallDispatcher::container(&self) -> Arc<Container>` (does not exist at HEAD; if B1–B3 named it differently, substitute and record); `Runtime::execute(&RunSpec)` allocating a fresh `Container` per call (so two calls in one process are two containers). `ContainerId` must be `Debug` (used in `{id:?}` messages) and is assumed `Copy` (contract: `pub struct ContainerId(u64)`).
- Consumes (tree, verified at `ea0dac4c`): `carrick_vmm_hvf::trap::{PersistentExecutorSpec (derive Clone, trap.rs:6880-6892), PersistentCarrierMappings::audit (6754-6757), PersistentCarrierMappings::host_pointer (6738), create_vm_with_admission (4405), create_vcpu (4389), create_vcpu_with_permit (4365), rebuilt_vm_cell (2187), prepare_global_exec_plan (9743), prepare_exec_region_raw (19551), exec_stage2_install (19605), inventory_hv_vm_map (19420), inventory_hv_vm_destroy (19504), is_persistent_executor_carrier_guest_mapping (6667), is_sparse_hvpatch_mmap_mapping (9898), GlobalExecPlan { plan, stage2_leases } (9516), GlobalFrameStage2Lease::mark_mapped (6524), MailboxSlotAllocator, HvfSyscallTransport (Copy, syscall_mailbox.rs:25)}`; `carrick_observability::vm_lifecycle::{process_snapshot, record_process_terminal, VmRunTerminalOutcome, VmLifecycleOperation, VM_LIFECYCLE_ARTIFACT_PATH_ENV, write_completed_process_artifact}` (re-exported as `carrick_runtime::vm_lifecycle`, lib.rs:224; `crate::probes::vm_lifecycle` records into the same process ledger, probes.rs:6142-6145); `RuntimeError::{Trap(#[from] TrapError), Configuration(String), Unsupported(String)}` (run_result.rs).
- Produces:
  - `carrick_vmm_hvf::trap::destroy_persistent_vm_at_carrier_exit() -> Result<(), TrapError>` (replaces `destroy_persistent_vm_at_run_terminal`; idempotent; no-op when no VM is live)
  - `carrick_vmm_hvf::trap::carrier_vm_live() -> bool`
  - `carrick_runtime::carrier::live_container_count() -> usize`
  - `carrick_runtime::carrier::ContainerAdmission` (RAII; `pub(crate) fn admit_container(id: ContainerId) -> ContainerAdmission`)
  - `pub struct carrick_runtime::carrier::ContainerTeardown { pub id: ContainerId, pub tasks_reaped: usize, pub mounts_dropped: usize, pub pid_region_released: bool }`
  - `pub(crate) fn carrick_runtime::carrier::retire_container(container: Arc<Container>, admission: ContainerAdmission) -> Result<ContainerTeardown, RuntimeError>`
  - `pub(crate) fn carrick_runtime::carrier::record_container_terminal(outcome: VmRunTerminalOutcome)`
  - `pub fn carrick_runtime::carrier::shutdown() -> Result<(), RuntimeError>` (destroys the VM, records the ledger terminal, publishes the lifecycle artifact — once per carrier)
  - `pub fn carrick_runtime::carrier::exit_carrier(status: i32) -> !`
  - `impl Container { pub(crate) fn retire(self: Arc<Self>) -> Result<ContainerTeardown, RuntimeError> }`

Decision recorded here (the brief asked for it): **the HVF VM, its five VM-global control mappings and the mailbox-slot allocator are carrier-lifetime.** They are created by the first container's root bring-up and destroyed only by `carrier::shutdown()`, which the CLI calls before every process exit. A container's run terminal retires the container — tasks, mounts, pid region — and nothing else. Rationale from the tree: Hypervisor.framework allows one VM per process — the residency table is built on exactly that ("one VM per process, destroy paths release first", trap.rs:4110-4112) and a second `hv_vm_create` while one is live answers `HV_BUSY` (the fork-shape note at runtime.rs:42-44 is the same rule seen across `fork`); `hv_vm_destroy` while another container's vCPUs exist is impossible; and the persistent-executor lane already treats `PersistentExecutorSpec { vm, carrier_mappings, mailbox_slots, syscall_transport }` (trap.rs:6882-6892) as the VM-global bundle every worker vCPU is built from (`from_persistent_executor_spec`, trap.rs:16661-16683). A later container's root is built from that same bundle plus its own image, placed the way `execve_rebuild` places a replacement image (global-frame stage-2 leases + rebased stage-1 tables, trap.rs:18077-18140 → `prepare_global_exec_plan`), so two live roots never collide on identity IPAs. Concurrent root bring-up is serialized by a boot gate so two first roots can never both reach `hv_vm_create`.

- [ ] **Step 1: Write the failing HVF test (red: symbols do not exist)**

Append to the module-level `#[cfg(test)] #[test]` functions that already hold `raw_hvf_stage2_calls_are_inventory_gated` (trap.rs:19512-19537) — place it directly after `reclaim_park_authority_contains_no_task_snapshot` (ends trap.rs:19549):

```rust
#[cfg(test)]
#[test]
fn carrier_exit_without_a_vm_is_a_recorded_no_op() {
    use carrick_observability::vm_lifecycle::{VmLifecycleOperation, process_snapshot};
    fn destroy_events() -> usize {
        process_snapshot()
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.operation,
                    VmLifecycleOperation::DestroyAttempt | VmLifecycleOperation::DestroySuccess
                )
            })
            .count()
    }
    // An unsigned test executable can never create a VM (HV_DENIED), so this
    // process has no live carrier VM: carrier exit must destroy nothing and
    // must NOT append DestroyAttempt/DestroySuccess to the lifecycle ledger.
    // Only destroy-class events are counted: a sibling test in this binary may
    // record a failed LogicalCreateAttempt concurrently.
    let before = destroy_events();
    assert!(!carrier_vm_live());
    destroy_persistent_vm_at_carrier_exit().expect("no VM: nothing to destroy");
    assert_eq!(
        destroy_events(),
        before,
        "carrier exit without a VM must not record destroy events"
    );
}
```

Run: `cargo test -p carrick-vmm-hvf --lib carrier_exit_without_a_vm_is_a_recorded_no_op`
Expected: compile error `E0425: cannot find function `carrier_vm_live``/`destroy_persistent_vm_at_carrier_exit`` — red.

- [ ] **Step 2: Add the carrier cell, the boot gate and the live-VM flag beside `rebuilt_vm_cell`**

In `crates/carrick-vmm-hvf/src/trap.rs`, directly after this existing block (lines 2180-2192):

```rust
/// Process-wide handoff for multithreaded fork: the forking thread (parent),
/// after rebuilding its VM, publishes a clone here so quiesced sibling threads
/// recreate their vCPUs in the same (new) process VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type SharedVm = applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rebuilt_vm_cell() -> &'static parking_lot::Mutex<Option<SharedVm>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Option<SharedVm>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(None))
}
```

add:

```rust
/// Carrier-lifetime HVF VM authority: the ONE `hv_vm_create` per carrier plus
/// the five VM-global control mappings and the mailbox-slot allocator that
/// every container's executors share (`PersistentExecutorSpec`).
///
/// Published by the FIRST root bring-up (`HvfVmState::take_persistent_executor_spec`),
/// consumed by every LATER root bring-up (`HvfVmState::new_with_plan` builds
/// the new container's root inside this VM instead of calling `hv_vm_create`,
/// which would return `HV_BUSY`), and drained exactly once by
/// [`destroy_persistent_vm_at_carrier_exit`]. It is never drained at a
/// container's run terminal: containers come and go inside one VM. Readers
/// still consult [`rebuilt_vm_cell`] first, exactly as
/// `from_persistent_executor_spec` does, so a VM rebuilt after publication
/// supersedes the bundle's handle.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_carrier_cell() -> &'static parking_lot::Mutex<Option<PersistentExecutorSpec>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Option<PersistentExecutorSpec>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(None))
}

/// Signalled by `take_persistent_executor_spec` when the first root publishes
/// the carrier bundle; paired with `persistent_carrier_cell`'s mutex.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_published() -> &'static parking_lot::Condvar {
    static PUBLISHED: parking_lot::Condvar = parking_lot::Condvar::new();
    &PUBLISHED
}

/// Serializes the "does this carrier own a VM yet?" decision across roots
/// booting at the same time. Held across the FIRST root's `hv_vm_create`, so
/// a second root arriving mid-create observes `carrier_vm_live()` and waits
/// for the published bundle instead of issuing its own `hv_vm_create`
/// (which would return `HV_BUSY`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_root_boot_gate() -> &'static parking_lot::Mutex<()> {
    static GATE: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    &GATE
}

/// Bound on how long a later root waits for the first root to publish the
/// carrier bundle (publication happens at that root's persistent-lane start,
/// before any guest instruction runs).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CARRIER_PUBLISH_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether this carrier currently owns a live HVF VM. Set on the single create
/// funnel's success (`create_vm_with_admission`), cleared by
/// `record_vm_released` after a successful `hv_vm_destroy`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static CARRIER_VM_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True while this carrier owns a live HVF VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn carrier_vm_live() -> bool {
    CARRIER_VM_LIVE.load(std::sync::atomic::Ordering::Acquire)
}
```

- [ ] **Step 3: Set/clear the flag at the create funnel and the release point**

In `create_vm_with_admission` (trap.rs:4429-4433) the Ok arm currently reads:

```rust
        Ok(vm) => {
            record_vm_resident();
            crate::probes::vm_lifecycle(1, admission.probe_code());
            Ok((vm, permit))
        }
```

Replace with:

```rust
        Ok(vm) => {
            record_vm_resident();
            CARRIER_VM_LIVE.store(true, std::sync::atomic::Ordering::Release);
            crate::probes::vm_lifecycle(1, admission.probe_code());
            Ok((vm, permit))
        }
```

In `record_vm_released` (trap.rs:4126-4132) the body currently reads:

```rust
fn record_vm_released() {
    crate::probes::vm_lifecycle(3, -1);
    if !atomic_permit_enabled() {
        return;
    }
    vm_residency_region().release_token(VM_RESIDENCY_LOCAL_KEY);
}
```

Replace with:

```rust
fn record_vm_released() {
    crate::probes::vm_lifecycle(3, -1);
    CARRIER_VM_LIVE.store(false, std::sync::atomic::Ordering::Release);
    if !atomic_permit_enabled() {
        return;
    }
    vm_residency_region().release_token(VM_RESIDENCY_LOCAL_KEY);
}
```

- [ ] **Step 4: Replace `destroy_persistent_vm_at_run_terminal` with the carrier-exit destroy**

Replace this existing function (trap.rs:4134-4147):

```rust
/// Explicitly retire the one persistent HVPatch VM after every guest vCPU has
/// left the threaded loop. The VM wrapper is `ManuallyDrop`, so relying on host
/// process death would leave no authoritative destroy-success boundary.
pub fn destroy_persistent_vm_at_run_terminal() -> Result<(), TrapError> {
    crate::probes::vm_lifecycle(2, -1);
    let rc = unsafe { inventory_hv_vm_destroy() };
    if rc != 0 {
        return Err(TrapError::Hypervisor(format!(
            "terminal hv_vm_destroy rc={rc:#x}"
        )));
    }
    record_vm_released();
    Ok(())
}
```

with:

```rust
/// Retire the one persistent HVPatch VM when the CARRIER exits — never at a
/// container's run terminal. Containers boot, run and retire inside this VM;
/// the VM wrapper is `ManuallyDrop`, so relying on host process death would
/// leave no authoritative destroy-success boundary for the lifecycle ledger.
///
/// Idempotent and honest about "nothing to do": a carrier that never created
/// a VM (image resolution failed, an entrypoint resolved to 127, or the second
/// call after a successful destroy) records no lifecycle event at all.
pub fn destroy_persistent_vm_at_carrier_exit() -> Result<(), TrapError> {
    if !carrier_vm_live() {
        return Ok(());
    }
    // Drop the carrier's control-mapping authority first: `PersistentCarrierMappings`'s
    // `Drop` unmaps the five fixed stage-2 extents, which must precede
    // `hv_vm_destroy`. This only releases the cell's `Arc`; every executor pool
    // holding another `Arc` must already have been shut down by its container's
    // run terminal (`pool_shutdown` in `run_threaded_loop_inner`) — a retained
    // `Arc` leaves the extents mapped until `hv_vm_destroy` tears them down.
    drop(persistent_carrier_cell().lock().take());
    crate::probes::vm_lifecycle(2, -1);
    let rc = unsafe { inventory_hv_vm_destroy() };
    if rc != 0 {
        return Err(TrapError::Hypervisor(format!(
            "carrier-exit hv_vm_destroy rc={rc:#x}"
        )));
    }
    record_vm_released();
    Ok(())
}
```

- [ ] **Step 5: Publish the carrier bundle from the first root bring-up; tolerate a reused root**

`take_persistent_executor_spec` (trap.rs:16611-16627) currently reads:

```rust
    pub(crate) fn take_persistent_executor_spec(
        &mut self,
    ) -> Result<PersistentExecutorSpec, TrapError> {
        if self.carrier_mappings.is_some() {
            return Err(TrapError::Hypervisor(
                "persistent executor carrier authority was already extracted".to_owned(),
            ));
        }
        let carrier_mappings =
            std::sync::Arc::new(PersistentCarrierMappings::extract(&mut self.mappings)?);
        Ok(PersistentExecutorSpec {
            vm: (*self._vm).clone(),
            carrier_mappings,
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
        })
    }
```

Replace with:

```rust
    pub(crate) fn take_persistent_executor_spec(
        &mut self,
    ) -> Result<PersistentExecutorSpec, TrapError> {
        if let Some(carrier_mappings) = self.carrier_mappings.as_ref() {
            // A later container's root was built INSIDE the carrier VM
            // (`new_with_plan` reuse lane) and already shares the carrier's
            // control-mapping authority: hand back the carrier's own bundle.
            // Any other holder (a worker) is still refused as before.
            let cell = persistent_carrier_cell().lock();
            return match cell.as_ref() {
                Some(spec)
                    if std::sync::Arc::ptr_eq(&spec.carrier_mappings, carrier_mappings) =>
                {
                    Ok(spec.clone())
                }
                _ => Err(TrapError::Hypervisor(
                    "persistent executor carrier authority was already extracted".to_owned(),
                )),
            };
        }
        let carrier_mappings =
            std::sync::Arc::new(PersistentCarrierMappings::extract(&mut self.mappings)?);
        let spec = PersistentExecutorSpec {
            vm: (*self._vm).clone(),
            carrier_mappings,
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
        };
        // First root of this carrier: publish the VM-global bundle for every
        // later container's root bring-up and wake any root parked on it. The
        // boot gate in `new_with_plan` guarantees only ONE first root exists,
        // so the cell is empty here; the guard is defensive.
        {
            let mut cell = persistent_carrier_cell().lock();
            if cell.is_none() {
                *cell = Some(spec.clone());
            }
        }
        carrier_published().notify_all();
        Ok(spec)
    }
```

- [ ] **Step 6: Teach `HvfVmState::new_with_plan` the reuse lane (boot a root inside the live carrier VM)**

The head of `new_with_plan` (trap.rs:11772-11786) currently reads:

```rust
    pub(crate) fn new_with_plan(
        plan: &GuestMappingPlan,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        use applevisor::prelude::*;

        let (vm, permit) = create_vm_with_admission(VmCreateAdmission::Initial)?;
        let vcpu = create_vcpu_with_permit(&vm, permit)?;
        enable_el0_counter_access(vcpu.id());

        let syscall_transport = HvfSyscallTransport::from_env()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            task: HvfTaskState {
```

Replace with:

```rust
    pub(crate) fn new_with_plan(
        plan: &GuestMappingPlan,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        use applevisor::prelude::*;

        // Carrier reuse: when this carrier already owns a VM, a new container's
        // root boots INSIDE it. Its image is placed the way `execve_rebuild`
        // places a replacement image (global-frame stage-2 leases + rebased
        // stage-1 tables), so two live roots never collide on identity IPAs,
        // and the five carrier control mappings are shared, not re-mapped.
        //
        // The boot gate is held across the first root's `hv_vm_create`, so two
        // roots racing here cannot both create (HV_BUSY for the loser); a root
        // that finds the VM live but the bundle not yet published waits for
        // the first root's `take_persistent_executor_spec`.
        let boot_gate = carrier_root_boot_gate().lock();
        let carrier: Option<PersistentExecutorSpec> = if carrier_vm_live() {
            let mut cell = persistent_carrier_cell().lock();
            while cell.is_none() {
                if carrier_published()
                    .wait_for(&mut cell, CARRIER_PUBLISH_WAIT)
                    .timed_out()
                {
                    return Err(TrapError::Hypervisor(
                        "carrier VM is live but its executor bundle was never published"
                            .to_owned(),
                    ));
                }
            }
            cell.clone()
        } else {
            None
        };
        let mut global_plan = match &carrier {
            Some(spec) => {
                spec.carrier_mappings.audit()?;
                audit_plan_against_installed_carrier(plan, &spec.carrier_mappings)?;
                Some(prepare_global_exec_plan(plan, None)?)
            }
            None => None,
        };
        let (vm, permit, syscall_transport, mailbox_slots, carrier_mappings) = match &carrier {
            Some(spec) => (
                // A VM rebuilt since publication supersedes the bundle's handle,
                // exactly as `from_persistent_executor_spec` reads it.
                rebuilt_vm_cell()
                    .lock()
                    .clone()
                    .unwrap_or_else(|| spec.vm.clone()),
                None,
                spec.syscall_transport,
                std::sync::Arc::clone(&spec.mailbox_slots),
                Some(std::sync::Arc::clone(&spec.carrier_mappings)),
            ),
            None => {
                let (vm, permit) = create_vm_with_admission(VmCreateAdmission::Initial)?;
                let syscall_transport = HvfSyscallTransport::from_env()
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
                (
                    vm,
                    permit,
                    syscall_transport,
                    std::sync::Arc::new(MailboxSlotAllocator::new()),
                    None,
                )
            }
        };
        drop(boot_gate);
        let vcpu = if carrier.is_some() {
            // Existing-VM vCPU: admitted by the in-process scheduler, like a
            // thread sibling (see `create_vcpu`).
            create_vcpu(&vm)?
        } else {
            create_vcpu_with_permit(&vm, permit)?
        };
        enable_el0_counter_access(vcpu.id());

        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            task: HvfTaskState {
```

The struct tail plus the identity mapping loop (trap.rs:11814-11836) currently reads:

```rust
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: std::sync::Arc::new(MailboxSlotAllocator::new()),
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
        };
        state.seed_readonly_spans_from_plan(plan);

        for mapping in &plan.mappings {
            #[cfg(feature = "trace-hvf")]
            eprintln!(
                "MAP guest_start=0x{:x} mapped_size=0x{:x} payload_size=0x{:x} perms=r{}w{}x{}",
                mapping.guest_start,
                mapping.mapped_size,
                mapping.payload_size,
                if mapping.perms.read { '+' } else { '-' },
                if mapping.perms.write { '+' } else { '-' },
                if mapping.perms.execute { '+' } else { '-' },
            );
            let region = map_region_raw(mapping, false)?;
            state.mappings.push(region);
        }
```

Replace with:

```rust
            carrier_mappings,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots,
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
        };
        state.seed_readonly_spans_from_plan(plan);

        // Reuse lane: map the relocated image with owning stage-2 leases (the
        // exec placement); first-boot lane: the identity `map_region_raw`
        // placement. `plan` is rebound so the register programming below reads
        // the relocated stage-1 table root (guest VAs are unchanged).
        let plan: &GuestMappingPlan = match global_plan.as_mut() {
            Some(GlobalExecPlan {
                plan: relocated,
                stage2_leases,
            }) => {
                for mapping in relocated.mappings.iter().filter(|mapping| {
                    !is_sparse_hvpatch_mmap_mapping(mapping)
                        && !is_persistent_executor_carrier_guest_mapping(mapping)
                }) {
                    let key = (mapping.ipa_start, mapping.mapped_size);
                    let mut lease = stage2_leases.remove(&key).ok_or_else(|| {
                        TrapError::Hypervisor(format!(
                            "carrier root mapping IPA 0x{:x} size {} has no owning lease",
                            key.0, key.1
                        ))
                    })?;
                    let mut region = prepare_exec_region_raw(mapping)?;
                    let install = exec_stage2_install(mapping, &region);
                    let rc = unsafe {
                        inventory_hv_vm_map(
                            install.host.cast(),
                            install.ipa,
                            install.size,
                            install.perms,
                        )
                    };
                    if rc != 0 {
                        return Err(TrapError::Hypervisor(format!(
                            "map carrier root IPA 0x{:x} size {} failed: 0x{rc:x}",
                            install.ipa, install.size
                        )));
                    }
                    lease.mark_mapped();
                    region.stage2_lease = Some(lease);
                    state.mappings.push(region);
                }
                if !stage2_leases.is_empty() {
                    return Err(TrapError::Hypervisor(format!(
                        "carrier root left {} reserved stage-2 leases unmaterialized",
                        stage2_leases.len()
                    )));
                }
                relocated
            }
            None => {
                for mapping in &plan.mappings {
                    #[cfg(feature = "trace-hvf")]
                    eprintln!(
                        "MAP guest_start=0x{:x} mapped_size=0x{:x} payload_size=0x{:x} perms=r{}w{}x{}",
                        mapping.guest_start,
                        mapping.mapped_size,
                        mapping.payload_size,
                        if mapping.perms.read { '+' } else { '-' },
                        if mapping.perms.write { '+' } else { '-' },
                        if mapping.perms.execute { '+' } else { '-' },
                    );
                    let region = map_region_raw(mapping, false)?;
                    state.mappings.push(region);
                }
                plan
            }
        };
```

The mailbox tail (trap.rs:11985-11987) currently reads:

```rust
        state.populate_vdso_data_page();
        let mailbox = state.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((state, vcpu, mailbox))
```

Replace with:

```rust
        state.populate_vdso_data_page();
        let mailbox = match &carrier {
            // Shared arena, shared allocator: the slot is unique across every
            // container's vCPUs in this VM.
            Some(spec) => Self::allocate_persistent_mailbox_for_vcpu(spec, &vcpu)?,
            None => state.allocate_mailbox_for_vcpu(&vcpu)?,
        };
        Ok((state, vcpu, mailbox))
```

- [ ] **Step 7: Add the carrier-vs-plan audit (fail closed on a different control image)**

Directly before `fn is_persistent_executor_carrier_mapping` (its `#[cfg]` attribute is at trap.rs:6661) add:

```rust
/// A root booting inside a live carrier must carry the SAME control image the
/// carrier installed: identical geometry for all five fixed mappings, and
/// identical bytes for the three code pages (EL0 trampoline, EL1 vectors, EL1
/// maintenance). The mailbox arena and the carrier maintenance root are live
/// data, so only their geometry is compared. Divergence is a build/config
/// error, never something to paper over by remapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn audit_plan_against_installed_carrier(
    plan: &GuestMappingPlan,
    carrier: &PersistentCarrierMappings,
) -> Result<(), TrapError> {
    let code_pages = [
        carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
        carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
        carrick_mem::memory::LINUX_EL1_MAINT_BASE,
    ];
    let mut seen = 0_usize;
    for mapping in plan
        .mappings
        .iter()
        .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
    {
        seen += 1;
        let installed = carrier
            .mappings
            .iter()
            .find(|installed| installed.start == mapping.guest_start)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "carrier has no control mapping at 0x{:x}",
                    mapping.guest_start
                ))
            })?;
        if installed.end.saturating_sub(installed.start) != mapping.mapped_size {
            return Err(TrapError::Hypervisor(format!(
                "carrier control mapping 0x{:x} size {} differs from plan size {}",
                mapping.guest_start,
                installed.end.saturating_sub(installed.start),
                mapping.mapped_size
            )));
        }
        if code_pages.contains(&mapping.guest_start) {
            let payload = usize::try_from(mapping.payload_size)
                .map_err(|_| TrapError::MappingTooLarge(mapping.payload_size))?;
            let offset = usize::try_from(mapping.offset_in_mapping)
                .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
            let planned = mapping
                .image
                .get(offset..offset + payload)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "carrier control image at 0x{:x} is shorter than its payload",
                        mapping.guest_start
                    ))
                })?;
            let live = carrier
                .host_pointer(mapping.guest_start + mapping.offset_in_mapping, payload)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "carrier control mapping 0x{:x} payload is not host-visible",
                        mapping.guest_start
                    ))
                })?;
            // SAFETY: `host_pointer` proved `[ptr, ptr+payload)` lies inside one
            // live carrier mapping; the code pages are immutable after install.
            let live = unsafe { std::slice::from_raw_parts(live.as_ptr(), payload) };
            if live != planned {
                return Err(TrapError::Hypervisor(format!(
                    "carrier control code at 0x{:x} differs from this image's bytes",
                    mapping.guest_start
                )));
            }
        }
    }
    if seen != 5 {
        return Err(TrapError::Hypervisor(format!(
            "root image carries {seen} carrier control mappings, expected 5"
        )));
    }
    Ok(())
}
```

(`GuestMapping::image` and `HvfMappedRegion::{start, end}` are private fields, readable here because the audit lives in `trap.rs`.)

- [ ] **Step 8: Run the HVF unit tests (green, and the raw-call inventory gate still holds)**

Run: `cargo test -p carrick-vmm-hvf --lib -- carrier_exit_without_a_vm_is_a_recorded_no_op raw_hvf_stage2_calls_are_inventory_gated`
Expected: `test result: ok. 2 passed` — the reuse lane calls only `inventory_hv_vm_map`, so the `applevisor_sys::hv_vm_map(` count stays 1.

- [ ] **Step 9: Write the failing runtime test (red: `crate::carrier` does not exist)**

In `crates/carrick-runtime/src/execute.rs:892-901` the test currently reads:

```rust
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvpatch_uses_container_entrypoint_resolution() {
        let result = Runtime::execute(&hvpatch_run_spec())
            .expect("hvpatch container setup should classify a missing entrypoint");

        assert_eq!(result.exit_code, 127);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
```

Replace with:

```rust
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvpatch_uses_container_entrypoint_resolution_for_every_container_in_one_carrier() {
        // Two sequential containers in ONE carrier process: each resolves its
        // entrypoint independently (127 both times) and leaves no live
        // container behind, and carrier shutdown afterwards is a no-op. A 127
        // run never boots a VM (it fails in `run_elf_from_dispatcher_debug`,
        // before `run_address_space_with_hvf_and_dispatcher`), so this proves
        // the carrier module's idempotency without HVF; the live two-container
        // proof is Gate B (`conformance_container_gate`, Task 17).
        for round in 0..2 {
            let result = Runtime::execute(&hvpatch_run_spec())
                .expect("hvpatch container setup should classify a missing entrypoint");
            assert_eq!(result.exit_code, 127, "round {round}");
            assert!(result.stdout.is_empty());
            assert!(result.stderr.is_empty());
            assert_eq!(
                crate::carrier::live_container_count(),
                0,
                "round {round}: container must be retired at run end"
            );
        }
        crate::carrier::shutdown().expect("carrier shutdown without a VM is a no-op");
        assert!(crate::vm_lifecycle::process_snapshot().terminal.is_none());
    }
```

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib hvpatch_uses_container_entrypoint_resolution`
Expected: compile error `E0433: failed to resolve: could not find `carrier` in the crate root` — red.

- [ ] **Step 10: Create `crates/carrick-runtime/src/carrier.rs`**

```rust
//! Carrier-lifetime infrastructure.
//!
//! A carrier is ONE host process hosting ONE HVF VM, ONE `KernelArena`, and any
//! number of containers — sequentially or at once. Everything in the table is
//! installed once per carrier, is idempotent on re-entry, and is torn down only
//! by [`shutdown`], never by a container's run terminal. None of it may alias a
//! container: every `KernelContext` reaches its container through its task,
//! not through one of these statics.
//!
//! | Facility | Install site | Re-entry | Torn down by |
//! |---|---|---|---|
//! | HVF VM, five control mappings, mailbox allocator | first `HvfVmState::new_with_plan` (`carrick-vmm-hvf::trap::persistent_carrier_cell`) | later roots boot inside it | [`shutdown`] → `destroy_persistent_vm_at_carrier_exit` |
//! | `KernelArena` (pid regions live inside it, per container) | `KernelArena::init_global` (`OnceLock`, carrick-kernel/src/arena.rs) | first wins | process exit |
//! | Host signal dispositions: SIGINT, xsig nudge, pending self-pipe, xsig ring, FASYNC table | `host_signal::install_default_handlers` (`INSTALLED` CAS guard) | guarded | process exit |
//! | Signal-pump dispositions (`PUMP_SIGNALS`, SIGCHLD) | `signal_pump::install_handlers` / `install_sigchld_handler` (`SIGCHLD_INSTALLED`) | re-install is a no-op by effect | process exit |
//! | SIGWINCH self-pipe (`pty_relay::WINCH_PIPE_WRITE`) | `PtyRelay::start_with_pair_and_winsize` (tty runs only) | one relay at a time; endpoints stay open for the process lifetime by design | relay drop restores the disposition |
//! | Deadlock watchdog thread | `deadlock_watchdog::arm` (`ARMED` swap) | guarded | process exit |
//! | vCPU admission scheduler | `vcpu_sched::install_for_budget` (`OnceLock`) | first wins | process exit |
//! | `TimerDelivery` handle | `timer_delivery::register_delivery` (`OnceLock`; `HvfTimerDelivery` is a unit struct) | first wins | process exit |
//! | `RLIMIT_NOFILE` soft raise | `carrick-cli/main.rs` at startup; `dispatch/time.rs::raise_host_nofile_backing` | only ever raises | process exit |
//! | VM lifecycle ledger terminal + artifact | [`shutdown`] | single terminal per carrier | — |
//!
//! Per-container state (pid namespace root and region, rootfs + mount table,
//! UTS hostname, netns membership, clock domain, granted caps, executor pool,
//! kernel process tree) is owned by `crate::kernel::container::Container` and
//! retired by [`retire_container`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::container::{Container, ContainerId};
use crate::run_result::RuntimeError;
use crate::vm_lifecycle::VmRunTerminalOutcome;

static LIVE_CONTAINERS: AtomicUsize = AtomicUsize::new(0);
static LAST_CONTAINER_TERMINAL: parking_lot::Mutex<Option<VmRunTerminalOutcome>> =
    parking_lot::Mutex::new(None);
static SHUTDOWN_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Number of containers currently booted in this carrier.
pub fn live_container_count() -> usize {
    LIVE_CONTAINERS.load(Ordering::Acquire)
}

/// RAII admission of one container into the carrier census. Dropped by
/// [`retire_container`] (or by unwinding, so a failed boot never leaks a seat).
#[must_use = "dropping the admission immediately un-counts the container"]
pub(crate) struct ContainerAdmission {
    id: ContainerId,
}

pub(crate) fn admit_container(id: ContainerId) -> ContainerAdmission {
    LIVE_CONTAINERS.fetch_add(1, Ordering::AcqRel);
    ContainerAdmission { id }
}

impl ContainerAdmission {
    pub(crate) fn id(&self) -> ContainerId {
        self.id
    }
}

impl Drop for ContainerAdmission {
    fn drop(&mut self) {
        LIVE_CONTAINERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Receipt of one container's teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerTeardown {
    pub id: ContainerId,
    pub tasks_reaped: usize,
    pub mounts_dropped: usize,
    pub pid_region_released: bool,
}

/// Retire a container whose run loop has returned: reap every remaining task
/// of its process tree, drop its mount table, release its pid region. The VM
/// and the arena stay for the next container.
pub(crate) fn retire_container(
    container: Arc<Container>,
    admission: ContainerAdmission,
) -> Result<ContainerTeardown, RuntimeError> {
    debug_assert_eq!(container.id(), admission.id());
    let receipt = container.retire()?;
    drop(admission);
    Ok(receipt)
}

/// Remember the most recent container's terminal outcome for the carrier
/// ledger. The lifecycle ledger accepts ONE run terminal per carrier, so it is
/// written at [`shutdown`], not per container.
pub(crate) fn record_container_terminal(outcome: VmRunTerminalOutcome) {
    *LAST_CONTAINER_TERMINAL.lock() = Some(outcome);
}

#[cfg(feature = "platform-macos")]
fn destroy_vm() -> Result<(), RuntimeError> {
    crate::trap::destroy_persistent_vm_at_carrier_exit().map_err(RuntimeError::from)
}

#[cfg(not(feature = "platform-macos"))]
fn destroy_vm() -> Result<(), RuntimeError> {
    Ok(())
}

/// Whether this carrier ever ATTEMPTED a VM create. A failed create still
/// leaves a `LogicalCreateAttempt` in the ledger, and such a carrier records a
/// `RuntimeError` terminal (the shape `setup_failure_has_one_vm_teardown_and_
/// runtime_error_artifact` pins for the helper).
#[cfg(feature = "platform-macos")]
fn ledger_has_events() -> bool {
    !crate::vm_lifecycle::process_snapshot().events.is_empty()
}

#[cfg(not(feature = "platform-macos"))]
fn ledger_has_events() -> bool {
    false
}

/// Tear the carrier down: destroy the persistent VM, record the ledger
/// terminal (the last container's outcome, or `RuntimeError` if a VM create
/// was attempted but no container completed), and publish the lifecycle
/// artifact when `CARRICK_HVPATCH_VM_LEDGER_PATH` names one. Idempotent; a
/// carrier whose ledger is empty records nothing.
pub fn shutdown() -> Result<(), RuntimeError> {
    if SHUTDOWN_DONE.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    if live_container_count() != 0 {
        return Err(RuntimeError::Configuration(format!(
            "carrier shutdown with {} live container(s)",
            live_container_count()
        )));
    }
    let attempted = ledger_has_events();
    destroy_vm()?;
    if !attempted {
        return Ok(());
    }
    let terminal = LAST_CONTAINER_TERMINAL
        .lock()
        .take()
        .unwrap_or(VmRunTerminalOutcome::RuntimeError);
    crate::vm_lifecycle::record_process_terminal(terminal);
    if let Some(path) = std::env::var_os(crate::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_PATH_ENV) {
        crate::vm_lifecycle::write_completed_process_artifact(std::path::Path::new(&path))
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "HVPatch VM lifecycle artifact publication failed at carrier exit: {error}"
                ))
            })?;
    }
    Ok(())
}

/// The CLI's one exit funnel: shut the carrier down, then exit with `status`.
/// A shutdown failure is reported on stderr and turns a successful status into
/// 125 (infrastructure failure), never the other way round.
pub fn exit_carrier(status: i32) -> ! {
    let status = match shutdown() {
        Ok(()) => status,
        Err(error) => {
            eprintln!("carrick: carrier shutdown failed: {error:#}");
            if status == 0 { 125 } else { status }
        }
    };
    std::process::exit(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_without_a_booted_container_records_no_terminal() {
        assert_eq!(live_container_count(), 0);
        shutdown().expect("shutdown without a VM is a no-op");
        assert!(crate::vm_lifecycle::process_snapshot().terminal.is_none());
        // Idempotent.
        shutdown().expect("second shutdown is a no-op");
    }
}
```

(`write_completed_process_artifact(&Path) -> Result<VmLifecycleArtifactSummary, VmLifecycleArtifactError>` is the same function runtime.rs:654-655 calls today; keep its signature. If B1–B3 made `ContainerId` non-`Copy`, change `id()` to return a clone and drop the `Copy` derive on `ContainerTeardown`. The `eprintln!` in `exit_carrier` is operator-facing CLI output, the same class as `record_vm_resident`'s admission message in trap.rs:4117; if `just lint-domains` flags it, move the message to the CLI callers and have `exit_carrier` return the status instead.)

- [ ] **Step 11: Declare the module**

In `crates/carrick-runtime/src/lib.rs` the lines 316-317 read:

```rust
pub mod threaded_loop;
pub mod vcpu_loop;
```

Replace with:

```rust
pub mod carrier;
pub mod threaded_loop;
pub mod vcpu_loop;
```

- [ ] **Step 12: Append `Container::retire` to `crates/carrick-runtime/src/kernel/container.rs`**

This file is created by Tasks 1–15 (B1–B3). Append (field names follow the shared contract comment — `pid_root`, `mounts`; substitute B1–B3's real names and record the substitution):

```rust
impl Container {
    /// Retire this container after its run loop returned. Precondition: the
    /// run loop joined every executor of this container (`join_hvpatch_process_threads`
    /// + `take_process_terminal` in `threaded_loop::run_threaded_loop_inner`),
    /// so no task of this pid namespace can still be running. Reaps whatever
    /// the tree still holds (zombies an init never waited for), drops the
    /// mount table, and releases the pid region back to the carrier arena.
    /// Fails closed — never silently skips — if a live task is still keyed to
    /// this container.
    pub(crate) fn retire(self: std::sync::Arc<Self>) -> Result<crate::carrier::ContainerTeardown, crate::run_result::RuntimeError> {
        let id = self.id();
        let live = self.pid_root.live_task_count();
        if live != 0 {
            return Err(crate::run_result::RuntimeError::Configuration(format!(
                "container {id:?} retired with {live} live task(s)"
            )));
        }
        let tasks_reaped = self.pid_root.reap_remaining();
        let mounts_dropped = self.mounts.write().clear_all();
        let pid_region_released = self.pid_root.release_region();
        Ok(crate::carrier::ContainerTeardown {
            id,
            tasks_reaped,
            mounts_dropped,
            pid_region_released,
        })
    }
}
```

`pid_root.live_task_count()`, `pid_root.reap_remaining() -> usize`, `pid_root.release_region() -> bool` and `VfsMounts::clear_all() -> usize` are the per-container primitives B1–B3 own (the contract's "pid_root" replaces `namespace::pid::REGION`); if B1–B3 exposed them under other names, call those and record the substitution in the commit body. Add `VfsMounts::clear_all` in `crates/carrick-runtime/src/vfs/` if B1–B3 did not (it drains the longest-prefix table and returns the count). `{id:?}` needs `ContainerId: Debug`.

- [ ] **Step 13: Retire the container — not the VM — at run end in `runtime.rs`**

`run_address_space_with_hvf_and_dispatcher` (runtime.rs:610-620) currently begins:

```rust
fn run_address_space_with_hvf_and_dispatcher(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let _ = crate::ulock::preinit_waiter_table();
    ensure_kernel_arena_path_env()?;
    // The carrier owns the kernel arena and PID-namespace placement directly.
    // Guest fork/clone creates logical Carrick-kernel tasks, never a host
    // namespace-supervisor process.
    let _ = carrick_kernel::arena::KernelArena::init_global();
```

Replace with:

```rust
fn run_address_space_with_hvf_and_dispatcher(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let _ = crate::ulock::preinit_waiter_table();
    ensure_kernel_arena_path_env()?;
    // The carrier owns the kernel arena; this container owns its pid region
    // inside it. Guest fork/clone creates logical Carrick-kernel tasks, never a
    // host namespace-supervisor process.
    let _ = carrick_kernel::arena::KernelArena::init_global();
    let container = dispatcher.container();
    let admission = crate::carrier::admit_container(container.id());
    // Taken by the run terminal (inside `finalize_persistent_hvf_run`), or by
    // the boot-failure path below when the loop never ran.
    let mut retire = Some((container, admission));
```

and the finalize call (runtime.rs:647-661) currently reads:

```rust
        let mut run = finalize_persistent_hvf_run(
            completion.run,
            || crate::trap::destroy_persistent_vm_at_run_terminal().map_err(RuntimeError::from),
            crate::vm_lifecycle::record_process_terminal,
            |run| {
                if let Some(path) =
                    std::env::var_os(crate::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_PATH_ENV)
                    && let Err(artifact_error) =
                        crate::vm_lifecycle::write_completed_process_artifact(Path::new(&path))
                {
                    let run_context = run
                        .as_ref()
                        .err()
                        .map_or_else(|| "guest run completed".to_owned(), ToString::to_string);
                    return Err(RuntimeError::Unsupported(format!(
                        "HVPatch VM lifecycle artifact publication failed after {run_context}: {artifact_error}"
                    )));
                }
                Ok(())
            },
        );
```

Replace with:

```rust
        // Container teardown: reap, drop mounts, release the pid region. The
        // VM, the arena and every other carrier facility persist for the next
        // container; `carrier::shutdown` retires them at carrier exit.
        let mut run = finalize_persistent_hvf_run(
            completion.run,
            || {
                let (container, admission) = retire.take().ok_or_else(|| {
                    RuntimeError::Configuration("container retired twice".to_owned())
                })?;
                crate::carrier::retire_container(container, admission).map(|_| ())
            },
            crate::carrier::record_container_terminal,
            |_| Ok(()),
        );
```

The closure ends at runtime.rs:683 with `})();`; change the binding from `let run = (|| -> Result<RunResult, RuntimeError> {` (runtime.rs:626) to `let mut run = …` and insert directly after `})();`:

```rust
    // Boot failed before the loop (file authority, VM/root bring-up, boot
    // identity): `finalize_persistent_hvf_run` never ran, so the container is
    // still admitted. Retire it here; the admission's RAII drop alone would
    // un-count it but leave its tasks/mounts/pid region behind.
    if let Some((container, admission)) = retire.take()
        && let Err(error) = crate::carrier::retire_container(container, admission)
        && run.is_ok()
    {
        run = Err(error);
    }
```

`finalize_persistent_hvf_run` itself (runtime.rs:581-608) is unchanged — its closure contract still reads "retire → record → publish", and its unit test `setup_failure_has_one_vm_teardown_and_runtime_error_artifact` (runtime.rs:2428, which uses a LOCAL ledger) keeps passing. Rename its first parameter from `destroy_vm` to `retire` and reword its doc so the name no longer lies. Remove the now-unused `use std::path::Path` only if the compiler flags it.

- [ ] **Step 14: Run the runtime tests (green)**

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib -- hvpatch_uses_container_entrypoint_resolution carrier::tests`
Expected: `test result: ok. 2 passed` (both rounds return 127; live count is 0 after each; shutdown is a no-op with an empty ledger).

- [ ] **Step 15: Route every CLI exit through `carrier::exit_carrier`**

`crates/carrick-cli/src/commands.rs:1010-1032` currently reads:

```rust
            let spec = match block_on_oci(engine.resolve(req.clone())) {
                Ok(s) => s,
                // resolve runs in the PARENT (no fork yet) → normal exit is safe.
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    std::process::exit(125);
                }
            };
            let result = match carrick_runtime::Runtime::execute(&spec) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    if tty {
                        // The separately-scoped interactive TTY supervisor may
                        // put this error arm in its forked runtime child. Do not
                        // unwind fd-owning state there.
                        // SAFETY: `_exit` skips atexit/Drop; stderr is unbuffered.
                        unsafe { libc::_exit(125) };
                    }
                    // Ordinary/raw HVPatch execution is the original carrier,
                    // so normal process cleanup and terminal receipts are safe.
                    std::process::exit(125);
                }
            };
```

Replace with:

```rust
            let spec = match block_on_oci(engine.resolve(req.clone())) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    carrick_runtime::carrier::exit_carrier(125);
                }
            };
            let result = match carrick_runtime::Runtime::execute(&spec) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    // The interactive PTY relay is a thread of this carrier
                    // (no host fork survives), so the carrier exit funnel is
                    // the right teardown on every lane.
                    carrick_runtime::carrier::exit_carrier(125);
                }
            };
```

(If Phase A already rewrote the tty comment, apply only the `exit_carrier` substitution; also drop the "Fork-safety on the engine error path" paragraph at commands.rs:46-52 if it is still there, since the `_exit` arm it explains is gone.) Then replace the three `std::process::exit(status);` at commands.rs:1058, :1080 and :1095 (the `tty || interactive`, `--json`, and raw tails of the `Run` arm) with `carrick_runtime::carrier::exit_carrier(status);`.

`crates/carrick-cli/src/lifecycle.rs:601-607` currently reads:

```rust
    match carrick_runtime::Runtime::execute(&spec) {
        Ok(r) => std::process::exit(r.exit_code),
        Err(_) => {
            container::mark_exited(id, 1);
            std::process::exit(1);
        }
    }
```

Replace with:

```rust
    match carrick_runtime::Runtime::execute(&spec) {
        Ok(r) => carrick_runtime::carrier::exit_carrier(r.exit_code),
        Err(_) => {
            container::mark_exited(id, 1);
            carrick_runtime::carrier::exit_carrier(1);
        }
    }
```

- [ ] **Step 16: Rewrite the process-model prose and the stale doc symbol**

`crates/carrick-cli/src/main.rs:65-72` currently reads:

```rust
//! ## Process model: one container == one host carrier
//!
//! HVPatch keeps every logical Linux process, thread, wait edge and signal in
//! the Carrick kernel graph inside one carrier. Guest `fork`/`clone` and Docker
//! exec do not create host subprocesses. Detached launch has one typed
//! `posix_spawn` carrier-birth boundary; the Docker API server remains an
//! operator process and launches exactly one carrier per running container.
//! The loud [`install_guest_abort_banner`] panic hook attributes failures in
```

Replace the first seven of those lines (keep the `install_guest_abort_banner` sentence that follows) with:

```rust
//! ## Process model: one carrier hosts many containers
//!
//! HVPatch keeps every logical Linux process, thread, wait edge and signal in
//! the Carrick kernel graph inside one carrier, which owns ONE HVF VM and ONE
//! kernel arena for its whole life (`carrick_runtime::carrier`). Containers are
//! namespace trees on that graph: the CLI boots one per `carrick run`, and
//! `carrick debug container-gate` (Gate B) boots two — in sequence or at once
//! — in the same carrier, the shape the Phase C embed library generalises.
//! Guest `fork`/`clone` and Docker exec do not create host subprocesses.
//! Detached launch has one typed `posix_spawn` carrier-birth boundary; the
//! Docker API server remains an operator process and launches one carrier per
//! running container. Every exit goes through `carrier::exit_carrier`, which
//! retires the VM and publishes the lifecycle ledger.
```

In `docs/hvpatch-carrier-only-process-plan.md:78` replace `destroy_persistent_vm_at_run_terminal()` with `destroy_persistent_vm_at_carrier_exit()` and `runtime.rs:767` with `carrier.rs::shutdown`.

- [ ] **Step 17: Grep gate — the run-terminal destroy is gone everywhere**

Run: `grep -rn 'destroy_persistent_vm_at_run_terminal' crates docs scripts; echo "exit=$?"`
Expected: no lines, `exit=1`.

Run: `grep -n 'std::process::exit(' crates/carrick-cli/src/commands.rs`
Expected: no hit between lines 1004 and 1100 (the `Run` arm); other subcommands untouched.

- [ ] **Step 18: Format, lint, host gates**

Run: `just fmt && just clippy && just lint-domains`
Expected: each exits 0 (the carrier-only process invariant, `scripts/migrate/check-carrier-only-process-invariant.py`, keys on `fork`/`vfork`/`posix_spawn`/`forkpty`/`kill`/`pthread_kill`/`Command` births under `crates/`; this task adds none).

Run: `just test`
Expected: `test result: ok` for every crate; the serial `carrick-runtime` process includes the two new tests.

- [ ] **Step 19: Live verification on the signed artifact (HVF; requires the signed recipe)**

Run: `just build && CARRICK_RUN_ID=b4-t16 ./target/release/carrick run docker.io/library/ubuntu:24.04 /bin/sh -c 'echo ok; exit 3'; echo "exit=$?"`
Expected: `ok` then `exit=3` — the CLI path still boots, streams, retires the container, destroys the VM at `exit_carrier`, and propagates the guest status.

Run: `strings target/release/carrick | grep -c 'carrier-exit hv_vm_destroy'`
Expected: `1` or more (the new code's error string is in the binary you ran; a stale binary prints `0`; release builds keep full DWARF per `[profile.release]`, so `grep -c destroy_persistent_vm_at_carrier_exit` works too).

Run: `sudo -n scripts/sudo/kill.sh b4-t16`
Expected: nothing left to reap.

- [ ] **Step 20: Commit**

```bash
git add crates/carrick-runtime/src/carrier.rs crates/carrick-runtime/src/lib.rs \
  crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/execute.rs \
  crates/carrick-runtime/src/kernel/container.rs crates/carrick-vmm-hvf/src/trap.rs \
  crates/carrick-cli/src/commands.rs crates/carrick-cli/src/lifecycle.rs \
  crates/carrick-cli/src/main.rs docs/hvpatch-carrier-only-process-plan.md
git commit -F- <<'EOF'
feat(runtime): retire containers at run end, keep the HVF VM for the carrier

Why: a carrier could only ever host one container. The run terminal called
`destroy_persistent_vm_at_run_terminal` (hv_vm_destroy) and recorded the
process ledger terminal, so a second `Runtime::execute` in the same process
found no VM bundle to reuse and `hv_vm_create` answered HV_BUSY for a
concurrent one; the pid region, mounts and process tree of the first run
were never retired either. Phase B of the embed program makes containers
namespace trees on one kernel graph, which needs the VM, the arena and the
host-side installs (signal dispositions, SIGWINCH pipe, deadlock watchdog,
vCPU scheduler, TimerDelivery, RLIMIT_NOFILE) to be explicitly carrier-
lifetime and the container to be the thing that is torn down.

What:
- `carrick-vmm-hvf`: `persistent_carrier_cell` publishes the first root's
  `PersistentExecutorSpec` (VM + five control mappings + mailbox allocator);
  `HvfVmState::new_with_plan` boots a later root INSIDE that VM through the
  exec placement lane (`prepare_global_exec_plan` + owning stage-2 leases)
  after auditing the image's control pages against the installed carrier,
  serialized by a root boot gate so concurrent first roots never both reach
  `hv_vm_create`; `destroy_persistent_vm_at_carrier_exit` replaces the
  run-terminal destroy and is a recorded no-op when no VM is live.
- `carrick-runtime::carrier`: the carrier-lifetime table, container
  admission census, `retire_container` (reap, drop mounts, release region —
  also on boot failure before the loop), `shutdown` (VM destroy + single
  ledger terminal + artifact) and `exit_carrier`, the CLI's one exit funnel.
- `Container::retire` on the kernel-graph container object.
Deliberate divergence: the lifecycle ledger records ONE terminal per carrier
(the last container's outcome), not one per container.

Verified: red-first `carrier_exit_without_a_vm_is_a_recorded_no_op`
(vmm-hvf) and the two-round in-process
`hvpatch_uses_container_entrypoint_resolution_for_every_container_in_one_carrier`
(runtime, no HVF); `just test`, `just clippy`, `just lint-domains` green;
signed `carrick run ubuntu:24.04 sh -c 'echo ok; exit 3'` prints ok and
exits 3 on the rebuilt artifact.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 23: Gate B — the `container_gate` probe, `carrick debug container-gate`, and the dedicated conformance runner

**Files:**
- Create: `conformance-probes/src/bin/container_gate.rs`
- Modify: `conformance-probes/probe-inventory.json` (insert one row after `"connrefused"`, lines 232-236)
- Modify: `scripts/conformance/closure-probe-scenarios.py:18-19`
- Modify: `crates/carrick-cli/tests/conformance.rs:3249-3251` (denominator doc + `PROBE_SOURCE_COUNT`), `:3256-3313` (`DEDICATED_PROBE_RUNNERS`), `:4996-5002` (`closure_probe_inventory_enforces_authoritative_runners_and_denominator`), plus a new `#[test] fn conformance_container_gate` placed after `conformance_native_host_gateway` (ends line 1905)
- Modify: `crates/carrick-cli/src/args.rs:1181-1196` (new `DebugCommand::ContainerGate` + `ContainerGateMode`)
- Modify: `crates/carrick-cli/src/debug.rs:38` (`run_debug` gains the store) and its match tail (`:223-231`), new `fn run_container_gate`
- Modify: `crates/carrick-cli/src/commands.rs:1335` (`run_debug(command)?` → `run_debug(command, store.clone())?`)
- Modify: `justfile:349-363` (new `gate-containers` recipe after `conformance-probes-closure`)
- Test: `conformance_container_gate` (signed binary + built probe; HVF guest), `closure_probe_inventory_enforces_authoritative_runners_and_denominator` (no HVF)

**Interfaces:**
- Consumes: Task 16's `carrick_runtime::carrier::{shutdown, live_container_count}`, `carrick_runtime::vm_lifecycle::{process_snapshot, VmLifecycleOperation}`; `carrick_engine::{Engine, CliRunRequest, Mount}` (`Mount` is re-exported from carrick-spec at engine lib.rs:84-88; Phase C renames `CliRunRequest` → `RunRequest`; this task uses the name that exists now, `crates/carrick-engine/src/lib.rs:98`); `crate::runtime_util::block_on_oci` (runtime_util.rs:229); `carrick_runtime::Runtime::execute`; `carrick_runtime::runtime::{RunResult, RuntimeError, DEFAULT_MAX_TRAPS}`; `carrick_runtime::memory::init_alias_ipa_allocator` and `carrick_runtime::fs_resolve_cache::init` (the CLI's pre-run setup at commands.rs:952-961); conformance.rs helpers `CONFORMANCE_LOCK` (:32), `carrick_bin` (:353), `ensure_signed` (:2540), `probes_dir` (:3206), `selected_dedicated_probe_target` (:2382), `dedicated_closure_mode` (:2354), `lane_runnable_here` (:2388), `run_carrick_probe_process` (:3754, stamps `CARRICK_RUN_ID=cr-gate-<pid>-<seq>` and scopes cleanup per case), `format_exit_status` (:3539), `ARM64` (:206).
- Produces:
  - probe binary `container_gate` (musl + gnu sets), invocation `container_gate <alpha|beta> <solo|paired>`, report lines `role=`, `getpid=`, `hostname=`, `own_marker_written=`, `foreign_marker_visible=`, `child_comm_visible=`, `foreign_proc_visible=`, `peer_ready=`; exit 7 (alpha) / 9 (beta)
  - `carrick debug container-gate --image <ref> --probe <path> --gate-dir <dir> --mode sequential|concurrent --output <json>` (`pub(crate) enum ContainerGateMode { Sequential, Concurrent }`)
  - `#[test] fn conformance_container_gate()` — dedicated runner registered in `DEDICATED_PROBE_RUNNERS` and `probe-inventory.json`
  - `just gate-containers`

Vehicle decision (the brief asked for it): the guest-running part lives in the **signed `carrick` binary** as a `carrick debug` subcommand — the only executable that carries the hypervisor entitlement today (survey: nothing signs `target/debug/deps/*`; the Phase C `just test-embed` signing recipe does not exist yet). The Rust harness is a **dedicated conformance runner** in `crates/carrick-cli/tests/conformance.rs`, the mechanism the tree already uses for topology-specific probes (`DEDICATED_PROBE_RUNNERS`, `closure-probe-scenarios.py`): it shells out to `target/release/carrick`, `ensure_signed`s it, and asserts on a JSON receipt plus the per-container report files. In closure mode (`CARRICK_PROBE_MODE=closure`, what `just conformance-probes-closure` and the new `just gate-containers` set) every missing prerequisite is a panic, never a skip.

- [ ] **Step 1: Register the probe first (red: inventory names a source that does not exist)**

Insert into `conformance-probes/probe-inventory.json` after the `"connrefused"` row (lines 232-236; the file is alphabetical and `container_gate` sorts between `connrefused` and `coredumpbit`):

```json
  "container_gate": {
    "class": "conformance",
    "excluded": false,
    "runner": "conformance_container_gate"
  },
```

Run: `python3 scripts/probe-inventory.py check; echo "exit=$?"`
Expected: `probe source inventory drift (missing=[], absent_from_disk=['container_gate'])`, `exit=1` — red.

- [ ] **Step 2: Write the probe `conformance-probes/src/bin/container_gate.rs`**

```rust
//! container_gate: Gate B reducer for "many containers in one carrier".
//!
//! Run DIRECTLY as the container command (it must be ns-pid 1), once per
//! container, with one host directory bind-mounted at `/gate` in BOTH:
//!
//!     /tmp/p <role: alpha|beta> <mode: solo|paired>
//!
//! INVARIANTS (one `key=value` line each, to stdout AND `/gate/<role>.report`):
//!   getpid=1                   — this container's init is pid 1 of its own ns
//!   hostname=<uname nodename>  — the harness sets a distinct one per container
//!   own_marker_written=true    — `/etc/carrick-gate-<role>` written into THIS rootfs
//!   foreign_marker_visible=false — the peer's marker is not in this rootfs
//!   child_comm_visible=true    — a forked child renamed `gate-<role>` shows in /proc
//!   foreign_proc_visible=false — no `gate-<peer>` task is visible in this /proc
//!   peer_ready=true            — (paired) the peer was alive when /proc was scanned
//! `paired` rendezvous through `/gate/<role>.ready` / `.scanned` so both
//! containers scan `/proc` while the other's child is alive. Exits 7 (alpha)
//! or 9 (beta) so the harness can prove independent exit statuses.
use conformance_probes::reap;
use std::io::Write;

const READY_TIMEOUT_MS: u64 = 60_000;

fn role_code(role: &str) -> i32 {
    match role {
        "alpha" => 7,
        "beta" => 9,
        _ => 3,
    }
}

fn peer_of(role: &str) -> &'static str {
    if role == "alpha" { "beta" } else { "alpha" }
}

fn wait_for(path: &str) -> bool {
    let mut waited = 0;
    while waited < READY_TIMEOUT_MS {
        if std::path::Path::new(path).exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 100;
    }
    false
}

fn proc_comms() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{name}/comm")) {
                out.push(comm.trim().to_string());
            }
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("alpha");
    let paired = args.get(2).map(String::as_str) == Some("paired");
    let peer = peer_of(role);
    let my_comm = format!("gate-{role}");
    let peer_comm = format!("gate-{peer}");

    let pid = unsafe { libc::getpid() };
    let mut host = [0 as libc::c_char; 256];
    unsafe { libc::gethostname(host.as_mut_ptr(), host.len() - 1) };
    let hostname = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();

    let own_marker = format!("/etc/carrick-gate-{role}");
    let peer_marker = format!("/etc/carrick-gate-{peer}");
    let own_marker_written = std::fs::write(&own_marker, b"1\n").is_ok();

    // A child with a distinctive comm, alive while the peer scans /proc.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let name = std::ffi::CString::new(my_comm.clone()).unwrap();
        unsafe {
            libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
        }
        loop {
            unsafe { libc::pause() };
        }
    }
    let child_forked = child > 0;
    if paired {
        let _ = std::fs::write(format!("/gate/{role}.ready"), b"1\n");
    }
    let peer_ready = !paired || wait_for(&format!("/gate/{peer}.ready"));
    let comms = proc_comms();
    let child_comm_visible = comms.iter().any(|c| c == &my_comm);
    let foreign_proc_visible = comms.iter().any(|c| c == &peer_comm);
    let foreign_marker_visible = std::path::Path::new(&peer_marker).exists();
    if paired {
        let _ = std::fs::write(format!("/gate/{role}.scanned"), b"1\n");
        let _ = wait_for(&format!("/gate/{peer}.scanned"));
    }
    if child_forked {
        unsafe {
            libc::kill(child, libc::SIGKILL);
            let _ = reap(child);
        }
    }
    let lines = format!(
        "role={role}\ngetpid={pid}\nhostname={hostname}\nown_marker_written={own_marker_written}\n\
         foreign_marker_visible={foreign_marker_visible}\nchild_comm_visible={child_comm_visible}\n\
         foreign_proc_visible={foreign_proc_visible}\npeer_ready={peer_ready}\n"
    );
    print!("{lines}");
    if let Ok(mut file) = std::fs::File::create(format!("/gate/{role}.report")) {
        let _ = file.write_all(lines.as_bytes());
    }
    std::process::exit(role_code(role));
}
```

(`conformance_probes::reap` is `pub unsafe fn reap(pid: i32) -> (i32, i32)`, conformance-probes/src/lib.rs:157. The probe crate lives outside `crates/`, so the carrier-only process invariant does not scan its `fork`/`kill`.)

Run: `python3 scripts/probe-inventory.py check; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 3: Move the closure denominators (red → green for the count test)**

Run first: `cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator -- --exact`
Expected: FAILED at `assert_eq!(sources.len(), PROBE_SOURCE_COUNT)` — `assertion `left == right` failed` with `left: 466` / `right: 465` — red (the source now exists, the constants do not know it).

In `crates/carrick-cli/tests/conformance.rs:3249-3251` the doc comment ends and the constant reads:

```rust
/// for the migrating stack-smash family) move the denominator from 463 to 465
/// and the gating rows from 874 to 878 — 439 conformance sources under both
/// variants.
const PROBE_SOURCE_COUNT: usize = 465;
```

Replace with:

```rust
/// for the migrating stack-smash family) move the denominator from 463 to 465
/// and the gating rows from 874 to 878 — 439 conformance sources under both
/// variants. `container_gate` (Gate B of the embed program: two containers in
/// ONE carrier, sequential then concurrent, each pid 1 with its own rootfs,
/// hostname and /proc; dedicated runner `conformance_container_gate`) moves
/// the denominator from 465 to 466 and the gating rows from 878 to 880 — 440
/// conformance sources under both variants.
const PROBE_SOURCE_COUNT: usize = 466;
```

In `DEDICATED_PROBE_RUNNERS` (conformance.rs:3256-3313) insert after the `bridge_udp_sendto_unreachable` pair (the table is alphabetical; `container_gate` precedes `host_gateway_client`):

```rust
    ("container_gate", "conformance_container_gate"),
```

In `closure_probe_inventory_enforces_authoritative_runners_and_denominator` (conformance.rs:4996-5002) the assertions currently read:

```rust
    assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 20);
    assert_eq!(sources.len(), PROBE_SOURCE_COUNT);
    let generic = validate_closure_probe_rows(&inventory(), &sources)
        .expect("checked-in closure probe inventory must match the source denominator");
    assert_eq!(generic.len(), 419);
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 439);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 878);
```

Replace with:

```rust
    assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 21);
    assert_eq!(sources.len(), PROBE_SOURCE_COUNT);
    let generic = validate_closure_probe_rows(&inventory(), &sources)
        .expect("checked-in closure probe inventory must match the source denominator");
    assert_eq!(generic.len(), 419);
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 440);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 880);
```

In `scripts/conformance/closure-probe-scenarios.py:18-19`:

```python
DEDICATED_SOURCE_COUNT = 20
DEDICATED_RUNNER_COUNT = 14
```

becomes:

```python
DEDICATED_SOURCE_COUNT = 21
DEDICATED_RUNNER_COUNT = 15
```

(`build_plan` derives the runner list from the inventory and always targets `--test conformance`, so no runner→target mapping needs editing.)

Run: `cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator -- --exact && python3 scripts/conformance/closure-probe-scenarios.py --check`
Expected: `test result: ok. 1 passed` and `dedicated closure plan: 21 sources, 15 runners`.

- [ ] **Step 4: Build the probe sets (Docker phase — no carrick guest may run concurrently)**

Run: `./scripts/build-probes.sh --closure-arm64`
Expected: ends with the `check-binaries` inventory lines for `arm64-musl` and `arm64-gnu`; `ls conformance-probes/target/aarch64-unknown-linux-musl/release/container_gate` exists.

- [ ] **Step 5: Add the `carrick debug container-gate` command model**

In `crates/carrick-cli/src/args.rs`, after the `LldbSnapshot { .. }` variant (which ends at line 1195, before the enum's closing `}` at 1196) add:

```rust
    /// Gate B of the embed program: boot TWO containers in THIS carrier —
    /// sequentially or concurrently — each running the `container_gate` probe
    /// as its init, and write a JSON receipt proving they shared one HVF VM
    /// while keeping separate pid namespaces, rootfs, hostnames and /proc.
    ContainerGate {
        /// Image both containers boot from.
        #[arg(long, default_value = "docker.io/library/ubuntu:24.04")]
        image: String,
        /// Host path of the static `container_gate` probe binary.
        #[arg(long)]
        probe: PathBuf,
        /// Host directory bind-mounted at `/gate` in both containers (the
        /// rendezvous and report directory).
        #[arg(long = "gate-dir")]
        gate_dir: PathBuf,
        /// Boot the two containers one after the other, or at the same time.
        #[arg(long, value_enum)]
        mode: ContainerGateMode,
        /// Where to write the JSON receipt.
        #[arg(long)]
        output: PathBuf,
    },
```

and, after the enum's closing brace, the mode type (`PathBuf` is already imported at args.rs:33; `clap::ValueEnum` is already used at :92):

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum ContainerGateMode {
    Sequential,
    Concurrent,
}
```

- [ ] **Step 6: Implement the subcommand in `crates/carrick-cli/src/debug.rs`**

`run_debug`'s signature (debug.rs:38) currently reads:

```rust
pub(crate) fn run_debug(command: DebugCommand) -> anyhow::Result<()> {
```

Replace with:

```rust
pub(crate) fn run_debug(
    command: DebugCommand,
    store: carrick_image::ImageStore,
) -> anyhow::Result<()> {
```

and add a match arm before the closing of the `match command` (after the `DebugCommand::LldbSnapshot { .. } => { ... }` arm, debug.rs:223-230):

```rust
        DebugCommand::ContainerGate {
            image,
            probe,
            gate_dir,
            mode,
            output,
        } => {
            run_container_gate(store, &image, &probe, &gate_dir, mode, &output)?;
        }
```

Then add the implementation at the end of the file:

```rust
fn container_gate_request(
    image: &str,
    probe: &Path,
    gate_dir: &Path,
    role: &str,
    mode: &str,
) -> carrick_engine::CliRunRequest {
    use camino::Utf8PathBuf;
    carrick_engine::CliRunRequest {
        image_ref: image.to_owned(),
        pull: carrick_image::PullPolicy::Missing,
        platform: Some("linux/arm64".to_owned()),
        args: vec!["/tmp/p".to_owned(), role.to_owned(), mode.to_owned()],
        env_overrides: Vec::new(),
        mounts: vec![
            carrick_engine::Mount {
                source: Utf8PathBuf::from_path_buf(probe.to_path_buf())
                    .unwrap_or_else(|p| Utf8PathBuf::from(p.to_string_lossy().into_owned())),
                target: Utf8PathBuf::from("/tmp/p"),
                readonly: true,
            },
            carrick_engine::Mount {
                source: Utf8PathBuf::from_path_buf(gate_dir.to_path_buf())
                    .unwrap_or_else(|p| Utf8PathBuf::from(p.to_string_lossy().into_owned())),
                target: Utf8PathBuf::from("/gate"),
                readonly: false,
            },
        ],
        workdir: None,
        user: None,
        hostname: Some(format!("gate-{role}")),
        entrypoint_override: Some(Vec::new()),
        tty: false,
        interactive: false,
        rm: false,
        name: None,
        max_traps: carrick_runtime::runtime::DEFAULT_MAX_TRAPS,
        debug_state_path: None,
        fs: Some(carrick_spec::FsBackendKind::Host),
        exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
        pid: carrick_spec::PidMode::Private,
        network: carrick_spec::NetworkMode::Host,
        network_bridge: None,
        network_container: None,
        network_namespace_id: None,
        network_attachments: Vec::new(),
        network_ipv4: None,
        network_aliases: Vec::new(),
        extra_hosts: Vec::new(),
        dns_servers: Vec::new(),
        dns_search: Vec::new(),
        dns_options: Vec::new(),
        volumes_from: Vec::new(),
        published_ports: Vec::new(),
        stop_signal: None,
        stop_timeout: None,
        security_opts: Vec::new(),
        cap_add: Vec::new(),
    }
}

fn container_gate_outcome(
    run: &Result<carrick_runtime::runtime::RunResult, carrick_runtime::runtime::RuntimeError>,
) -> serde_json::Value {
    match run {
        Ok(result) => serde_json::json!({
            "exit_code": result.exit_code,
            "terminating_signal": result.terminating_signal,
            "trap_limit_hit": result.trap_limit_hit,
            "traps": result.traps,
        }),
        Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
    }
}

/// Two containers, one carrier. Resolution runs under a short-lived tokio
/// runtime that is dropped before execution (the CLI's own pattern, see
/// `commands.rs`); execution is plain `Runtime::execute` — on this thread in
/// sequence, or on two host threads at once.
fn run_container_gate(
    store: carrick_image::ImageStore,
    image: &str,
    probe: &Path,
    gate_dir: &Path,
    mode: crate::args::ContainerGateMode,
    output: &Path,
) -> anyhow::Result<()> {
    use crate::args::ContainerGateMode;
    if !probe.is_file() {
        bail!("container_gate probe is not a file: {}", probe.display());
    }
    fs::create_dir_all(gate_dir)
        .with_context(|| format!("failed to create {}", gate_dir.display()))?;
    carrick_runtime::memory::init_alias_ipa_allocator();
    carrick_runtime::fs_resolve_cache::init();
    let engine = carrick_engine::Engine::new(store);
    let probe_mode = match mode {
        ContainerGateMode::Sequential => "solo",
        ContainerGateMode::Concurrent => "paired",
    };
    let alpha = crate::runtime_util::block_on_oci(engine.resolve(container_gate_request(
        image, probe, gate_dir, "alpha", probe_mode,
    )))
    .map_err(|error| anyhow::anyhow!("resolve alpha: {error:#}"))?;
    let beta = crate::runtime_util::block_on_oci(engine.resolve(container_gate_request(
        image, probe, gate_dir, "beta", probe_mode,
    )))
    .map_err(|error| anyhow::anyhow!("resolve beta: {error:#}"))?;
    let started = Instant::now();
    let (alpha_run, beta_run) = match mode {
        ContainerGateMode::Sequential => (
            carrick_runtime::Runtime::execute(&alpha),
            carrick_runtime::Runtime::execute(&beta),
        ),
        ContainerGateMode::Concurrent => {
            let alpha_thread = thread::Builder::new()
                .name("gate-alpha".into())
                .spawn(move || carrick_runtime::Runtime::execute(&alpha))
                .context("spawn alpha container thread")?;
            let beta_thread = thread::Builder::new()
                .name("gate-beta".into())
                .spawn(move || carrick_runtime::Runtime::execute(&beta))
                .context("spawn beta container thread")?;
            let alpha_run = alpha_thread
                .join()
                .map_err(|_| anyhow::anyhow!("alpha container thread panicked"))?;
            let beta_run = beta_thread
                .join()
                .map_err(|_| anyhow::anyhow!("beta container thread panicked"))?;
            (alpha_run, beta_run)
        }
    };
    let elapsed_ms = started.elapsed().as_millis();
    let snapshot = carrick_runtime::vm_lifecycle::process_snapshot();
    let vm_creates = snapshot
        .events
        .iter()
        .filter(|event| {
            event.operation == carrick_runtime::vm_lifecycle::VmLifecycleOperation::CreateSuccess
        })
        .count();
    let receipt = serde_json::json!({
        "schema": "carrick.container-gate.v1",
        "mode": match mode {
            ContainerGateMode::Sequential => "sequential",
            ContainerGateMode::Concurrent => "concurrent",
        },
        "carrier_pid": std::process::id(),
        "image": image,
        "elapsed_ms": elapsed_ms,
        "vm_create_success_events": vm_creates,
        "live_containers_after": carrick_runtime::carrier::live_container_count(),
        "alpha": container_gate_outcome(&alpha_run),
        "beta": container_gate_outcome(&beta_run),
    });
    fs::write(output, serde_json::to_vec_pretty(&receipt)?)
        .with_context(|| format!("failed to write {}", output.display()))?;
    carrick_runtime::carrier::shutdown().map_err(|error| anyhow::anyhow!("{error:#}"))?;
    alpha_run.map_err(|error| anyhow::anyhow!("alpha container: {error:#}"))?;
    beta_run.map_err(|error| anyhow::anyhow!("beta container: {error:#}"))?;
    Ok(())
}
```

`Path`, `fs`, `thread`, `Instant`, `Context` and `bail` are already imported at debug.rs:25-33; `camino`, `serde_json`, `carrick-image`, `carrick-engine` and `carrick-spec` are already dependencies of `carrick-cli` (Cargo.toml:85-96). `carrick_runtime::runtime::DEFAULT_MAX_TRAPS` is what commands.rs:77 imports today; `carrick_runtime::runtime::{RunResult, RuntimeError}` are re-exported at runtime.rs:196.

In `crates/carrick-cli/src/commands.rs:1335` change:

```rust
        Commands::Debug { command } => run_debug(command)?,
```

to:

```rust
        Commands::Debug { command } => run_debug(command, store.clone())?,
```

(`store` is the opened `ImageStore` bound at commands.rs:401-403 in the same function; it is already cloned into `Engine::new` at :1001.) The non-macOS `Commands::Debug` match at commands.rs:1341 ends in `_ => bail!("debug (guest address-space inspection) is HVF-only on this build")`, which already covers the new variant — keep the catch-all.

Run: `just check`
Expected: compiles (unsigned build; no guest is run).

- [ ] **Step 7: Write the dedicated runner (red first against a run-terminal VM destroy)**

Add to `crates/carrick-cli/tests/conformance.rs` right after `conformance_native_host_gateway` (after line 1905):

```rust
/// Gate B of the embed program (docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md,
/// "Phase B"): two containers in ONE carrier, first sequentially and then
/// concurrently, each seeing `getpid() == 1`, its own rootfs marker, its own
/// hostname, no cross-visible `/proc/<pid>`, and an independent exit status —
/// on the signed artifact, via `carrick debug container-gate`. One HVF VM
/// serves both containers (`vm_create_success_events == 1` per invocation).
#[test]
fn conformance_container_gate() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let closure = dedicated_closure_mode();
    let bin = match carrick_bin() {
        Some(bin) => bin,
        None if closure => panic!("closure gate requires target/release/carrick"),
        None => {
            eprintln!("SKIP conformance_container_gate: target/release/carrick not built");
            return;
        }
    };
    if !lane_runnable_here(&ARM64) {
        assert!(!closure, "closure gate requires an arm64 host");
        eprintln!("SKIP conformance_container_gate: host cannot run linux/arm64 guests");
        return;
    }
    let target = selected_dedicated_probe_target(&ARM64).expect("select dedicated probe target");
    let probe = probes_dir(target).join("container_gate");
    if !probe.is_file() {
        assert!(!closure, "closure gate requires {} — run scripts/build-probes.sh", probe.display());
        eprintln!("SKIP conformance_container_gate: probe not built at {}", probe.display());
        return;
    }
    ensure_signed(&bin);

    fn assert_report(report: &str, role: &str) {
        let expected = [
            format!("role={role}"),
            "getpid=1".to_string(),
            format!("hostname=gate-{role}"),
            "own_marker_written=true".to_string(),
            "foreign_marker_visible=false".to_string(),
            "child_comm_visible=true".to_string(),
            "foreign_proc_visible=false".to_string(),
            "peer_ready=true".to_string(),
        ];
        for line in expected {
            assert!(
                report.lines().any(|l| l == line),
                "{role} report missing `{line}`:\n{report}"
            );
        }
    }

    for mode in ["sequential", "concurrent"] {
        let gate = tempfile::tempdir().expect("gate tempdir");
        let receipt_path = gate.path().join("receipt.json");
        let mut command = Command::new(&bin);
        command
            .args(["debug", "container-gate", "--image", ARM64.image, "--mode", mode])
            .arg("--probe")
            .arg(&probe)
            .arg("--gate-dir")
            .arg(gate.path())
            .arg("--output")
            .arg(&receipt_path)
            .env("CARRICK_ACCEPT_ROSETTA_TERMS", "0");
        let out = run_carrick_probe_process(command, None, Duration::from_secs(240));
        assert!(
            !out.timed_out,
            "container-gate ({mode}) timed out:\n{}",
            out.normalized_output
        );
        assert!(
            out.exit_status.is_some_and(|s| s.success()),
            "container-gate ({mode}) failed: {}\nstdout:\n{}\nstderr:\n{}",
            format_exit_status(out.exit_status.as_ref(), out.timed_out, out.deadline),
            String::from_utf8_lossy(&out.raw_stdout),
            String::from_utf8_lossy(&out.raw_stderr)
        );
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&receipt_path).expect("container-gate receipt"),
        )
        .expect("parse container-gate receipt");
        assert_eq!(receipt["mode"], mode);
        assert_eq!(receipt["alpha"]["exit_code"], 7, "alpha status ({mode}): {receipt}");
        assert_eq!(receipt["beta"]["exit_code"], 9, "beta status ({mode}): {receipt}");
        assert_eq!(receipt["alpha"]["trap_limit_hit"], false);
        assert_eq!(receipt["beta"]["trap_limit_hit"], false);
        assert_eq!(
            receipt["vm_create_success_events"], 1,
            "both containers must share ONE HVF VM ({mode}): {receipt}"
        );
        assert_eq!(receipt["live_containers_after"], 0);
        let alpha = std::fs::read_to_string(gate.path().join("alpha.report"))
            .expect("alpha report");
        let beta = std::fs::read_to_string(gate.path().join("beta.report"))
            .expect("beta report");
        assert_report(&alpha, "alpha");
        assert_report(&beta, "beta");
        if mode == "concurrent" {
            // Both rendezvous files prove the two inits overlapped in time.
            assert!(gate.path().join("alpha.scanned").exists());
            assert!(gate.path().join("beta.scanned").exists());
        }
    }
}
```

(`tempfile` and `serde_json` are already dev-dependencies of `carrick-cli`, Cargo.toml:112-119; `CarrickProbeExecution` carries `normalized_output`, `raw_stdout`, `raw_stderr`, `exit_status: Option<ExitStatus>`, `timed_out`, `deadline` at conformance.rs:3531-3536.)

Red-first proof. A pre-Task-16 checkout cannot compile against `carrier.rs`, so the red is a single controlled, UNCOMMITTED edit that restores the old behaviour at the one seam Task 16 moved: in `run_address_space_with_hvf_and_dispatcher` (runtime.rs), replace the `retire_container` closure passed to `finalize_persistent_hvf_run` with

```rust
            || crate::trap::destroy_persistent_vm_at_carrier_exit().map_err(RuntimeError::from),
```

(leave everything else, including the post-closure retire, untouched), then:

```bash
just build
CARRICK_PROBE_MODE=closure CARRICK_PROBE_LANE=arm64 CARRICK_EXEC_BACKEND=hvpatch \
CARRICK_PROBE_SCENARIO_LIBC=musl cargo test -p carrick-cli --test conformance \
  conformance_container_gate -- --exact --nocapture; echo "exit=$?"
git checkout -- crates/carrick-runtime/src/runtime.rs
```

Expected: the gate FAILS in SEQUENTIAL mode with `exit=101`: the first container's run terminal destroys the carrier VM, so the second root finds `carrier_vm_live()` false, creates a fresh VM, and the receipt reports `vm_create_success_events` = 2 (the `== 1` assertion fails) — or, if the stale published bundle is picked up, the second container reports a hypervisor error. Record which shape you saw in the commit body.

- [ ] **Step 8: Rebuild the signed artifact and run the gate (green)**

```bash
just build
CARRICK_PROBE_MODE=closure CARRICK_PROBE_LANE=arm64 CARRICK_EXEC_BACKEND=hvpatch \
CARRICK_PROBE_SCENARIO_LIBC=musl cargo test -p carrick-cli --test conformance \
  conformance_container_gate -- --exact --nocapture
```

Expected: `test conformance_container_gate ... ok`; the `--nocapture` stream shows both probes' `getpid=1`, `hostname=gate-alpha` / `hostname=gate-beta`, and no `SKIP`. Repeat with `CARRICK_PROBE_SCENARIO_LIBC=gnu` (the GNU set is built by `--closure-arm64`): `ok`.

Run: `pgrep -fl 'carrick debug container-gate'; echo "leftover=$?"`
Expected: `leftover=1` — no leftover carriers (the harness stamps each case with `CARRICK_RUN_ID=cr-gate-<pid>-<seq>` and reaps it by that id; if anything is left, reap it with `sudo -n scripts/sudo/kill.sh <that run id>`).

- [ ] **Step 9: Add the `just gate-containers` recipe**

After the `conformance-probes-closure` recipe (justfile:349-363) add:

```just
# Gate B (embed program, Phase B): two containers in ONE carrier, sequential
# then concurrent, on the signed artifact. Fail-closed: a missing binary,
# probe or arm64 host is a panic, never a skip. Needs the probe sets from
# `scripts/build-probes.sh --closure-arm64` (Docker phase; run it first, never
# concurrently with a carrick guest).
gate-containers: build
    #!/usr/bin/env bash
    set -euo pipefail
    for libc in musl gnu; do
        CARRICK_PROBE_MODE=closure CARRICK_PROBE_LANE=arm64 CARRICK_EXEC_BACKEND=hvpatch \
        CARRICK_PROBE_SCENARIO_LIBC="$libc" \
          cargo test -p carrick-cli --test conformance conformance_container_gate -- --exact --nocapture
    done
```

Run: `mkdir -p target/perf && just gate-containers 2>&1 | tee target/perf/gate-containers.log; echo "exit=${PIPESTATUS[0]}"`
Expected: two `test result: ok. 1 passed` blocks (musl, gnu), `exit=0`. Keep the log (never truncate a gate log).

- [ ] **Step 10: Full local gate**

Run: `just fmt && just ci`
Expected: exit 0. Note that `just ci` does NOT run `--test conformance` (`just test-integration` runs only `trace_profile`, `fs_backend_flag` and `cli` for carrick-cli), so ALSO run `cargo test -p carrick-cli --test conformance closure_probe_inventory -- --nocapture` and confirm `ok`.

- [ ] **Step 11: Commit**

```bash
git add conformance-probes/src/bin/container_gate.rs conformance-probes/probe-inventory.json \
  scripts/conformance/closure-probe-scenarios.py crates/carrick-cli/tests/conformance.rs \
  crates/carrick-cli/src/args.rs crates/carrick-cli/src/debug.rs crates/carrick-cli/src/commands.rs \
  justfile
git commit -F- <<'EOF'
test(conformance): gate B — two containers in one carrier via container_gate

Why: Phase B of the embed program claims a carrier can host containers as
namespace trees on one kernel graph. Nothing in the tree could exercise two
live Linux processes in one carrier, let alone two containers (AGENTS.md:
"a case exercising TWO live guest processes is worth more than any number
of single-process cases"). The unsigned cargo test executable cannot boot
a guest, so the guest-running half must live in the signed binary.

What:
- `conformance-probes/src/bin/container_gate.rs`: a static probe run as
  each container's init that reports getpid()==1, its hostname, its own
  rootfs marker, the absence of the peer's marker and the peer's `/proc`
  tasks, and exits 7/9; `paired` mode rendezvous through a shared `/gate`
  bind mount so both scan `/proc` while the other is alive.
- `carrick debug container-gate`: resolves two RunSpecs under the CLI's
  short-lived tokio runtime, executes them sequentially or on two host
  threads, writes a JSON receipt (exit codes, `vm_create_success_events`,
  live container census) and shuts the carrier down.
- `conformance_container_gate`: a dedicated closure runner (inventory row,
  `DEDICATED_PROBE_RUNNERS`, denominators 465→466 / 20→21 / 14→15) asserting
  the receipt and both report files for musl and gnu; `just gate-containers`.
Deviation from the brief: the probe is Rust in the conformance-probes
layout, which is the tree's probe language (no C probes exist).

Verified: red-first with the run-terminal VM destroy restored at the
finalize seam (sequential mode reports two VM creates, or a hypervisor
error on the second boot); green on the rebuilt signed artifact for musl
and gnu, `vm_create_success_events == 1` in both modes, no leftover
carriers after scoped cleanup; `just ci` green plus the explicit
`closure_probe_inventory` run.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

<details><summary>Verifier problems fixed in place (17) and claims still unverified (7)</summary>

- fixed: Tree HEAD is ea0dac4c (3dc6cc72 is 35 commits behind it). crates/carrick-vmm-hvf/src/trap.rs is byte-identical between 39426141 and ea0dac4c, so the draft's trap.rs citations hold; recorded the verified HEAD in the file list.
- fixed: Line-range nits fixed: rebuilt_vm_cell block is 2180-2192 (doc starts at 2180); record_vm_released is 4123-4132; destroy_persistent_vm_at_run_terminal is 4134-4147; the create_vm_with_admission Ok arm is 4429-4433; PersistentCarrierMappings::audit is 6754-6757 (not 6771-6774); take_persistent_executor_spec is 16611-16627; the mailbox tail is 11985-11987; is_sparse_hvpatch_mmap_mapping is 9898; main.rs process-model prose is lines 65-72 (not 66-73).
- fixed: HV_BUSY citations were wrong: trap.rs:16829 is about hv_vcpu_create on a torn-down VM and runtime.rs:42-44 is about fork; the one-VM-per-process fact the decision rests on is stated in record_vm_resident's comment (trap.rs:4110-4112). Reworded.
- fixed: Concurrent first-boot race (breaks Task 17's concurrent mode): two roots booting with an empty carrier cell BOTH call hv_vm_create and the loser gets HV_BUSY; the draft's `get_or_insert_with` comment ('the loser reuses it next time') is false because the loser has already failed. Added a carrier_root_boot_gate mutex held across the first root's hv_vm_create plus a Condvar (carrier_published, notified from take_persistent_executor_spec) that a root finding the VM live but unpublished waits on.
- fixed: Reuse lane ignored rebuilt_vm_cell(): the SharedWaitResume/ExecveRebuild admissions (trap.rs:16494, 18333) destroy and recreate the VM, and the tree's own persistent-spec consumer (from_persistent_executor_spec, trap.rs:16665-16668) consults rebuilt_vm_cell first. Added the same fallback.
- fixed: Step 6's `for mapping in &plan.mappings { if reusing_carrier { break; } ... }` was a loop that never iterates on one lane; restructured so the identity map_region_raw loop is the None arm of the same match that installs the relocated image.
- fixed: Step 1's HVF test compared TOTAL ledger event counts; sibling tests in the same test binary can record a failed LogicalCreateAttempt concurrently (create_vm_with_admission records operation 0 before the attempt). Now counts only DestroyAttempt/DestroySuccess.
- fixed: `cargo test -p <crate> --lib a b` rejects a second positional filter; Steps 8 and 14 now pass both filters after `--`.
- fixed: Step 13 leaked the container on every pre-loop failure (activate_file_authority, new_hvf_trap_engine, capture_one_task_context return before finalize_persistent_hvf_run): the RAII admission un-counted it but retire_container never ran. Added a post-closure retire for the not-yet-retired case.
- fixed: carrier.rs `vm_was_created()` was misnamed: a non-empty ledger includes a failed LogicalCreateAttempt. Renamed to ledger_has_events and documented that shape (a carrier whose create failed still records a RuntimeError terminal).
- fixed: Step 9's test comment claimed the second Runtime::execute 'inherited the first run's process statics' — a 127 run never reaches run_address_space_with_hvf_and_dispatcher (execute.rs:382-393), so the test proves idempotency/compile only; toned down and pointed at Gate B for the live proof.
- fixed: Step 12/13: `{id:?}` needs ContainerId: Debug and ContainerTeardown's Copy derive needs ContainerId: Copy — both are contract-dependent; called out.
- fixed: Task 17 Step 3's expected red message was invented; the assertion is `assert_eq!(sources.len(), PROBE_SOURCE_COUNT)`, so the failure reads `assertion `left == right` failed` with left 466 / right 465.
- fixed: Task 17 Step 7's red-first (checking out pre-Task-16 runtime.rs/trap.rs) cannot compile against carrier.rs and its `git log --grep | xargs git rev-parse` pipeline breaks when the grep matches nothing; replaced with a controlled local edit (restore the run-terminal destroy in the finalize closure) whose expected failure is `vm_create_success_events == 2`.
- fixed: Task 17 Step 8's cleanup passed a PID from `pgrep -f cr-gate-` to scripts/sudo/kill.sh, which takes a run-id; the harness already reaps each case by its `cr-gate-<pid>-<seq>` run id, so the step is now the leftover check only.
- fixed: Task 17 Step 10 claimed closure_probe_inventory_enforces_authoritative_runners_and_denominator runs inside `just test-integration`; that recipe runs only trace_profile/fs_backend_flag/cli for carrick-cli, and `just ci` does not run `--test conformance`. Now run explicitly.
- fixed: Task 17 Step 9: `tee target/perf/gate-containers.log` needs `mkdir -p target/perf` first.
- UNVERIFIED: That `prepare_global_exec_plan(plan, None)` accepts a BOOT image plan (it was read only as called from `execve_rebuild` with a live mm; the root-slot=None branch at trap.rs:9770-9780 documents 'the root's table is allocator-owned after its first exec', which is the shape a fresh root needs, but no test in the tree boots an image through it).
- UNVERIFIED: That `is_sparse_hvpatch_mmap_mapping` mappings may be skipped for a boot root exactly as the exec lane skips them (the first-boot lane maps every plan mapping via `map_region_raw`; whether the boot image's mmap arena mapping is the sparse reservation the exec lane expects was not confirmed by reading `with_hvpatch_stage1_page_tables`).
- UNVERIFIED: That `PersistentCarrierMappings::drop` (unmapping the five carrier extents) is reached before `hv_vm_destroy` in `destroy_persistent_vm_at_carrier_exit` — it requires every executor pool's `Arc` to be gone; pools are shut down per run (`pool_shutdown` in run_threaded_loop_inner), but a detached carrier's control-exec runtime was not traced for Arc retention.
- UNVERIFIED: Whether the first container's initial identity-IPA extents are unmapped at its root mm retirement under persistent lifecycle (needed for the SEQUENTIAL case to re-map the same identity plan is NOT required by this plan since the reuse lane relocates every root, but `release_retired_stage2_ipa` (trap.rs:6469) returning Ok for non-reusable extents without unmapping suggests boot identity extents may be leaked until carrier exit — harmless for correctness, worth a census).
- UNVERIFIED: `carrick_runtime::fs_resolve_cache::init` and `carrick_runtime::memory::init_alias_ipa_allocator` being idempotent when the CLI `run` path already called them in the same process (the debug subcommand calls them once; the `run` arm is a different subcommand, so they never both run in one process today).
- UNVERIFIED: That `/proc/<pid>/comm` and `prctl(PR_SET_NAME)` are served for a forked child under HVPatch (procid/procpeerdir probes and the proctitle comment suggest yes; not run).
- UNVERIFIED: Line numbers cited for crates/carrick-vmm-hvf/src/trap.rs and crates/carrick-cli/tests/conformance.rs are from HEAD 39426141; Tasks 1-15 will shift them.

</details>
