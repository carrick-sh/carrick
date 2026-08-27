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
use crate::namespace::process::{CapabilitySet, capability_mask_for_names};
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
}

use carrick_guest_mem::{GuestMemory, MemoryError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The container's time authority. Phase B ships `System` mode only: the
/// host clock plus a per-container CLOCK_REALTIME offset that guest
/// `clock_settime`/`settimeofday` move. It replaces the carrier-wide
/// static realtime offset, which let one Linux process's
/// `clock_settime` shift every process in the carrier.
///
/// The host-derived base (`carrick_mem::vdso::REALTIME_OFF_NS`,
/// `unix_ns - uptime_ns` published by the VMM's `populate_vdso_data_page`
/// at vCPU construction and at every exec image replace) is a carrier
/// calibration value shared by every domain; only the offset is container
/// state.
#[derive(Debug, Default)]
pub struct ClockDomain {
    /// Guest `CLOCK_REALTIME` minus host realtime, in nanoseconds.
    realtime_offset_ns: AtomicI64,
    /// Bumped (Release) on every offset change, AFTER the new delta is stored,
    /// so a reader that observes the new epoch (Acquire) also observes the new
    /// delta. Each Linux MM records the epoch its vvar word was stamped under
    /// and re-stamps itself when it falls behind.
    epoch: AtomicU64,
}

/// The vvar `VVAR_OFF_REALTIME_OFF_NS` word for a domain: the vDSO computes
/// `realtime_ns = CNTVCT/freq + word` with u64 wrapping arithmetic, so a
/// negative offset is published as its two's complement.
pub fn vvar_realtime_word(base_off_ns: u64, offset_ns: i64) -> u64 {
    crate::vdso::vvar_realtime_off_ns(base_off_ns, offset_ns)
}

impl ClockDomain {
    /// The host clock, unshifted.
    pub fn system() -> Self {
        Self {
            realtime_offset_ns: AtomicI64::new(0),
            epoch: AtomicU64::new(0),
        }
    }

    pub fn realtime_offset_ns(&self) -> i64 {
        self.realtime_offset_ns.load(Ordering::SeqCst)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn set_realtime_offset_ns(&self, delta_ns: i64) {
        self.realtime_offset_ns.store(delta_ns, Ordering::SeqCst);
        self.epoch.fetch_add(1, Ordering::Release);
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
        match memory.write_bytes_unchecked(
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
            &word.to_le_bytes(),
        ) {
            Ok(()) | Err(MemoryError::OutOfBounds { .. }) => Ok(()),
            Err(error) => Err(error),
        }
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
    /// The PID namespace root's region (`None` = the container shares the
    /// host pid namespace, `PidMode::Host`). Installed once by
    /// `Runtime::execute` before the root task boots; every task reaches it
    /// through `Task::pid_ns_region`. `Container::retire` (Task 23) retires
    /// the namespace's members and releases its arena slot through
    /// `NsSharedRegion::retire`; dropping the last `Arc` is the safety net.
    pid_ns: OnceLock<Arc<crate::namespace::pid::NsSharedRegion>>,
    clock: Arc<ClockDomain>,
    /// The capability set every process of this container starts from: the
    /// Docker default raised by the launch-time `--cap-add` grant. A launch
    /// constant — set once through `with_launch_capabilities` before the
    /// root task is bootstrapped, then read-only; forks copy it per task.
    granted_caps: CapabilitySet,
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
            pid_ns: OnceLock::new(),
            clock: Arc::new(ClockDomain::default()),
            granted_caps: CapabilitySet::docker_default(),
        }
    }

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

    /// The container every in-crate reference-model kernel and the
    /// `"hvpatch-test-root"` / `"adapter-root"` bootstraps boot into: an
    /// unmanaged launch with a fixed stamp. Returned un-`Arc`'d so builders
    /// can chain further defaults (B3 adds `with_launch_capabilities`).
    pub fn for_reference_model() -> Self {
        Self::new(LaunchContext::unmanaged(RunId::new("reference-model")))
    }

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

    /// Retire this container after its run loop returned. Precondition: the
    /// run loop joined every executor of this container (`join_hvpatch_process_threads`
    /// and `take_process_terminal` in `threaded_loop::run_threaded_loop_inner`),
    /// so no task of this pid namespace can still be running. Releases the pid
    /// region back to the carrier arena.
    pub(crate) fn retire(
        self: std::sync::Arc<Self>,
    ) -> Result<crate::carrier::ContainerTeardown, crate::run_result::RuntimeError> {
        let id = self.id();
        let pid_region_released = self
            .pid_region()
            .map(|region| region.retire())
            .unwrap_or(false);
        Ok(crate::carrier::ContainerTeardown {
            id,
            tasks_reaped: 0,
            mounts_dropped: 0,
            pid_region_released,
        })
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
            RegistryContainerId::new("deadbeef")
                .expect("safe id")
                .as_str(),
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
}

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
