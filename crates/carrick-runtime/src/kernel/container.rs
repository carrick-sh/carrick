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

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use camino::Utf8PathBuf;
use carrick_guest_mem::{CurrentMmMemory, MemoryError};

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

/// A signed duration in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SignedDuration(i128);

impl SignedDuration {
    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos as i128)
    }

    pub const fn from_nanos_i128(nanos: i128) -> Self {
        Self(nanos)
    }

    pub const fn from_secs(secs: i64) -> Self {
        Self((secs as i128) * 1_000_000_000)
    }

    pub const fn from_millis(millis: i64) -> Self {
        Self((millis as i128) * 1_000_000)
    }

    pub const fn from_micros(micros: i64) -> Self {
        Self((micros as i128) * 1_000)
    }

    pub fn from_std(duration: Duration) -> Self {
        Self(duration.as_nanos() as i128)
    }

    pub const fn as_nanos(&self) -> i128 {
        self.0
    }

    pub const fn as_nanos_i64(&self) -> Option<i64> {
        if self.0 >= i64::MIN as i128 && self.0 <= i64::MAX as i128 {
            Some(self.0 as i64)
        } else {
            None
        }
    }

    pub const fn as_secs(&self) -> i64 {
        (self.0 / 1_000_000_000) as i64
    }

    pub const fn is_positive(&self) -> bool {
        self.0 > 0
    }

    pub const fn is_negative(&self) -> bool {
        self.0 < 0
    }

    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl From<Duration> for SignedDuration {
    fn from(d: Duration) -> Self {
        Self::from_std(d)
    }
}

/// Time control mode for a container domain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TimeControl {
    /// Real host time (default).
    #[default]
    System,
    /// Wall clock shifted by a fixed signed offset; monotonic advances with host.
    Offset(SignedDuration),
    /// Wall clock frozen at a fixed time; monotonic advances with host.
    Frozen(SystemTime),
    /// Time passes at rational factor `num / den`.
    Scaled {
        base: SystemTime,
        num: u32,
        den: u32,
    },
    /// Strictly incrementing virtual time, reproducible across runs.
    Deterministic { epoch: SystemTime },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    #[error("zero denominator is invalid for scaled time")]
    ZeroDenominator,
    #[error("cannot advance time in mode {0:?}; advance is only supported in Deterministic mode")]
    UnsupportedMode(String),
}

#[derive(Debug, Default)]
struct DeterministicWaiters {
    next_id: u64,
    waiters: std::collections::BTreeMap<u64, DeterministicWaiter>,
}

#[derive(Debug, Clone)]
struct DeterministicWaiter {
    due_monotonic: Option<Duration>,
    pair: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

/// The vvar `VVAR_OFF_REALTIME_OFF_NS` word for a domain: the vDSO computes
/// `realtime_ns = CNTVCT/freq + word` with u64 wrapping arithmetic, so a
/// negative offset must be stored in its two's-complement representation.
pub fn vvar_realtime_word(base_realtime_ns: u64, offset_ns: i64) -> u64 {
    base_realtime_ns.wrapping_add(offset_ns as u64)
}

/// The container's time authority. Supports standard system time tracking
/// plus embedder-controlled modes (`Offset`, `Frozen`, `Scaled`, and
/// `Deterministic`).
#[derive(Debug)]
pub struct ClockDomain {
    control: TimeControl,
    /// Guest `CLOCK_REALTIME` minus host realtime, in nanoseconds.
    realtime_offset_ns: AtomicI64,
    /// Bumped (Release) on every offset change, AFTER the new delta is stored,
    /// so a reader that observes the new epoch (Acquire) also observes the new
    /// delta. Each Linux MM records the epoch its vvar word was stamped under
    /// and re-stamps itself when it falls behind.
    epoch: AtomicU64,
    start_host_instant: Instant,
    virtual_monotonic_ns: AtomicU64,
    waiters: Mutex<DeterministicWaiters>,
}

impl Default for ClockDomain {
    fn default() -> Self {
        Self::new(TimeControl::System)
    }
}

impl ClockDomain {
    /// Create a new clock domain with the given `TimeControl`.
    pub fn new(control: TimeControl) -> Self {
        let initial_offset_ns = match &control {
            TimeControl::Offset(delta) => delta.as_nanos_i64().unwrap_or(0),
            _ => 0,
        };
        Self {
            control,
            realtime_offset_ns: AtomicI64::new(initial_offset_ns),
            epoch: AtomicU64::new(0),
            start_host_instant: Instant::now(),
            virtual_monotonic_ns: AtomicU64::new(0),
            waiters: Mutex::new(DeterministicWaiters::default()),
        }
    }

    /// Construct a standard `System` clock domain (real host time).
    pub fn system() -> Self {
        Self::new(TimeControl::System)
    }

    /// Construct an `Offset` clock domain with a fixed wall-clock delta.
    pub fn offset(delta: SignedDuration) -> Self {
        Self::new(TimeControl::Offset(delta))
    }

    /// Construct a `Frozen` clock domain pinned at `base`.
    pub fn frozen(base: SystemTime) -> Self {
        Self::new(TimeControl::Frozen(base))
    }

    /// Construct a `Scaled` clock domain with rational speedup factor `num / den`.
    pub fn scaled(base: SystemTime, num: u32, den: u32) -> Result<Self, TimeError> {
        if den == 0 {
            return Err(TimeError::ZeroDenominator);
        }
        Ok(Self::new(TimeControl::Scaled { base, num, den }))
    }

    /// Construct a `Deterministic` clock domain with `epoch` virtual base.
    pub fn deterministic(epoch: SystemTime) -> Self {
        Self::new(TimeControl::Deterministic { epoch })
    }

    /// The time control mode of this domain.
    pub fn control(&self) -> &TimeControl {
        &self.control
    }

    /// Whether this clock domain is controlled by an embedder (not live System time).
    pub fn is_controlled(&self) -> bool {
        !matches!(self.control, TimeControl::System)
    }

    /// Whether realtime is frozen.
    pub fn is_frozen(&self) -> bool {
        matches!(self.control, TimeControl::Frozen(_))
    }

    /// Whether time is scaled rationally.
    pub fn is_scaled(&self) -> bool {
        matches!(self.control, TimeControl::Scaled { .. })
    }

    /// Whether virtual time is deterministic.
    pub fn is_deterministic(&self) -> bool {
        matches!(self.control, TimeControl::Deterministic { .. })
    }

    /// Guest `CLOCK_REALTIME` minus host realtime, in nanoseconds.
    pub fn realtime_offset_ns(&self) -> i64 {
        match &self.control {
            TimeControl::Offset(delta) => delta.as_nanos_i64().unwrap_or(0),
            _ => self.realtime_offset_ns.load(Ordering::SeqCst),
        }
    }

    /// The domain's generation counter; bumped on every offset change.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Attempt to set the guest realtime offset. Returns EPERM if embedder time control is active.
    pub fn try_set_realtime_offset_ns(&self, delta_ns: i64) -> Result<(), carrick_abi::LinuxErrno> {
        if self.is_controlled() {
            return Err(carrick_abi::LINUX_EPERM);
        }
        self.realtime_offset_ns.store(delta_ns, Ordering::SeqCst);
        self.epoch.fetch_add(1, Ordering::Release);
        Ok(())
    }

    pub fn set_realtime_offset_ns(&self, delta_ns: i64) {
        let _ = self.try_set_realtime_offset_ns(delta_ns);
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
        match &self.control {
            TimeControl::System => {
                let offset_ns = self.realtime_offset_ns();
                let base = self.realtime_base_now();
                if offset_ns >= 0 {
                    base.saturating_add(Duration::from_nanos(offset_ns as u64))
                } else {
                    base.saturating_sub(Duration::from_nanos(offset_ns.unsigned_abs()))
                }
            }
            TimeControl::Offset(delta) => {
                let offset_ns = delta.as_nanos_i64().unwrap_or(0);
                let base = self.realtime_base_now();
                if offset_ns >= 0 {
                    base.saturating_add(Duration::from_nanos(offset_ns as u64))
                } else {
                    base.saturating_sub(Duration::from_nanos(offset_ns.unsigned_abs()))
                }
            }
            TimeControl::Frozen(base) => base.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO),
            TimeControl::Scaled { base, num, den } => {
                let base_dur = base.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
                let elapsed_scaled = self.scaled_elapsed(*num, *den);
                base_dur.saturating_add(elapsed_scaled)
            }
            TimeControl::Deterministic { epoch } => {
                let epoch_dur = epoch.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
                let virt_ns = self.virtual_monotonic_ns.load(Ordering::SeqCst);
                epoch_dur.saturating_add(Duration::from_nanos(virt_ns))
            }
        }
    }

    /// CLOCK_MONOTONIC as this container sees it.
    pub fn monotonic_now(&self) -> Duration {
        match &self.control {
            TimeControl::System | TimeControl::Offset(_) | TimeControl::Frozen(_) => {
                crate::dispatch::monotonic_duration()
            }
            TimeControl::Scaled { num, den, .. } => self.scaled_elapsed(*num, *den),
            TimeControl::Deterministic { .. } => {
                let virt_ns = self.virtual_monotonic_ns.load(Ordering::SeqCst);
                Duration::from_nanos(virt_ns)
            }
        }
    }

    /// CLOCK_BOOTTIME as this container sees it.
    pub fn boottime_now(&self) -> Duration {
        match &self.control {
            TimeControl::System | TimeControl::Offset(_) | TimeControl::Frozen(_) => {
                crate::dispatch::boottime_duration()
            }
            TimeControl::Scaled { num, den, .. } => self.scaled_elapsed(*num, *den),
            TimeControl::Deterministic { .. } => {
                let virt_ns = self.virtual_monotonic_ns.load(Ordering::SeqCst);
                Duration::from_nanos(virt_ns)
            }
        }
    }

    fn scaled_elapsed(&self, num: u32, den: u32) -> Duration {
        let den = if den == 0 { 1 } else { den };
        let elapsed_host = self.start_host_instant.elapsed();
        let scaled_nanos = (elapsed_host.as_nanos() * (num as u128)) / (den as u128);
        Duration::from_nanos(u64::try_from(scaled_nanos).unwrap_or(u64::MAX))
    }

    /// Scale a guest timeout into the duration to wait on the host.
    pub fn scale_timeout(&self, timeout: Duration) -> Duration {
        match &self.control {
            TimeControl::Scaled { num, den, .. } => {
                let num = if *num == 0 { 1 } else { *num };
                let host_nanos = (timeout.as_nanos() * (*den as u128)) / (num as u128);
                Duration::from_nanos(u64::try_from(host_nanos).unwrap_or(u64::MAX))
            }
            _ => timeout,
        }
    }

    /// Advance virtual time in Deterministic mode by `delta`.
    pub fn advance(&self, delta: Duration) -> Result<(), TimeError> {
        if !self.is_deterministic() {
            return Err(TimeError::UnsupportedMode(format!("{:?}", self.control)));
        }
        let old_ns = self
            .virtual_monotonic_ns
            .fetch_add(delta.as_nanos() as u64, Ordering::SeqCst);
        let new_now = Duration::from_nanos(old_ns.saturating_add(delta.as_nanos() as u64));
        self.wake_due_waiters_locked(new_now);
        Ok(())
    }

    /// The base epoch duration for Deterministic mode.
    pub fn realtime_epoch_duration(&self) -> Duration {
        match &self.control {
            TimeControl::Deterministic { epoch } => {
                epoch.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO)
            }
            _ => Duration::ZERO,
        }
    }

    /// Enroll a waiter on the virtual scheduler in Deterministic mode.
    pub fn enroll_waiter(&self, due_monotonic: Option<Duration>) -> u64 {
        let mut state = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = state.next_id;
        state.next_id += 1;
        state.waiters.insert(
            id,
            DeterministicWaiter {
                due_monotonic,
                pair: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            },
        );
        id
    }

    /// Remove an enrolled waiter from the virtual scheduler.
    pub fn remove_waiter(&self, id: u64) {
        let mut state = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.waiters.remove(&id);
    }

    fn wake_due_waiters_locked(&self, current_time: Duration) {
        let state = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for waiter in state.waiters.values() {
            if let Some(due) = waiter.due_monotonic {
                if due <= current_time {
                    let (lock, cvar) = &*waiter.pair;
                    let mut done = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    *done = true;
                    cvar.notify_all();
                }
            }
        }
    }

    /// In Deterministic mode, wait on the virtual clock until due time or host deadline.
    pub fn wait_virtual(&self, waiter_id: u64, host_deadline: Option<Instant>) -> bool {
        let pair = {
            let state = self
                .waiters
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(w) = state.waiters.get(&waiter_id) else {
                return true;
            };
            Arc::clone(&w.pair)
        };

        self.maybe_auto_advance();

        let (lock, cvar) = &*pair;
        let mut done = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !*done {
            if let Some(dl) = host_deadline {
                let now = Instant::now();
                if now >= dl {
                    return false;
                }
                let rem = dl - now;
                let (g, res) = cvar
                    .wait_timeout(done, rem)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                done = g;
                if res.timed_out() {
                    break;
                }
            } else {
                done = cvar
                    .wait(done)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
        *done
    }

    /// Delay execution by `duration` using the container's clock domain.
    ///
    /// Under `Deterministic` mode this enrolls a due time on the virtual clock,
    /// triggering virtual time auto-advance when all tasks are blocked. Under
    /// `Scaled` mode the timeout is scaled by the rational factor. Never issues
    /// a bare host `thread::sleep` that would block the carrier.
    pub fn delay(&self, duration: Duration) {
        if duration.is_zero() {
            return;
        }
        let due = self.monotonic_now().saturating_add(duration);
        let waiter_id = self.enroll_waiter(Some(due));
        if self.is_deterministic() {
            self.wait_virtual(waiter_id, None);
        } else {
            let scaled = self.scale_timeout(duration);
            let pair = (std::sync::Mutex::new(false), std::sync::Condvar::new());
            let (lock, cvar) = &pair;
            let done = lock.lock().unwrap_or_else(|p| p.into_inner());
            let _ = cvar.wait_timeout(done, scaled);
        }
        self.remove_waiter(waiter_id);
    }

    /// Auto-advance virtual time if all enrolled waiters have a due deadline.
    pub fn maybe_auto_advance(&self) {
        if !self.is_deterministic() {
            return;
        }
        let state = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut min_due: Option<Duration> = None;
        let mut all_timed = true;
        let mut active_count = 0;
        for waiter in state.waiters.values() {
            let (lock, _) = &*waiter.pair;
            let is_done = *lock.lock().unwrap_or_else(|p| p.into_inner());
            if is_done {
                continue;
            }
            active_count += 1;
            match waiter.due_monotonic {
                Some(due) => {
                    min_due = match min_due {
                        None => Some(due),
                        Some(m) => Some(m.min(due)),
                    };
                }
                None => {
                    all_timed = false;
                }
            }
        }

        if !all_timed || active_count == 0 {
            return;
        }

        let current_ns = self.virtual_monotonic_ns.load(Ordering::SeqCst);
        let current_dur = Duration::from_nanos(current_ns);

        if let Some(earliest) = min_due {
            if earliest > current_dur {
                self.virtual_monotonic_ns
                    .store(earliest.as_nanos() as u64, Ordering::SeqCst);
                for waiter in state.waiters.values() {
                    if let Some(due) = waiter.due_monotonic {
                        if due <= earliest {
                            let (lock, cvar) = &*waiter.pair;
                            let mut done = lock.lock().unwrap_or_else(|p| p.into_inner());
                            *done = true;
                            cvar.notify_all();
                        }
                    }
                }
            } else {
                for waiter in state.waiters.values() {
                    if let Some(due) = waiter.due_monotonic {
                        if due <= current_dur {
                            let (lock, cvar) = &*waiter.pair;
                            let mut done = lock.lock().unwrap_or_else(|p| p.into_inner());
                            *done = true;
                            cvar.notify_all();
                        }
                    }
                }
            }
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
        memory: &mut impl CurrentMmMemory,
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
    budget: Option<Arc<crate::observe::ResourceBudget>>,
    /// The capability set every process of this container starts from: the
    /// Docker default raised by the launch-time `--cap-add` grant. A launch
    /// constant — set once through `with_launch_capabilities` before the
    /// root task is bootstrapped, then read-only; forks copy it per task.
    granted_caps: CapabilitySet,
    generation: u64,
    retired: Arc<AtomicBool>,
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
            budget: None,
            granted_caps: CapabilitySet::docker_default(),
            generation: 1,
            retired: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Attach a resource budget quota and counter set to the container.
    pub fn with_resource_budget(mut self, budget: Arc<crate::observe::ResourceBudget>) -> Self {
        self.budget = Some(budget);
        self
    }

    /// The container's resource budget, if configured.
    pub fn budget(&self) -> Option<&Arc<crate::observe::ResourceBudget>> {
        self.budget.as_ref()
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

    /// Configure time control for the container.
    pub fn with_time_control(mut self, control: TimeControl) -> Self {
        self.clock = Arc::new(ClockDomain::new(control));
        self
    }

    /// Attach an explicit [`ClockDomain`] to the container.
    pub fn with_clock(mut self, clock: Arc<ClockDomain>) -> Self {
        self.clock = clock;
        self
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
        if let Some(key) = self.pid_root() {
            if let Ok(pid) = u32::try_from(key.id.raw()) {
                region.set_init(pid);
            }
        }
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
            .map_err(|_| super::KernelError::ContainerRootAlreadyPublished(self.id))?;
        if let Some(region) = self.pid_region() {
            if let Ok(pid) = u32::try_from(key.id.raw()) {
                region.set_init(pid);
            }
        }
        Ok(())
    }

    pub fn clock(&self) -> &Arc<ClockDomain> {
        &self.clock
    }

    /// The execution and lifecycle generation of this container.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether this container has completed execution and been retired.
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// A shared token observing this container's retirement status.
    pub fn retirement_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.retired)
    }

    /// Retire this container after its run loop returned. Precondition: the
    /// run loop joined every executor of this container (`join_hvpatch_process_threads`
    /// and `take_process_terminal` in `threaded_loop::run_threaded_loop_inner`),
    /// so no task of this pid namespace can still be running. Releases the pid
    /// region back to the carrier arena.
    pub(crate) fn retire(
        self: std::sync::Arc<Self>,
    ) -> Result<crate::carrier::ContainerTeardown, crate::run_result::RuntimeError> {
        self.retired.store(true, Ordering::Release);
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
    use super::{ClockDomain, SignedDuration, TimeError, vvar_realtime_word};
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
        assert!(!clock.is_controlled());
        assert!(!clock.is_frozen());
        assert!(!clock.is_scaled());
        assert!(!clock.is_deterministic());
        assert!(
            clock.realtime_now().abs_diff(wall_now()) < Duration::from_secs(5),
            "an unshifted System domain reports the host wall clock"
        );
        assert!(clock.try_set_realtime_offset_ns(1_000_000).is_ok());
        assert_eq!(clock.realtime_offset_ns(), 1_000_000);
        assert_eq!(clock.epoch(), 1);
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
    fn offset_domain_refuses_guest_shift() {
        let delta = SignedDuration::from_secs(3600);
        let clock = ClockDomain::offset(delta);
        assert!(clock.is_controlled());
        assert_eq!(clock.realtime_offset_ns(), 3600 * 1_000_000_000);
        assert_eq!(
            clock.try_set_realtime_offset_ns(100),
            Err(carrick_abi::LINUX_EPERM)
        );
    }

    #[test]
    fn frozen_domain_reports_exact_base_and_refuses_guest_shift() {
        let target = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = ClockDomain::frozen(target);
        assert!(clock.is_controlled());
        assert!(clock.is_frozen());
        assert_eq!(clock.realtime_now(), Duration::from_secs(1_700_000_000));
        assert_eq!(
            clock.try_set_realtime_offset_ns(50),
            Err(carrick_abi::LINUX_EPERM)
        );
    }

    #[test]
    fn scaled_domain_scales_timeout_and_time_rationally() {
        let base = UNIX_EPOCH + Duration::from_secs(1_000_000);
        // 2x speed (num: 2, den: 1)
        let clock = ClockDomain::scaled(base, 2, 1).expect("valid scale");
        assert!(clock.is_controlled());
        assert!(clock.is_scaled());
        assert_eq!(
            clock.scale_timeout(Duration::from_millis(100)),
            Duration::from_millis(50)
        );
        assert_eq!(
            clock.try_set_realtime_offset_ns(10),
            Err(carrick_abi::LINUX_EPERM)
        );

        // 0.5x speed (num: 1, den: 2)
        let slow = ClockDomain::scaled(base, 1, 2).expect("valid scale");
        assert_eq!(
            slow.scale_timeout(Duration::from_millis(100)),
            Duration::from_millis(200)
        );

        assert!(matches!(
            ClockDomain::scaled(base, 1, 0),
            Err(TimeError::ZeroDenominator)
        ));
    }

    #[test]
    fn deterministic_domain_starts_at_zero_and_advances() {
        let epoch = UNIX_EPOCH + Duration::from_secs(500);
        let clock = ClockDomain::deterministic(epoch);
        assert!(clock.is_controlled());
        assert!(clock.is_deterministic());
        assert_eq!(clock.monotonic_now(), Duration::ZERO);
        assert_eq!(clock.realtime_now(), Duration::from_secs(500));

        let waiter_id = clock.enroll_waiter(Some(Duration::from_millis(100)));
        assert!(clock.advance(Duration::from_millis(50)).is_ok());
        assert_eq!(clock.monotonic_now(), Duration::from_millis(50));
        assert_eq!(
            clock.realtime_now(),
            Duration::from_secs(500) + Duration::from_millis(50)
        );

        // Advance past due time
        assert!(clock.advance(Duration::from_millis(60)).is_ok());
        assert_eq!(clock.monotonic_now(), Duration::from_millis(110));
        clock.remove_waiter(waiter_id);
    }

    #[test]
    fn vvar_word_adds_the_signed_offset_with_wrapping() {
        // The vDSO computes realtime_ns = CNTVCT/freq + word (u64 wrapping),
        // so a negative offset must be published as two's complement.
        assert_eq!(vvar_realtime_word(1_000, 5), 1_005);
        assert_eq!(vvar_realtime_word(1_000, -400), 600);
        assert_eq!(vvar_realtime_word(u64::MAX, 1), 0);
    }

    #[test]
    fn deterministic_auto_advance_wakes_waiters_in_deadline_order() {
        let epoch = UNIX_EPOCH + Duration::from_secs(1000);
        let clock = ClockDomain::deterministic(epoch);

        let w1 = clock.enroll_waiter(Some(Duration::from_millis(100)));
        let w2 = clock.enroll_waiter(Some(Duration::from_millis(200)));

        assert_eq!(clock.monotonic_now(), Duration::ZERO);

        // Auto-advance should jump to 100ms and wake w1
        clock.maybe_auto_advance();
        assert_eq!(clock.monotonic_now(), Duration::from_millis(100));

        // w1 wait_virtual should return true immediately
        assert!(clock.wait_virtual(w1, None));

        // Auto-advance again should jump to 200ms and wake w2
        clock.maybe_auto_advance();
        assert_eq!(clock.monotonic_now(), Duration::from_millis(200));
        assert!(clock.wait_virtual(w2, None));

        clock.remove_waiter(w1);
        clock.remove_waiter(w2);
    }

    #[test]
    fn deterministic_threads_wait_and_wake_on_advance() {
        use std::sync::Arc;
        let epoch = UNIX_EPOCH + Duration::from_secs(100);
        let clock = Arc::new(ClockDomain::deterministic(epoch));

        let clock_clone = Arc::clone(&clock);
        let waiter_id = clock.enroll_waiter(Some(Duration::from_millis(50)));

        let handle = std::thread::spawn(move || {
            let woke = clock_clone.wait_virtual(waiter_id, None);
            assert!(woke);
            assert!(clock_clone.monotonic_now() >= Duration::from_millis(50));
        });

        // Sleep briefly on host to ensure the thread is waiting, then advance
        std::thread::sleep(Duration::from_millis(10));
        assert!(clock.advance(Duration::from_millis(50)).is_ok());

        handle.join().expect("thread joined");
        clock.remove_waiter(waiter_id);
    }

    #[test]
    fn deterministic_wait_virtual_respects_host_deadline() {
        let epoch = UNIX_EPOCH + Duration::from_secs(100);
        let clock = ClockDomain::deterministic(epoch);
        // An indefinite waiter (e.g. task blocked on I/O) prevents auto-advance
        let indefinite = clock.enroll_waiter(None);
        let waiter_id = clock.enroll_waiter(Some(Duration::from_secs(3600)));

        let host_deadline = std::time::Instant::now() + Duration::from_millis(20);
        let woke = clock.wait_virtual(waiter_id, Some(host_deadline));
        assert!(
            !woke,
            "virtual wait should time out when host deadline passes"
        );
        clock.remove_waiter(indefinite);
        clock.remove_waiter(waiter_id);
    }

    #[test]
    fn advance_on_non_deterministic_returns_unsupported_mode() {
        let clock = ClockDomain::system();
        assert!(matches!(
            clock.advance(Duration::from_secs(1)),
            Err(TimeError::UnsupportedMode(_))
        ));

        let frozen = ClockDomain::frozen(UNIX_EPOCH);
        assert!(matches!(
            frozen.advance(Duration::from_secs(1)),
            Err(TimeError::UnsupportedMode(_))
        ));
    }

    #[test]
    fn signed_duration_arithmetic() {
        let pos = SignedDuration::from_secs(10);
        assert!(!pos.is_negative());
        assert!(!pos.is_zero());
        assert_eq!(pos.as_nanos_i64(), Some(10_000_000_000));

        let neg = SignedDuration::from_secs(-10);
        assert!(neg.is_negative());
        assert!(!neg.is_zero());
        assert_eq!(neg.as_nanos_i64(), Some(-10_000_000_000));

        let zero = SignedDuration::ZERO;
        assert!(!zero.is_negative());
        assert!(zero.is_zero());
        assert_eq!(zero.as_nanos_i64(), Some(0));

        let from_std: SignedDuration = Duration::from_secs(5).into();
        assert_eq!(from_std.as_nanos_i64(), Some(5_000_000_000));
    }

    #[test]
    fn guest_observed_monotonic_under_deterministic_and_scaled() {
        use crate::vdso_policy::with_optional_vdso_for_clock;
        use carrick_hal::aarch64_arch::Aarch64GuestArch;
        use carrick_mem::memory::AddressSpace;

        // 1. Deterministic container
        let det_clock = ClockDomain::deterministic(UNIX_EPOCH);
        // Ensure vDSO routes to syscalls
        let det_space = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &det_clock,
        )
        .unwrap();
        let det_vdso = det_space
            .regions()
            .iter()
            .find(|r| r.start == carrick_mem::vdso::LINUX_VDSO_BASE)
            .unwrap()
            .bytes()
            .to_vec();
        let syscall_bytes = carrick_mem::vdso::vdso_image_bytes_with_clock_syscalls();
        assert_eq!(
            &det_vdso[..syscall_bytes.len()],
            syscall_bytes.as_slice(),
            "deterministic mode must map syscall-stub vDSO to prevent unscaled hardware counter reads"
        );

        // Guest reads CLOCK_MONOTONIC via syscall
        let t0 = det_clock.monotonic_now();
        assert_eq!(t0, Duration::ZERO);
        // Sleep on host - monotonic time must not advance
        std::thread::sleep(Duration::from_millis(5));
        let t1 = det_clock.monotonic_now();
        assert_eq!(
            t1,
            Duration::ZERO,
            "deterministic monotonic time must not drift on host time"
        );

        // Advance virtual time by 500ms
        det_clock.advance(Duration::from_millis(500)).unwrap();
        let t2 = det_clock.monotonic_now();
        assert_eq!(
            t2,
            Duration::from_millis(500),
            "deterministic monotonic time must step by exact advance delta"
        );

        // 2. Scaled container (10x speedup)
        let scaled_clock = ClockDomain::scaled(UNIX_EPOCH, 10, 1).unwrap();
        let scaled_space = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &scaled_clock,
        )
        .unwrap();
        let scaled_vdso = scaled_space
            .regions()
            .iter()
            .find(|r| r.start == carrick_mem::vdso::LINUX_VDSO_BASE)
            .unwrap()
            .bytes()
            .to_vec();
        assert_eq!(
            &scaled_vdso[..syscall_bytes.len()],
            syscall_bytes.as_slice(),
            "scaled mode must map syscall-stub vDSO to prevent unscaled hardware counter reads"
        );
        // Timeouts are compressed by 10x
        assert_eq!(
            scaled_clock.scale_timeout(Duration::from_secs(10)),
            Duration::from_secs(1)
        );
    }
}
