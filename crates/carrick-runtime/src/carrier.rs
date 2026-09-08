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
//! | `KernelArena` (pid regions live inside it, per container) | `KernelArena::global` (`OnceLock`, carrick-kernel/src/arena.rs) | first wins | process exit |
//! | Host signal dispositions: SIGINT, xsig nudge, pending self-pipe, xsig ring, FASYNC table | `host_signal::install_default_handlers` (`INSTALLED` CAS guard) | guarded | process exit |
//! | Signal-pump dispositions (`PUMP_SIGNALS`, SIGCHLD) | `signal_pump::install_handlers` / `install_sigchld_handler` (`SIGCHLD_INSTALLED`) | re-install is a no-op by effect | process exit |
//! | SIGWINCH self-pipe (`pty_relay::WINCH_PIPE_WRITE`) | `PtyRelay::start_with_pair_and_winsize` (tty runs only) | one relay at a time; endpoints stay open for the process lifetime by design | relay drop restores the disposition |
//! | Deadlock watchdog thread | `deadlock_watchdog::arm` (`ARMED` swap) | guarded | process exit |
//! | vCPU admission scheduler | `vcpu_sched::install_for_budget` (`OnceLock`) | first wins | process exit |
//! | Shared HVPatch runtime directory and executor services | first root activation | later roots use the same services | [`shutdown`] |
//! | `TimerDelivery` handle | `timer_delivery::register_delivery` (`OnceLock`; `HvfTimerDelivery` is a unit struct) | first wins | process exit |
//! | `RLIMIT_NOFILE` soft raise | `runtime::finish_and_run_image` (every `run_*` entry, CLI and embed); `dispatch/time.rs::raise_host_nofile_backing` | only ever raises | process exit |
//! | VM lifecycle ledger terminal + artifact | [`shutdown`] | single terminal per carrier | — |
//!
//! Per-container state (pid namespace root and region, rootfs + mount table,
//! clock domain, granted caps, and kernel process tree) is owned by
//! `crate::kernel::container::Container` and retired by [`Kernel::retire_container_root`](crate::kernel::Kernel::retire_container_root).
//! Root UTS/network launch state remains carrier-scoped until the next
//! isolation phase moves those namespaces onto `Container`; executor services
//! deliberately remain shared carrier infrastructure.

use std::collections::{BTreeMap, btree_map::Entry};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crate::kernel::container::{CarrierScopeId, Container, ContainerId, LaunchContext, RunId};
use crate::run_result::RuntimeError;
use crate::vm_lifecycle::VmRunTerminalOutcome;

static NEXT_CARRIER_GENERATION: AtomicU64 = AtomicU64::new(1);
static CARRIER_PROCESS_EPOCH: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CarrierOwnerKind {
    Explicit,
    ImplicitSingleUse,
}

#[derive(Debug)]
struct IndependentCarrierGate {
    active: Weak<CarrierInner>,
}

impl Default for IndependentCarrierGate {
    fn default() -> Self {
        Self {
            active: Weak::new(),
        }
    }
}

#[derive(Debug)]
struct IndependentCarrierGateSlot {
    current: AtomicPtr<parking_lot::Mutex<IndependentCarrierGate>>,
}

impl IndependentCarrierGateSlot {
    const fn new() -> Self {
        Self {
            current: AtomicPtr::new(ptr::null_mut()),
        }
    }

    fn get(&self) -> &'static parking_lot::Mutex<IndependentCarrierGate> {
        let mut current = self.current.load(Ordering::Acquire);
        if current.is_null() {
            let candidate = Box::into_raw(Box::new(parking_lot::Mutex::new(
                IndependentCarrierGate::default(),
            )));
            match self.current.compare_exchange(
                ptr::null_mut(),
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => current = candidate,
                Err(installed) => {
                    // SAFETY: the losing candidate was never published.
                    drop(unsafe { Box::from_raw(candidate) });
                    current = installed;
                }
            }
        }
        // SAFETY: a published gate is process-lifetime storage. The fork
        // child replaces and intentionally leaks the inherited allocation.
        unsafe { &*current }
    }

    fn reset_after_fork_child(&self) {
        let replacement = Box::into_raw(Box::new(parking_lot::Mutex::new(
            IndependentCarrierGate::default(),
        )));
        self.current.store(replacement, Ordering::Release);
    }
}

fn independent_carrier_gate_slot() -> &'static IndependentCarrierGateSlot {
    static SLOT: IndependentCarrierGateSlot = IndependentCarrierGateSlot::new();
    &SLOT
}

fn independent_carrier_gate() -> &'static parking_lot::Mutex<IndependentCarrierGate> {
    independent_carrier_gate_slot().get()
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
    pub internal_task_id: crate::kernel::TaskId,
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
    pub live_tasks: Option<usize>,
    pub live_pid_regions: Option<usize>,
    pub live_mounts: Option<usize>,
    pub live_frame_leases: Option<usize>,
    pub live_vcpu_leases: Option<usize>,
    pub live_continuations: Option<usize>,
    pub live_job_groups: Option<usize>,
    pub live_workers: Option<usize>,
    pub vm_create_success_events: usize,
    pub vm_lifecycle_violations: usize,
    pub container_inits: Option<Vec<ContainerInitSnapshot>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ContainerPhase {
    Prepared,
    Running,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CarrierTerminalClaim {
    Unclaimed,
    Destroying,
    Finalizing,
}

#[derive(Debug)]
struct ContainerRecord {
    reservation: u64,
    phase: ContainerPhase,
    mounts: Option<usize>,
}

#[derive(Debug)]
struct CarrierState {
    admission: CarrierAdmissionState,
    terminal_claim: CarrierTerminalClaim,
    failure: Option<String>,
    next_reservation: u64,
    containers: BTreeMap<ContainerId, ContainerRecord>,
    latest_terminal: Option<VmRunTerminalOutcome>,
    completed_lifecycle: Option<crate::vm_lifecycle::VmLifecycleSnapshot>,
}

pub(crate) struct CarrierKernelRuntime {
    kernel: Arc<crate::kernel::Kernel>,
    directory: Arc<crate::vcpu_loop::HvpatchRuntimeDirectory>,
}

impl CarrierKernelRuntime {
    pub(crate) fn kernel(&self) -> &Arc<crate::kernel::Kernel> {
        &self.kernel
    }

    pub(crate) fn directory(&self) -> &Arc<crate::vcpu_loop::HvpatchRuntimeDirectory> {
        &self.directory
    }
}

enum CarrierKernelRuntimeSlot {
    Vacant,
    Booting(Option<PendingCarrierKernelRuntime>),
    Ready(Arc<CarrierKernelRuntime>),
}

struct PendingCarrierKernelRuntime {
    runtime: Arc<CarrierKernelRuntime>,
    root_task: crate::kernel::TaskKey,
    root_rollback: FirstRootRollback,
    activation_claimed: bool,
    owner: std::thread::ThreadId,
}

struct KernelBootClaim<'a> {
    carrier: &'a CarrierRuntime,
    armed: bool,
}

impl KernelBootClaim<'_> {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for KernelBootClaim<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.carrier.rollback_kernel_boot_claim();
        }
    }
}

struct FirstRootRollback {
    container: Arc<crate::kernel::Container>,
    task: crate::kernel::TaskKey,
    armed: bool,
}

impl FirstRootRollback {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FirstRootRollback {
    fn drop(&mut self) {
        if self.armed {
            self.container.rollback_pid_root(self.task);
        }
    }
}

pub(crate) struct CarrierKernelRoot {
    carrier: CarrierRuntime,
    runtime: Arc<CarrierKernelRuntime>,
    context: crate::kernel::KernelContext,
    first_boot: bool,
}

pub(crate) struct CarrierKernelActivation {
    carrier: CarrierRuntime,
    runtime: Arc<CarrierKernelRuntime>,
    root_task: crate::kernel::TaskKey,
    armed: bool,
}

impl CarrierKernelActivation {
    pub(crate) fn runtime(&self) -> &Arc<CarrierKernelRuntime> {
        &self.runtime
    }

    /// Publish the fully activated graph/directory pair without auxiliary
    /// services. Production uses [`Self::commit_with_services`]; this helper
    /// keeps carrier-only tests focused on the state transition.
    #[cfg(test)]
    pub(crate) fn commit(self) {
        self.commit_with_services(|_| {});
    }

    /// Publish the graph/directory pair, then install infallible services that
    /// must never point at a provisional first root. The slot remains locked
    /// through the callback, so a later-root waiter cannot observe `Ready`
    /// until those services are installed.
    pub(crate) fn commit_with_services(mut self, publish: impl FnOnce(&Arc<CarrierKernelRuntime>)) {
        let mut slot = self.carrier.inner.kernel_runtime.lock();
        let previous = std::mem::replace(&mut *slot, CarrierKernelRuntimeSlot::Vacant);
        let CarrierKernelRuntimeSlot::Booting(Some(mut pending)) = previous else {
            std::process::abort();
        };
        if pending.root_task != self.root_task
            || !pending.activation_claimed
            || !Arc::ptr_eq(&pending.runtime, &self.runtime)
        {
            std::process::abort();
        }
        pending.root_rollback.disarm();
        *slot = CarrierKernelRuntimeSlot::Ready(Arc::clone(&pending.runtime));
        self.carrier.inner.kernel_runtime_changed.notify_all();
        self.armed = false;
        publish(&self.runtime);
        drop(slot);
    }
}

impl Drop for CarrierKernelActivation {
    fn drop(&mut self) {
        if self.armed {
            self.carrier
                .rollback_pending_kernel_activation(self.root_task, &self.runtime);
        }
    }
}

impl std::fmt::Debug for CarrierKernelRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CarrierKernelRoot")
            .field("task", &self.context.task().key())
            .finish_non_exhaustive()
    }
}

impl CarrierKernelRoot {
    #[cfg(test)]
    pub(crate) fn kernel(&self) -> &Arc<crate::kernel::Kernel> {
        self.runtime.kernel()
    }

    #[cfg(test)]
    fn directory(&self) -> &Arc<crate::vcpu_loop::HvpatchRuntimeDirectory> {
        self.runtime.directory()
    }

    pub(crate) fn is_first_boot(&self) -> bool {
        self.first_boot
    }

    pub(crate) fn context(&self) -> &crate::kernel::KernelContext {
        &self.context
    }

    /// Remove a root whose caller-owned post-publication initialization
    /// failed. First boot is still provisional in the carrier slot; a later
    /// root has crossed the kernel commit and must use the exact container
    /// retirement transaction without disturbing siblings.
    pub(crate) fn rollback_failed_initialization(self) -> Result<(), RuntimeError> {
        if self.first_boot {
            self.carrier
                .rollback_pending_kernel_activation(self.context.task().key(), &self.runtime);
            return Ok(());
        }
        self.runtime
            .kernel()
            .retire_container_root(self.context.container().id(), None)
            .map(|_| ())
            .map_err(|error| {
                RuntimeError::CarrierFailed(format!(
                    "rollback failed HVPatch container-root initialization: {error}"
                ))
            })
    }
}

struct CarrierInner {
    generation: u64,
    scope: CarrierScopeId,
    process_epoch: u64,
    owner_kind: CarrierOwnerKind,
    state: parking_lot::Mutex<CarrierState>,
    changed: parking_lot::Condvar,
    kernel_runtime: parking_lot::Mutex<CarrierKernelRuntimeSlot>,
    kernel_runtime_changed: parking_lot::Condvar,
    /// The scheduling policy an embedder installed for this carrier's run
    /// queue, read once when the carrier boots its kernel runtime.
    scheduling_policy: parking_lot::Mutex<Option<Arc<dyn carrick_hal::SchedulingPolicy>>>,
    lifecycle: crate::vm_lifecycle::VmLifecycleWindow,
    implicit_hold: parking_lot::Mutex<Option<Arc<CarrierInner>>>,
}

impl std::fmt::Debug for CarrierInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CarrierInner")
            .field("generation", &self.generation)
            .field("scope", &self.scope)
            .field("owner_kind", &self.owner_kind)
            .field("process_epoch", &self.process_epoch)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct CarrierRuntime {
    inner: Arc<CarrierInner>,
}

impl CarrierRuntime {
    /// Install the scheduling policy this carrier's run queue will use.
    ///
    /// CARRIER-scoped, because HVPatch multiplexes every Linux task of every
    /// container onto ONE run queue: the `P` set, the placement policy over
    /// it, and the `nproc` the guest reads are all fixed together when the
    /// carrier boots its kernel runtime. Installing after that boot, or
    /// installing a second and different policy, is refused rather than
    /// silently ignored — a guest that has already read `sched_getaffinity`
    /// cannot be told a different CPU count later.
    pub fn install_scheduling_policy(
        &self,
        policy: Arc<dyn carrick_hal::SchedulingPolicy>,
    ) -> Result<(), RuntimeError> {
        let mut slot = self.inner.scheduling_policy.lock();
        if let Some(installed) = slot.as_ref() {
            if Arc::ptr_eq(installed, &policy) {
                return Ok(());
            }
            return Err(RuntimeError::Configuration(
                "a different scheduling policy is already installed on this carrier; the \
                 policy and the guest CPU count it fixes are carrier-scoped, not per-container"
                    .to_owned(),
            ));
        }
        if !matches!(
            *self.inner.kernel_runtime.lock(),
            CarrierKernelRuntimeSlot::Vacant
        ) {
            return Err(RuntimeError::Configuration(
                "this carrier's kernel runtime has already booted; a scheduling policy must \
                 be installed before the carrier's first container starts"
                    .to_owned(),
            ));
        }
        *slot = Some(policy);
        Ok(())
    }

    fn allocate(owner_kind: CarrierOwnerKind, retain_implicit: bool) -> Result<Self, RuntimeError> {
        let generation = NEXT_CARRIER_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RuntimeError::CarrierFailed("carrier generation exhausted".to_owned()))?;
        let lifecycle = crate::vm_lifecycle::VmLifecycleWindow::open(generation)
            .map_err(|error| RuntimeError::CarrierFailed(error.to_string()))?;
        let scope = CarrierScopeId::from_process_env_or_random()?;
        let inner = Arc::new(CarrierInner {
            generation,
            scope,
            process_epoch: CARRIER_PROCESS_EPOCH.load(Ordering::Acquire),
            owner_kind,
            state: parking_lot::Mutex::new(CarrierState {
                admission: CarrierAdmissionState::Open,
                terminal_claim: CarrierTerminalClaim::Unclaimed,
                failure: None,
                next_reservation: 1,
                containers: BTreeMap::new(),
                latest_terminal: None,
                completed_lifecycle: None,
            }),
            changed: parking_lot::Condvar::new(),
            kernel_runtime: parking_lot::Mutex::new(CarrierKernelRuntimeSlot::Vacant),
            scheduling_policy: parking_lot::Mutex::new(None),
            kernel_runtime_changed: parking_lot::Condvar::new(),
            lifecycle,
            implicit_hold: parking_lot::Mutex::new(None),
        });
        if retain_implicit {
            *inner.implicit_hold.lock() = Some(Arc::clone(&inner));
        }
        let carrier = Self { inner };
        carrier.publish_process_title(0);
        Ok(carrier)
    }

    pub fn new_explicit() -> Result<Self, RuntimeError> {
        let mut gate = independent_carrier_gate().lock();
        if gate.active.upgrade().is_some() {
            return Err(RuntimeError::CarrierAlreadyActive);
        }
        let carrier = Self::allocate(CarrierOwnerKind::Explicit, false)?;
        gate.active = Arc::downgrade(&carrier.inner);
        Ok(carrier)
    }

    /// Allocate the private one-shot carrier used by the source-compatible
    /// embedding builder. Unlike the CLI compatibility owner, this carrier is
    /// not self-retained: the prepared run owns it and closes it after its
    /// single container retires.
    #[doc(hidden)]
    pub fn new_implicit_single_use() -> Result<Self, RuntimeError> {
        let mut gate = independent_carrier_gate().lock();
        if let Some(active) = gate.active.upgrade() {
            return match active.owner_kind {
                CarrierOwnerKind::Explicit => Err(RuntimeError::ExplicitCarrierBindingRequired),
                CarrierOwnerKind::ImplicitSingleUse => Err(RuntimeError::CarrierAlreadyActive),
            };
        }
        let carrier = Self::allocate(CarrierOwnerKind::ImplicitSingleUse, false)?;
        gate.active = Arc::downgrade(&carrier.inner);
        Ok(carrier)
    }

    #[cfg(test)]
    pub(crate) fn new_for_tests() -> Result<Self, RuntimeError> {
        Self::allocate(CarrierOwnerKind::Explicit, false)
    }

    fn ensure_current_process(&self) -> Result<(), RuntimeError> {
        if self.inner.process_epoch == CARRIER_PROCESS_EPOCH.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(RuntimeError::CarrierFailed(
                "carrier was inherited across fork and is invalid in the child".to_owned(),
            ))
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    pub fn scope(&self) -> &CarrierScopeId {
        &self.inner.scope
    }

    fn publish_process_title(&self, live_containers: usize) {
        crate::dispatch::set_carrier_process_title(self.inner.scope.as_str(), live_containers);
    }

    pub fn initialize_facilities(&self) {
        if self.ensure_current_process().is_err() {
            return;
        }
        crate::memory::init_alias_ipa_allocator();
        crate::fs_resolve_cache::init();
    }

    /// Boot one container into the carrier's single kernel graph and runtime
    /// directory. The first caller owns a provisional slot; waiters observe
    /// only a fully initialized pair, and a failed claimant restores `Vacant`.
    #[cfg(test)]
    pub(crate) fn boot_kernel_root(
        &self,
        bootstrap: crate::kernel::RootBootstrap,
        initialize: impl FnOnce(
            &Arc<crate::kernel::Kernel>,
            &Arc<crate::vcpu_loop::HvpatchRuntimeDirectory>,
            &crate::kernel::KernelContext,
        ) -> Result<(), RuntimeError>,
    ) -> Result<CarrierKernelRoot, RuntimeError> {
        self.boot_kernel_root_prepared(bootstrap, initialize)
            .map(|(root, ())| root)
    }

    /// Prepare one root's caller-owned initialization effects before the
    /// kernel publication boundary. Later roots return those effects only
    /// after their graph commit succeeds; first boot returns them beside its
    /// still-provisional activation. A rejected later-root commit drops
    /// `Prepared` in the failing call, so RAII rollback cannot escape beside
    /// an unpublished root.
    pub(crate) fn boot_kernel_root_prepared<Prepared>(
        &self,
        bootstrap: crate::kernel::RootBootstrap,
        initialize: impl FnOnce(
            &Arc<crate::kernel::Kernel>,
            &Arc<crate::vcpu_loop::HvpatchRuntimeDirectory>,
            &crate::kernel::KernelContext,
        ) -> Result<Prepared, RuntimeError>,
    ) -> Result<(CarrierKernelRoot, Prepared), RuntimeError> {
        self.ensure_current_process()?;
        let mut slot = self.inner.kernel_runtime.lock();
        loop {
            match &*slot {
                CarrierKernelRuntimeSlot::Vacant => {
                    *slot = CarrierKernelRuntimeSlot::Booting(None);
                    break;
                }
                CarrierKernelRuntimeSlot::Booting(_) => {
                    self.inner.kernel_runtime_changed.wait(&mut slot);
                }
                CarrierKernelRuntimeSlot::Ready(runtime) => {
                    let runtime = Arc::clone(runtime);
                    drop(slot);
                    let (registry_id, mm_backend, diagnostic_name, container) =
                        bootstrap.into_container_root_parts();
                    let prepared = runtime
                        .kernel
                        .prepare_container_root(
                            registry_id,
                            mm_backend,
                            diagnostic_name,
                            container,
                            None,
                        )
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
                    let context = prepared.context();
                    let initialization = initialize(&runtime.kernel, &runtime.directory, &context)?;
                    let context = prepared
                        .commit()
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
                    return Ok((
                        CarrierKernelRoot {
                            carrier: self.clone(),
                            runtime,
                            context,
                            first_boot: false,
                        },
                        initialization,
                    ));
                }
            }
        }
        drop(slot);
        let boot_claim = KernelBootClaim {
            carrier: self,
            armed: true,
        };

        let boot = crate::kernel::Kernel::bootstrap_root(bootstrap)
            .map_err(|error| RuntimeError::Configuration(error.to_string()));
        let (kernel, context) = boot?;
        let root_rollback = FirstRootRollback {
            container: context.container(),
            task: context.task().key(),
            armed: true,
        };
        let directory = Arc::new(
            crate::vcpu_loop::HvpatchRuntimeDirectory::with_scheduling_policy(
                self.inner.scheduling_policy.lock().clone(),
            ),
        );
        let initialization = initialize(&kernel, &directory, &context)?;
        let runtime = Arc::new(CarrierKernelRuntime { kernel, directory });
        let mut slot = self.inner.kernel_runtime.lock();
        if !matches!(*slot, CarrierKernelRuntimeSlot::Booting(None)) {
            return Err(RuntimeError::CarrierFailed(
                "carrier kernel boot claim changed before publication".to_owned(),
            ));
        }
        *slot = CarrierKernelRuntimeSlot::Booting(Some(PendingCarrierKernelRuntime {
            runtime: Arc::clone(&runtime),
            root_task: context.task().key(),
            root_rollback,
            activation_claimed: false,
            owner: std::thread::current().id(),
        }));
        drop(slot);
        boot_claim.disarm();
        Ok((
            CarrierKernelRoot {
                carrier: self.clone(),
                runtime,
                context,
                first_boot: true,
            },
            initialization,
        ))
    }

    pub(crate) fn kernel_runtime(&self) -> Option<Arc<CarrierKernelRuntime>> {
        match &*self.inner.kernel_runtime.lock() {
            CarrierKernelRuntimeSlot::Ready(runtime) => Some(Arc::clone(runtime)),
            CarrierKernelRuntimeSlot::Vacant | CarrierKernelRuntimeSlot::Booting(_) => None,
        }
    }

    pub(crate) fn claim_kernel_activation(
        &self,
        root_task: crate::kernel::TaskKey,
    ) -> Result<Option<CarrierKernelActivation>, RuntimeError> {
        let mut slot = self.inner.kernel_runtime.lock();
        match &mut *slot {
            CarrierKernelRuntimeSlot::Ready(_) => Ok(None),
            CarrierKernelRuntimeSlot::Booting(Some(pending))
                if pending.root_task == root_task && !pending.activation_claimed =>
            {
                pending.activation_claimed = true;
                Ok(Some(CarrierKernelActivation {
                    carrier: self.clone(),
                    runtime: Arc::clone(&pending.runtime),
                    root_task,
                    armed: true,
                }))
            }
            CarrierKernelRuntimeSlot::Booting(Some(pending)) if pending.root_task == root_task => {
                Err(RuntimeError::CarrierFailed(
                    "carrier kernel activation was already claimed".to_owned(),
                ))
            }
            CarrierKernelRuntimeSlot::Vacant | CarrierKernelRuntimeSlot::Booting(_) => {
                Err(RuntimeError::CarrierFailed(
                    "carrier kernel activation has no matching prepared root".to_owned(),
                ))
            }
        }
    }

    fn rollback_kernel_boot_claim(&self) {
        let mut slot = self.inner.kernel_runtime.lock();
        if matches!(*slot, CarrierKernelRuntimeSlot::Booting(_)) {
            *slot = CarrierKernelRuntimeSlot::Vacant;
            self.inner.kernel_runtime_changed.notify_all();
        }
    }

    fn rollback_pending_kernel_activation(
        &self,
        root_task: crate::kernel::TaskKey,
        runtime: &Arc<CarrierKernelRuntime>,
    ) {
        let mut slot = self.inner.kernel_runtime.lock();
        let matches = matches!(
            &*slot,
            CarrierKernelRuntimeSlot::Booting(Some(pending))
                if pending.root_task == root_task && Arc::ptr_eq(&pending.runtime, runtime)
        );
        if matches {
            *slot = CarrierKernelRuntimeSlot::Vacant;
            self.inner.kernel_runtime_changed.notify_all();
        }
    }

    pub(crate) fn rollback_pending_kernel_boot_for_current_thread(&self) {
        let owner = std::thread::current().id();
        let mut slot = self.inner.kernel_runtime.lock();
        if matches!(
            &*slot,
            CarrierKernelRuntimeSlot::Booting(Some(pending)) if pending.owner == owner
        ) {
            *slot = CarrierKernelRuntimeSlot::Vacant;
            self.inner.kernel_runtime_changed.notify_all();
        }
    }

    pub fn reserve(&self, mut launch: LaunchContext) -> Result<CarrierLease, RuntimeError> {
        self.ensure_current_process()?;
        let id = launch.container_id;
        let mut state = self.inner.state.lock();
        match state.admission {
            CarrierAdmissionState::Open => {}
            CarrierAdmissionState::Closing => return Err(RuntimeError::CarrierClosing),
            CarrierAdmissionState::Closed => return Err(RuntimeError::CarrierClosed),
            CarrierAdmissionState::Failed => {
                return Err(RuntimeError::CarrierFailed(
                    state
                        .failure
                        .clone()
                        .unwrap_or_else(|| "carrier lifecycle invariant failed".to_owned()),
                ));
            }
        }
        let reservation = state.next_reservation;
        state.next_reservation = state.next_reservation.checked_add(1).ok_or_else(|| {
            RuntimeError::CarrierFailed("carrier reservation identity exhausted".to_owned())
        })?;
        launch.carrier_scope_id = self.inner.scope.clone();
        if self.inner.owner_kind == CarrierOwnerKind::Explicit {
            launch.run_id = RunId::new(format!("{}-c{reservation}", self.inner.scope.as_str()));
        }
        match state.containers.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(ContainerRecord {
                    reservation,
                    phase: ContainerPhase::Prepared,
                    mounts: None,
                });
            }
            Entry::Occupied(_) => {
                let failure = format!("container {} reserved twice", id.raw());
                state.admission = CarrierAdmissionState::Failed;
                state.failure = Some(failure.clone());
                drop(state);
                self.release_failed_implicit_hold();
                return Err(RuntimeError::CarrierFailed(failure));
            }
        }
        self.inner.changed.notify_all();
        Ok(CarrierLease {
            carrier: Arc::clone(&self.inner),
            generation: self.generation(),
            reservation,
            launch,
        })
    }

    fn release_failed_implicit_hold(&self) {
        if self.inner.owner_kind == CarrierOwnerKind::ImplicitSingleUse {
            let _ = self.inner.implicit_hold.lock().take();
        }
    }

    pub fn begin_close(&self) -> Result<(), RuntimeError> {
        self.ensure_current_process()?;
        let mut state = self.inner.state.lock();
        match state.admission {
            CarrierAdmissionState::Open => state.admission = CarrierAdmissionState::Closing,
            CarrierAdmissionState::Closing => {}
            CarrierAdmissionState::Closed => return Err(RuntimeError::CarrierClosed),
            CarrierAdmissionState::Failed => {
                return Err(RuntimeError::CarrierFailed(
                    state
                        .failure
                        .clone()
                        .unwrap_or_else(|| "carrier failed".to_owned()),
                ));
            }
        }
        self.inner.changed.notify_all();
        Ok(())
    }

    /// Close admission, wait for every exact container lease to retire, then
    /// drain carrier services and destroy the persistent VM. This is the
    /// deterministic lifecycle boundary used by `carrick-embed::Carrier`.
    #[doc(hidden)]
    pub fn shutdown_wait(&self) -> Result<CarrierSnapshot, RuntimeError> {
        match self.begin_close() {
            Ok(()) => {}
            Err(RuntimeError::CarrierClosed) => return self.snapshot(),
            Err(error) => return Err(error),
        }
        self.cancel_running_containers();
        {
            let mut state = self.inner.state.lock();
            loop {
                match state.admission {
                    CarrierAdmissionState::Closing if state.containers.is_empty() => break,
                    CarrierAdmissionState::Closing => self.inner.changed.wait(&mut state),
                    CarrierAdmissionState::Closed => return Ok(self.snapshot_locked(&state)),
                    CarrierAdmissionState::Failed => {
                        return Err(RuntimeError::CarrierFailed(
                            state
                                .failure
                                .clone()
                                .unwrap_or_else(|| "carrier failed".to_owned()),
                        ));
                    }
                    CarrierAdmissionState::Open => return Err(RuntimeError::CarrierClosing),
                }
            }
        }
        let artifact_path = std::env::var_os(crate::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_PATH_ENV)
            .map(std::path::PathBuf::from);
        shutdown_carrier_with_terminal(
            self,
            destroy_vm,
            artifact_path.as_deref(),
            publish_completed_lifecycle,
            || {},
        )
    }

    fn cancel_running_containers(&self) {
        let running = {
            let state = self.inner.state.lock();
            state
                .containers
                .iter()
                .filter_map(|(container, record)| {
                    (record.phase == ContainerPhase::Running).then_some(*container)
                })
                .collect::<Vec<_>>()
        };
        let Some(runtime) = self.kernel_runtime() else {
            return;
        };
        for container in running {
            runtime.kernel().request_container_shutdown(container);
        }
    }

    pub fn finish_close(&self) -> Result<CarrierSnapshot, RuntimeError> {
        self.ensure_current_process()?;
        {
            let mut state = self.inner.state.lock();
            match state.admission {
                CarrierAdmissionState::Open => return Err(RuntimeError::CarrierClosing),
                CarrierAdmissionState::Closing => {}
                CarrierAdmissionState::Closed => return Ok(self.snapshot_locked(&state)),
                CarrierAdmissionState::Failed => {
                    return Err(RuntimeError::CarrierFailed(
                        state
                            .failure
                            .clone()
                            .unwrap_or_else(|| "carrier failed".to_owned()),
                    ));
                }
            }
            if !state.containers.is_empty() {
                return Err(RuntimeError::CarrierClosing);
            }
            match state.terminal_claim {
                CarrierTerminalClaim::Unclaimed => {
                    state.terminal_claim = CarrierTerminalClaim::Finalizing;
                }
                CarrierTerminalClaim::Destroying | CarrierTerminalClaim::Finalizing => {
                    return Err(RuntimeError::CarrierClosing);
                }
            }
            self.inner.changed.notify_all();
        }
        self.finish_claimed_close(None, |_, _, _| Ok(()))
    }

    fn finish_claimed_close(
        &self,
        artifact_path: Option<&std::path::Path>,
        publish: impl FnOnce(
            &std::path::Path,
            &crate::vm_lifecycle::VmLifecycleSnapshot,
            &CarrierScopeId,
        ) -> Result<(), String>,
    ) -> Result<CarrierSnapshot, RuntimeError> {
        let mut state = self.inner.state.lock();
        if state.admission != CarrierAdmissionState::Closing
            || state.terminal_claim != CarrierTerminalClaim::Finalizing
        {
            return Err(RuntimeError::CarrierClosing);
        }
        let raw = self.inner.lifecycle.raw_snapshot();
        if !raw.events.is_empty() && raw.terminal.is_none() {
            crate::vm_lifecycle::record_process_terminal(
                state
                    .latest_terminal
                    .unwrap_or(VmRunTerminalOutcome::RuntimeError),
            );
        }
        let completed = match self.inner.lifecycle.finalize() {
            Ok(completed) => completed,
            Err(error) => {
                let failure = error.to_string();
                state.admission = CarrierAdmissionState::Failed;
                state.failure = Some(failure.clone());
                self.inner.changed.notify_all();
                drop(state);
                self.release_failed_implicit_hold();
                return Err(RuntimeError::CarrierFailed(failure));
            }
        };
        state.completed_lifecycle = Some(completed.clone());
        drop(state);

        if let Some(path) = artifact_path.filter(|_| !completed.events.is_empty()) {
            if let Err(failure) = publish(path, &completed, &self.inner.scope) {
                let mut state = self.inner.state.lock();
                state.admission = CarrierAdmissionState::Failed;
                state.failure = Some(failure.clone());
                self.inner.changed.notify_all();
                drop(state);
                self.release_failed_implicit_hold();
                return Err(RuntimeError::CarrierFailed(failure));
            }
        }

        let mut state = self.inner.state.lock();
        if state.admission != CarrierAdmissionState::Closing
            || state.terminal_claim != CarrierTerminalClaim::Finalizing
        {
            let failure = "carrier finalization claim changed before close publication".to_owned();
            state.admission = CarrierAdmissionState::Failed;
            state.failure = Some(failure.clone());
            self.inner.changed.notify_all();
            drop(state);
            self.release_failed_implicit_hold();
            return Err(RuntimeError::CarrierFailed(failure));
        }
        state.admission = CarrierAdmissionState::Closed;
        self.inner.changed.notify_all();
        let snapshot = self.snapshot_locked(&state);
        drop(state);
        let _ = self.inner.implicit_hold.lock().take();
        Ok(snapshot)
    }

    pub fn record_terminal(&self, outcome: VmRunTerminalOutcome) {
        if self.ensure_current_process().is_ok() {
            self.inner.state.lock().latest_terminal = Some(outcome);
        }
    }

    pub fn snapshot(&self) -> Result<CarrierSnapshot, RuntimeError> {
        self.ensure_current_process()?;
        Ok(self.snapshot_locked(&self.inner.state.lock()))
    }

    fn snapshot_locked(&self, state: &CarrierState) -> CarrierSnapshot {
        let lifecycle = state
            .completed_lifecycle
            .clone()
            .unwrap_or_else(|| self.inner.lifecycle.raw_snapshot());
        // A temporary guard created inside the struct literal lives through
        // the whole literal, so lock this slot once before populating both
        // pointer-identical facility counts.
        let kernel_runtime = self.inner.kernel_runtime.lock();
        let ready_kernel_runtime = match &*kernel_runtime {
            CarrierKernelRuntimeSlot::Ready(runtime) => Some(Arc::clone(runtime)),
            CarrierKernelRuntimeSlot::Vacant | CarrierKernelRuntimeSlot::Booting(_) => None,
        };
        let has_kernel_runtime = ready_kernel_runtime.is_some();
        let (live_tasks, container_inits) = ready_kernel_runtime
            .as_ref()
            .map(|runtime| {
                let mut inits = runtime
                    .kernel
                    .container_ids()
                    .into_iter()
                    .filter_map(|container_id| {
                        runtime.kernel.container_init(container_id).map(|init| {
                            ContainerInitSnapshot {
                                container_id,
                                internal_task_id: init.id,
                                namespace_pid: 1,
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                inits.sort_by_key(|init| init.container_id);
                (runtime.kernel.registry().task_count(), inits)
            })
            .unzip();
        let live_pid_regions = ready_kernel_runtime
            .as_ref()
            .map(|runtime| runtime.kernel.container_ids().len());
        let live_frame_leases = ready_kernel_runtime
            .as_ref()
            .map(|runtime| runtime.kernel.frame_inventory().snapshot().mappings.len());
        let live_job_groups = ready_kernel_runtime
            .as_ref()
            .map(|runtime| runtime.directory.live_job_group_count());
        CarrierSnapshot {
            generation: self.generation(),
            state: state.admission,
            live_containers: state
                .containers
                .values()
                .filter(|record| record.phase == ContainerPhase::Running)
                .count(),
            kernel_graphs: usize::from(has_kernel_runtime),
            runtime_directories: usize::from(has_kernel_runtime),
            registered_containers: state.containers.len(),
            live_tasks,
            live_pid_regions,
            live_mounts: state
                .containers
                .values()
                .try_fold(0_usize, |total, record| total.checked_add(record.mounts?)),
            live_frame_leases,
            live_vcpu_leases: None,
            live_continuations: None,
            live_job_groups,
            live_workers: Some(
                state
                    .containers
                    .values()
                    .filter(|record| record.phase == ContainerPhase::Running)
                    .count(),
            ),
            vm_create_success_events: lifecycle
                .events
                .iter()
                .filter(|event| {
                    event.operation == crate::vm_lifecycle::VmLifecycleOperation::CreateSuccess
                })
                .count(),
            vm_lifecycle_violations: lifecycle.violations.len(),
            container_inits,
        }
    }

    #[cfg(test)]
    fn record_vm_lifecycle_for_test(&self, operation: u32, admission: i32) {
        if self.ensure_current_process().is_ok() {
            crate::vm_lifecycle::record_raw(operation, admission);
        }
    }

    #[cfg(test)]
    fn raw_vm_lifecycle_snapshot_for_test(&self) -> crate::vm_lifecycle::VmLifecycleSnapshot {
        self.inner.lifecycle.raw_snapshot()
    }
}

#[must_use = "dropping a prepared lease rolls its carrier reservation back"]
pub struct CarrierLease {
    carrier: Arc<CarrierInner>,
    generation: u64,
    reservation: u64,
    launch: LaunchContext,
}

impl CarrierLease {
    pub fn launch(&self) -> &LaunchContext {
        &self.launch
    }

    pub(crate) fn belongs_to(&self, carrier: &CarrierRuntime) -> bool {
        self.carrier.process_epoch == CARRIER_PROCESS_EPOCH.load(Ordering::Acquire)
            && self.generation == carrier.generation()
            && Arc::ptr_eq(&self.carrier, &carrier.inner)
    }

    pub(crate) fn mark_running(&self) -> Result<(), RuntimeError> {
        if self.carrier.process_epoch != CARRIER_PROCESS_EPOCH.load(Ordering::Acquire) {
            return Err(RuntimeError::CarrierFailed(
                "carrier lease was inherited across fork and is invalid in the child".to_owned(),
            ));
        }
        let mut state = self.carrier.state.lock();
        match state.admission {
            CarrierAdmissionState::Open => {}
            CarrierAdmissionState::Closing => return Err(RuntimeError::CarrierClosing),
            CarrierAdmissionState::Closed => return Err(RuntimeError::CarrierClosed),
            CarrierAdmissionState::Failed => {
                return Err(RuntimeError::CarrierFailed(
                    state
                        .failure
                        .clone()
                        .unwrap_or_else(|| "carrier failed".to_owned()),
                ));
            }
        }
        let record = state
            .containers
            .get_mut(&self.launch.container_id)
            .ok_or_else(|| {
                RuntimeError::CarrierFailed("carrier lease lost its reservation".to_owned())
            })?;
        if self.generation != self.carrier.generation
            || self.reservation != record.reservation
            || record.phase != ContainerPhase::Prepared
        {
            return Err(RuntimeError::CarrierFailed(
                "carrier lease cannot enter running twice or across generations".to_owned(),
            ));
        }
        record.phase = ContainerPhase::Running;
        let live_containers = state
            .containers
            .values()
            .filter(|record| record.phase == ContainerPhase::Running)
            .count();
        crate::dispatch::set_carrier_process_title(self.carrier.scope.as_str(), live_containers);
        self.carrier.changed.notify_all();
        Ok(())
    }

    pub(crate) fn register_mounts(&self, mounts: usize) -> Result<(), RuntimeError> {
        let mut state = self.carrier.state.lock();
        let record = state
            .containers
            .get_mut(&self.launch.container_id)
            .ok_or_else(|| RuntimeError::CarrierFailed("carrier lost mount owner".to_owned()))?;
        if self.generation != self.carrier.generation
            || self.reservation != record.reservation
            || record.phase != ContainerPhase::Running
        {
            return Err(RuntimeError::CarrierFailed(
                "mount table belongs to a stale carrier reservation".to_owned(),
            ));
        }
        match record.mounts {
            None => record.mounts = Some(mounts),
            Some(current) if current == mounts => {}
            Some(_) => {
                return Err(RuntimeError::CarrierFailed(
                    "carrier mount census changed after configuration sealed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn retire(
        &mut self,
        container: Arc<Container>,
    ) -> Result<ContainerTeardown, RuntimeError> {
        if self.carrier.process_epoch != CARRIER_PROCESS_EPOCH.load(Ordering::Acquire) {
            return Err(RuntimeError::CarrierFailed(
                "carrier lease was inherited across fork and is invalid in the child".to_owned(),
            ));
        }
        if container.id() != self.launch.container_id {
            return Err(RuntimeError::CarrierFailed(
                "carrier lease retired a different container".to_owned(),
            ));
        }
        {
            let state = self.carrier.state.lock();
            match state.admission {
                CarrierAdmissionState::Open
                | CarrierAdmissionState::Closing
                | CarrierAdmissionState::Failed => {}
                CarrierAdmissionState::Closed => return Err(RuntimeError::CarrierClosed),
            }
            let Some(record) = state.containers.get(&self.launch.container_id) else {
                return Err(RuntimeError::CarrierFailed(
                    "carrier lease retired twice".to_owned(),
                ));
            };
            if self.generation != self.carrier.generation
                || self.reservation != record.reservation
                || record.phase != ContainerPhase::Running
            {
                return Err(RuntimeError::CarrierFailed(
                    "carrier lease does not own the running reservation".to_owned(),
                ));
            }
        }
        container.retire()
    }

    /// Publish the already-completed kernel and mount teardown to carrier
    /// observers. The running record remains authoritative until this point,
    /// so snapshots and shutdown cannot report zero mounts while their
    /// destructors are still running.
    pub(crate) fn publish_retired(&mut self) {
        let mut state = self.carrier.state.lock();
        let exact = state
            .containers
            .get(&self.launch.container_id)
            .is_some_and(|record| {
                record.reservation == self.reservation && record.phase == ContainerPhase::Running
            });
        if !exact {
            std::process::abort();
        }
        state.containers.remove(&self.launch.container_id);
        let live_containers = state
            .containers
            .values()
            .filter(|record| record.phase == ContainerPhase::Running)
            .count();
        crate::dispatch::set_carrier_process_title(self.carrier.scope.as_str(), live_containers);
        self.carrier.changed.notify_all();
    }
}

impl Drop for CarrierLease {
    fn drop(&mut self) {
        if self.carrier.process_epoch != CARRIER_PROCESS_EPOCH.load(Ordering::Acquire) {
            return;
        }
        let mut state = self.carrier.state.lock();
        let Some(record) = state.containers.get(&self.launch.container_id) else {
            return;
        };
        if record.reservation != self.reservation || self.generation != self.carrier.generation {
            state.admission = CarrierAdmissionState::Failed;
            state.failure = Some("carrier lease ownership changed before drop".to_owned());
            self.carrier.changed.notify_all();
            drop(state);
            let _ = self.carrier.implicit_hold.lock().take();
            return;
        }
        match record.phase {
            ContainerPhase::Prepared => {
                state.containers.remove(&self.launch.container_id);
            }
            ContainerPhase::Running => {
                state.admission = CarrierAdmissionState::Failed;
                state.failure = Some(format!(
                    "running container {} lost its terminal lease",
                    self.launch.container_id.raw()
                ));
            }
        }
        self.carrier.changed.notify_all();
        let failed = state.admission == CarrierAdmissionState::Failed;
        drop(state);
        if failed && self.carrier.owner_kind == CarrierOwnerKind::ImplicitSingleUse {
            let _ = self.carrier.implicit_hold.lock().take();
        }
    }
}

fn active_process_carrier() -> Option<CarrierRuntime> {
    independent_carrier_gate()
        .lock()
        .active
        .upgrade()
        .map(|inner| CarrierRuntime { inner })
}

/// Compatibility owner used by the CLI path until every caller receives an
/// explicit carrier in Task 5. This is still an owned [`CarrierRuntime`]: the
/// process-global gate retains only a `Weak`, while the carrier retains itself
/// until [`shutdown`] completes and releases that ownership.
pub(crate) fn process_carrier() -> Result<CarrierRuntime, RuntimeError> {
    let mut gate = independent_carrier_gate().lock();
    if let Some(inner) = gate.active.upgrade() {
        return match inner.owner_kind {
            CarrierOwnerKind::Explicit => Err(RuntimeError::ExplicitCarrierBindingRequired),
            CarrierOwnerKind::ImplicitSingleUse => {
                let carrier = CarrierRuntime { inner };
                let state = carrier.inner.state.lock();
                match state.admission {
                    CarrierAdmissionState::Open => {
                        drop(state);
                        Ok(carrier)
                    }
                    CarrierAdmissionState::Closing => Err(RuntimeError::CarrierClosing),
                    CarrierAdmissionState::Closed => Err(RuntimeError::CarrierClosed),
                    CarrierAdmissionState::Failed => Err(RuntimeError::CarrierFailed(
                        state
                            .failure
                            .clone()
                            .unwrap_or_else(|| "carrier failed".to_owned()),
                    )),
                }
            }
        };
    }
    let carrier = CarrierRuntime::allocate(CarrierOwnerKind::ImplicitSingleUse, true)?;
    gate.active = Arc::downgrade(&carrier.inner);
    Ok(carrier)
}

fn active_implicit_process_carrier() -> Result<Option<CarrierRuntime>, RuntimeError> {
    let Some(carrier) = active_process_carrier() else {
        return Ok(None);
    };
    match carrier.inner.owner_kind {
        CarrierOwnerKind::Explicit => Err(RuntimeError::ExplicitCarrierBindingRequired),
        CarrierOwnerKind::ImplicitSingleUse => Ok(Some(carrier)),
    }
}

/// Number of containers currently booted in this carrier.
pub fn live_container_count() -> usize {
    active_implicit_process_carrier()
        .ok()
        .flatten()
        .and_then(|carrier| carrier.snapshot().ok())
        .map_or(0, |snapshot| snapshot.live_containers)
}

/// Receipt of one container's teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerTeardown {
    pub id: ContainerId,
    pub carrier_scope_id: CarrierScopeId,
    pub run_id: RunId,
    pub tasks_reaped: usize,
    pub mounts_dropped: usize,
    pub pid_region_released: bool,
}

/// Retire a container through the exact explicit carrier lease that admitted
/// it. Kernel and mount teardown complete before the running census is
/// decremented, preserving the same publication boundary as the compatibility
/// CLI admission wrapper.
pub(crate) fn retire_leased_container(
    container: Arc<Container>,
    lease: &mut CarrierLease,
    mounts: &mut crate::dispatch::MountRetirement,
) -> Result<ContainerTeardown, RuntimeError> {
    mounts
        .prepare_for(container.id())
        .map_err(|error| RuntimeError::CarrierFailed(error.to_string()))?;
    let mut receipt = lease.retire(container)?;
    receipt.mounts_dropped = mounts.clear();
    lease.publish_retired();
    Ok(receipt)
}

#[cfg(feature = "platform-macos")]
fn destroy_vm() -> Result<(), RuntimeError> {
    crate::trap::destroy_persistent_vm_at_carrier_exit().map_err(RuntimeError::from)
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn destroy_vm() -> Result<(), RuntimeError> {
    Ok(())
}

/// Tear the carrier down: destroy the persistent VM, record the ledger
/// terminal (the last container's outcome, or `RuntimeError` if a VM create
/// was attempted but no container completed), and publish the lifecycle
/// artifact when `CARRICK_HVPATCH_VM_LEDGER_PATH` names one. Idempotent; a
/// carrier whose ledger is empty records nothing.
pub fn shutdown() -> Result<(), RuntimeError> {
    shutdown_with_destroy_and_hooks(destroy_vm, publish_completed_lifecycle, || {})
}

fn publish_completed_lifecycle(
    path: &std::path::Path,
    completed: &crate::vm_lifecycle::VmLifecycleSnapshot,
    carrier_scope: &CarrierScopeId,
) -> Result<(), String> {
    crate::vm_lifecycle::write_completed_artifact(
        path,
        completed,
        carrier_scope.as_str().as_bytes(),
    )
    .map(|_| ())
    .map_err(|error| {
        format!("HVPatch VM lifecycle artifact publication failed at carrier exit: {error}")
    })
}

fn shutdown_with_destroy_and_hooks(
    destroy: impl FnOnce() -> Result<(), RuntimeError>,
    publish: impl FnOnce(
        &std::path::Path,
        &crate::vm_lifecycle::VmLifecycleSnapshot,
        &CarrierScopeId,
    ) -> Result<(), String>,
    wait_observer: impl FnOnce(),
) -> Result<(), RuntimeError> {
    let Some(carrier) = active_implicit_process_carrier()? else {
        return Ok(());
    };
    let artifact_path = std::env::var_os(crate::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_PATH_ENV)
        .map(std::path::PathBuf::from);
    shutdown_carrier_with_terminal(
        &carrier,
        destroy,
        artifact_path.as_deref(),
        publish,
        wait_observer,
    )?;
    Ok(())
}

#[cfg(test)]
fn shutdown_carrier_with(
    carrier: &CarrierRuntime,
    destroy: impl FnOnce() -> Result<(), RuntimeError>,
) -> Result<CarrierSnapshot, RuntimeError> {
    shutdown_carrier_with_terminal(carrier, destroy, None, |_, _, _| Ok(()), || {})
}

#[cfg(test)]
fn shutdown_carrier_with_wait_observer(
    carrier: &CarrierRuntime,
    destroy: impl FnOnce() -> Result<(), RuntimeError>,
    wait_observer: impl FnOnce(),
) -> Result<CarrierSnapshot, RuntimeError> {
    shutdown_carrier_with_terminal(carrier, destroy, None, |_, _, _| Ok(()), wait_observer)
}

fn shutdown_carrier_with_terminal(
    carrier: &CarrierRuntime,
    destroy: impl FnOnce() -> Result<(), RuntimeError>,
    artifact_path: Option<&std::path::Path>,
    publish: impl FnOnce(
        &std::path::Path,
        &crate::vm_lifecycle::VmLifecycleSnapshot,
        &CarrierScopeId,
    ) -> Result<(), String>,
    wait_observer: impl FnOnce(),
) -> Result<CarrierSnapshot, RuntimeError> {
    match carrier.begin_close() {
        Ok(()) => {}
        Err(RuntimeError::CarrierClosed) => return carrier.snapshot(),
        Err(error) => return Err(error),
    }
    let mut destroy = Some(destroy);
    let mut wait_observer = Some(wait_observer);
    loop {
        let mut state = carrier.inner.state.lock();
        match state.admission {
            CarrierAdmissionState::Open => return Err(RuntimeError::CarrierClosing),
            CarrierAdmissionState::Closing => {}
            CarrierAdmissionState::Closed => return Ok(carrier.snapshot_locked(&state)),
            CarrierAdmissionState::Failed => {
                return Err(RuntimeError::CarrierFailed(
                    state
                        .failure
                        .clone()
                        .unwrap_or_else(|| "carrier failed".to_owned()),
                ));
            }
        }
        if !state.containers.is_empty() {
            return Err(RuntimeError::CarrierClosing);
        }
        match state.terminal_claim {
            CarrierTerminalClaim::Unclaimed => {
                state.terminal_claim = CarrierTerminalClaim::Destroying;
                carrier.inner.changed.notify_all();
            }
            CarrierTerminalClaim::Destroying | CarrierTerminalClaim::Finalizing => {
                if let Some(observer) = wait_observer.take() {
                    drop(state);
                    observer();
                } else {
                    carrier.inner.changed.wait(&mut state);
                }
                continue;
            }
        }
        drop(state);

        // The persistent executor pool and every logical process job belong
        // to the carrier, not to whichever container root happens to finish
        // first. Only the terminal claimant may drain and close them.
        if let Some(runtime) = carrier.kernel_runtime()
            && let Err(error) = runtime.directory().shutdown_carrier_runtime()
        {
            let mut state = carrier.inner.state.lock();
            if state.admission == CarrierAdmissionState::Closing
                && state.terminal_claim == CarrierTerminalClaim::Destroying
            {
                state.terminal_claim = CarrierTerminalClaim::Unclaimed;
                carrier.inner.changed.notify_all();
            }
            return Err(error);
        }

        // Admission is Closing, so the empty registry cannot gain a new
        // record. The claim remains published while the state mutex is
        // deliberately released across hardware destruction.
        let Some(destroy_once) = destroy.take() else {
            let failure =
                "shutdown caller reclaimed destruction after consuming its callback".to_owned();
            let mut state = carrier.inner.state.lock();
            state.admission = CarrierAdmissionState::Failed;
            state.failure = Some(failure.clone());
            carrier.inner.changed.notify_all();
            drop(state);
            carrier.release_failed_implicit_hold();
            return Err(RuntimeError::CarrierFailed(failure));
        };
        let destroy_result = destroy_once();
        if let Err(error) = destroy_result {
            let mut state = carrier.inner.state.lock();
            if state.admission == CarrierAdmissionState::Closing
                && state.terminal_claim == CarrierTerminalClaim::Destroying
            {
                state.terminal_claim = CarrierTerminalClaim::Unclaimed;
                carrier.inner.changed.notify_all();
            }
            return Err(error);
        }

        let mut state = carrier.inner.state.lock();
        if state.admission != CarrierAdmissionState::Closing
            || state.terminal_claim != CarrierTerminalClaim::Destroying
        {
            let failure = "carrier destruction claim changed before finalization".to_owned();
            state.admission = CarrierAdmissionState::Failed;
            state.failure = Some(failure.clone());
            carrier.inner.changed.notify_all();
            drop(state);
            carrier.release_failed_implicit_hold();
            return Err(RuntimeError::CarrierFailed(failure));
        }
        state.terminal_claim = CarrierTerminalClaim::Finalizing;
        carrier.inner.changed.notify_all();
        drop(state);
        return carrier.finish_claimed_close(artifact_path, publish);
    }
}

/// Child-after-fork policy: every inherited carrier/window is invalid, and
/// the child begins with a fresh owner gate and lifecycle routing domain.
///
/// This function uses only atomics and pointer replacement. It never locks or
/// frees a mutex that may have been owned by a vanished parent thread.
pub fn reset_after_fork_child() {
    CARRIER_PROCESS_EPOCH.fetch_add(1, Ordering::AcqRel);
    independent_carrier_gate_slot().reset_after_fork_child();
    crate::vm_lifecycle::reset_after_fork_child();
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

/// The explicit-carrier CLI exit funnel.
pub fn exit_explicit_carrier(carrier: &CarrierRuntime, status: i32) -> ! {
    let status = match carrier.shutdown_wait() {
        Ok(_) => status,
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

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// The policy fixes the carrier's `P` set AND the guest's `nproc`, so a
    /// second, different one cannot be accepted quietly: the guest may
    /// already have read `sched_getaffinity`.
    #[test]
    fn a_second_different_scheduling_policy_is_refused_not_ignored() {
        let carrier =
            CarrierRuntime::allocate(CarrierOwnerKind::Explicit, false).expect("allocate carrier");
        let four: Arc<dyn carrick_hal::SchedulingPolicy> =
            Arc::new(carrick_hal::GuestCpuPolicy::new(4));
        let two: Arc<dyn carrick_hal::SchedulingPolicy> =
            Arc::new(carrick_hal::GuestCpuPolicy::new(2));
        carrier
            .install_scheduling_policy(Arc::clone(&four))
            .expect("first install");
        // The same policy twice is the same answer, so it is idempotent.
        carrier
            .install_scheduling_policy(Arc::clone(&four))
            .expect("re-installing the same policy is idempotent");
        let error = carrier
            .install_scheduling_policy(two)
            .expect_err("a different policy must be refused");
        assert!(
            matches!(error, RuntimeError::Configuration(ref message)
                if message.contains("carrier-scoped")),
            "unexpected error: {error:?}",
        );
    }

    struct ArtifactEnvGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl ArtifactEnvGuard {
        fn install(path: &std::path::Path) -> Self {
            crate::vm_lifecycle::install_process_command_sha256("00".repeat(32))
                .expect("install test command digest");
            let values = [
                (
                    crate::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_PATH_ENV,
                    path.as_os_str().to_owned(),
                ),
                ("CARRICK_RUN_ID", std::ffi::OsString::from("carrier-test")),
                (
                    crate::vm_lifecycle::VM_LIFECYCLE_SOURCE_SHA256_ENV,
                    std::ffi::OsString::from("11".repeat(32)),
                ),
            ];
            let previous = values
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    // SAFETY: carrick-runtime tests are required to run with
                    // RUST_TEST_THREADS=1; this guard is installed before the
                    // test creates its shutdown threads, which only read it.
                    unsafe { std::env::set_var(key, value) };
                    (*key, previous)
                })
                .collect();
            Self { previous }
        }
    }

    impl Drop for ArtifactEnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.previous.drain(..).rev() {
                // SAFETY: see `ArtifactEnvGuard::install`; shutdown workers
                // are joined before the guard is dropped.
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn launch(name: &str) -> crate::kernel::container::LaunchContext {
        crate::kernel::container::LaunchContext::unmanaged(crate::kernel::container::RunId::new(
            name,
        ))
    }

    fn snapshot(carrier: &CarrierRuntime) -> CarrierSnapshot {
        carrier
            .snapshot()
            .expect("current-process carrier snapshot")
    }

    fn record_completed_vm(carrier: &CarrierRuntime) {
        for operation in [0, 1, 2, 3] {
            carrier.record_vm_lifecycle_for_test(operation, 7);
        }
        carrier.record_terminal(VmRunTerminalOutcome::RuntimeError);
    }

    fn activate_first_root(carrier: &CarrierRuntime, root: &CarrierKernelRoot) {
        if root.is_first_boot() {
            carrier
                .claim_kernel_activation(root.context.task().key())
                .expect("claim kernel activation")
                .expect("first root activation")
                .commit();
        }
    }

    #[test]
    fn concurrent_kernel_boot_publishes_one_graph_and_directory() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for (pid, name) in [(5_100, "alpha"), (5_200, "beta")] {
            let carrier = carrier.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let container = Arc::new(Container::new(launch(name)));
                let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                    pid,
                    carrick_hal::ThreadId::synthetic_for_tests(pid),
                    format!("{name}-init"),
                )
                .expect("bootstrap")
                .with_container(container);
                barrier.wait();
                let root = carrier
                    .boot_kernel_root(bootstrap, |_, _, _| Ok(()))
                    .expect("boot shared root");
                activate_first_root(&carrier, &root);
                root
            }));
        }
        let alpha = workers.remove(0).join().expect("alpha worker");
        let beta = workers.remove(0).join().expect("beta worker");
        assert!(Arc::ptr_eq(alpha.kernel(), beta.kernel()));
        assert!(Arc::ptr_eq(alpha.directory(), beta.directory()));
        assert_eq!(alpha.kernel().container_count(), 2);
        let snapshot = carrier.snapshot().expect("carrier snapshot");
        assert_eq!(snapshot.kernel_graphs, 1);
        assert_eq!(snapshot.runtime_directories, 1);
        assert_eq!(
            snapshot
                .container_inits
                .expect("container init census")
                .len(),
            2
        );
    }

    #[test]
    fn failed_first_kernel_boot_rolls_slot_back_to_vacant() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let failed_container = Arc::new(Container::new(launch("failed")));
        let failed = crate::kernel::RootBootstrap::for_reference_model(
            5_300,
            carrick_hal::ThreadId::synthetic_for_tests(5_300),
            "failed-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(failed_container);
        let error = carrier
            .boot_kernel_root(failed, |_, _, _| {
                Err(RuntimeError::Configuration(
                    "injected boot failure".to_owned(),
                ))
            })
            .expect_err("first boot must fail");
        assert!(error.to_string().contains("injected boot failure"));
        assert_eq!(carrier.snapshot().expect("after failure").kernel_graphs, 0);

        let replacement_container = Arc::new(Container::new(launch("replacement")));
        let replacement = crate::kernel::RootBootstrap::for_reference_model(
            5_400,
            carrick_hal::ThreadId::synthetic_for_tests(5_400),
            "replacement-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(replacement_container);
        let root = carrier
            .boot_kernel_root(replacement, |_, _, _| Ok(()))
            .expect("replacement boot");
        assert_eq!(carrier.snapshot().expect("prepared").kernel_graphs, 0);
        activate_first_root(&carrier, &root);
        assert_eq!(root.kernel().container_count(), 1);
        assert_eq!(carrier.snapshot().expect("ready").kernel_graphs, 1);
    }

    #[test]
    fn later_root_waits_until_first_root_activation_commits() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let first = crate::kernel::RootBootstrap::for_reference_model(
            5_410,
            carrick_hal::ThreadId::synthetic_for_tests(5_410),
            "pending-first".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("pending-first"))));
        let first = carrier
            .boot_kernel_root(first, |_, _, _| Ok(()))
            .expect("prepare first root");
        let activation = carrier
            .claim_kernel_activation(first.context.task().key())
            .expect("claim")
            .expect("pending activation");

        let waiter_carrier = carrier.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let later = crate::kernel::RootBootstrap::for_reference_model(
                5_411,
                carrick_hal::ThreadId::synthetic_for_tests(5_411),
                "waiting-later".to_owned(),
            )
            .expect("bootstrap")
            .with_container(Arc::new(Container::new(launch("waiting-later"))));
            tx.send(
                waiter_carrier
                    .boot_kernel_root(later, |_, _, _| Ok(()))
                    .map(|root| root.context.task().key()),
            )
            .expect("report waiter");
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        assert_eq!(carrier.snapshot().expect("pending").kernel_graphs, 0);
        activation.commit();
        rx.recv_timeout(std::time::Duration::from_secs(1))
            .expect("waiter released")
            .expect("later root");
        waiter.join().expect("waiter");
    }

    #[test]
    fn dropped_first_root_activation_rolls_back_and_allows_retry() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let container = Arc::new(Container::new(launch("dropped-activation")));
        let first = crate::kernel::RootBootstrap::for_reference_model(
            5_420,
            carrick_hal::ThreadId::synthetic_for_tests(5_420),
            "dropped-activation".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::clone(&container));
        let first = carrier
            .boot_kernel_root(first, |_, _, _| Ok(()))
            .expect("prepare first root");
        drop(
            carrier
                .claim_kernel_activation(first.context.task().key())
                .expect("claim")
                .expect("pending activation"),
        );
        assert_eq!(container.pid_root(), None);
        assert_eq!(carrier.snapshot().expect("rolled back").kernel_graphs, 0);

        let replacement = crate::kernel::RootBootstrap::for_reference_model(
            5_421,
            carrick_hal::ThreadId::synthetic_for_tests(5_421),
            "replacement".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("replacement"))));
        let replacement = carrier
            .boot_kernel_root(replacement, |_, _, _| Ok(()))
            .expect("retry boot");
        activate_first_root(&carrier, &replacement);
    }

    #[test]
    fn first_root_services_publish_only_inside_final_activation() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let first = crate::kernel::RootBootstrap::for_reference_model(
            5_430,
            carrick_hal::ThreadId::synthetic_for_tests(5_430),
            "service-order-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("service-order"))));
        let first = carrier
            .boot_kernel_root(first, |_, _, _| Ok(()))
            .expect("prepare first root");
        let activation = carrier
            .claim_kernel_activation(first.context.task().key())
            .expect("claim")
            .expect("first root activation");
        let published = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let expected_kernel = Arc::clone(first.kernel());
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker_published = Arc::clone(&published);
        let worker_release = Arc::clone(&release);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);

        assert!(!published.load(Ordering::Acquire));
        assert!(carrier.kernel_runtime().is_none());
        let worker = std::thread::spawn(move || {
            activation.commit_with_services(|runtime| {
                assert!(Arc::ptr_eq(runtime.kernel(), &expected_kernel));
                entered_tx.send(()).expect("service hook entered");
                worker_release.wait();
                worker_published.store(true, Ordering::Release);
            });
        });
        entered_rx.recv().expect("activation reached service hook");
        let reader_carrier = carrier.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            ready_tx
                .send(reader_carrier.kernel_runtime().is_some())
                .expect("report ready state");
        });
        assert!(
            ready_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "later roots must not observe Ready until service publication finishes"
        );
        release.wait();
        assert!(
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("ready state after service publication")
        );
        worker.join().expect("activation worker");
        reader.join().expect("ready-state reader");
        assert!(published.load(Ordering::Acquire));
        assert!(carrier.kernel_runtime().is_some());
    }

    #[test]
    fn panicking_first_kernel_boot_releases_claim_and_root_publication() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let failed_container = Arc::new(Container::new(launch("panic")));
        let failed = crate::kernel::RootBootstrap::for_reference_model(
            5_500,
            carrick_hal::ThreadId::synthetic_for_tests(5_500),
            "panic-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::clone(&failed_container));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = carrier.boot_kernel_root(failed, |_, _, _| panic!("injected boot panic"));
        }));
        assert!(panic.is_err());
        assert_eq!(failed_container.pid_root(), None);
        assert_eq!(carrier.snapshot().expect("after panic").kernel_graphs, 0);

        let replacement = crate::kernel::RootBootstrap::for_reference_model(
            5_501,
            carrick_hal::ThreadId::synthetic_for_tests(5_501),
            "replacement-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("replacement-after-panic"))));
        let root = carrier
            .boot_kernel_root(replacement, |_, _, _| Ok(()))
            .expect("boot after panic");
        activate_first_root(&carrier, &root);
    }

    #[test]
    fn duplicate_later_root_is_rejected_before_initializer_side_effects() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let base = crate::kernel::RootBootstrap::for_reference_model(
            5_600,
            carrick_hal::ThreadId::synthetic_for_tests(5_600),
            "base-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("base"))));
        let base_root = carrier
            .boot_kernel_root(base, |_, _, _| Ok(()))
            .expect("base root");
        activate_first_root(&carrier, &base_root);

        let later_container = Arc::new(Container::new(launch("later")));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let initializer_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_carrier = carrier.clone();
        let worker_container = Arc::clone(&later_container);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let worker_calls = Arc::clone(&initializer_calls);
        let worker = std::thread::spawn(move || {
            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                5_601,
                carrick_hal::ThreadId::synthetic_for_tests(5_601),
                "later-init".to_owned(),
            )
            .expect("bootstrap")
            .with_container(worker_container);
            worker_carrier.boot_kernel_root(bootstrap, |_, _, _| {
                worker_calls.fetch_add(1, Ordering::AcqRel);
                worker_entered.wait();
                worker_release.wait();
                Ok(())
            })
        });
        entered.wait();
        let duplicate = crate::kernel::RootBootstrap::for_reference_model(
            5_602,
            carrick_hal::ThreadId::synthetic_for_tests(5_602),
            "duplicate-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::clone(&later_container));
        let duplicate_error = carrier
            .boot_kernel_root(duplicate, |_, _, _| {
                initializer_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .expect_err("duplicate reservation must fail before initialize");
        assert!(duplicate_error.to_string().contains("already registered"));
        assert_eq!(initializer_calls.load(Ordering::Acquire), 1);
        release.wait();
        worker
            .join()
            .expect("later worker")
            .expect("later root commit");
    }

    #[test]
    fn later_root_publication_failure_drops_prepared_effects_and_allows_retry() {
        #[derive(Debug)]
        struct PreparedBinding(Arc<std::sync::atomic::AtomicUsize>);

        impl Drop for PreparedBinding {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }

        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let base = crate::kernel::RootBootstrap::for_reference_model(
            5_610,
            carrick_hal::ThreadId::synthetic_for_tests(5_610),
            "base-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("base"))));
        let base_root = carrier
            .boot_kernel_root(base, |_, _, _| Ok(()))
            .expect("base root");
        activate_first_root(&carrier, &base_root);

        let live_bindings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failed_container = Arc::new(Container::new(launch("failed-later")));
        let arena = Box::leak(Box::new(
            carrick_kernel::arena::KernelArena::create().expect("kernel arena"),
        ));
        failed_container
            .install_pid_ns(
                crate::namespace::pid::NsSharedRegion::allocate(arena)
                    .expect("container pid namespace"),
            )
            .expect("install container pid namespace");
        let failed = crate::kernel::RootBootstrap::for_reference_model(
            5_611,
            carrick_hal::ThreadId::synthetic_for_tests(5_611),
            "failed-later-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::clone(&failed_container));
        let error = carrier
            .boot_kernel_root_prepared(failed, |_, _, context| {
                live_bindings.fetch_add(1, Ordering::AcqRel);
                // Simulate a conflicting publication after all fallible
                // initializer work has completed but before the root commit.
                assert!(
                    context
                        .container()
                        .pid_region()
                        .expect("container pid namespace")
                        .retire()
                );
                Ok(PreparedBinding(Arc::clone(&live_bindings)))
            })
            .expect_err("later root publication must reject the invalidated pid root");
        assert!(error.to_string().contains("namespace"));
        assert_eq!(live_bindings.load(Ordering::Acquire), 0);
        assert_eq!(base_root.kernel().container_count(), 1);

        let retry = crate::kernel::RootBootstrap::for_reference_model(
            5_612,
            carrick_hal::ThreadId::synthetic_for_tests(5_612),
            "retry-later-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("retry-later"))));
        let (retry, effect) = carrier
            .boot_kernel_root_prepared(retry, |_, _, _| {
                live_bindings.fetch_add(1, Ordering::AcqRel);
                Ok(PreparedBinding(Arc::clone(&live_bindings)))
            })
            .expect("retry later root");
        assert!(!retry.is_first_boot());
        assert_eq!(retry.kernel().container_count(), 2);
        assert_eq!(live_bindings.load(Ordering::Acquire), 1);
        drop(effect);
        assert_eq!(live_bindings.load(Ordering::Acquire), 0);
    }

    #[test]
    fn later_root_post_publication_initialization_failure_retires_only_that_root() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let base = crate::kernel::RootBootstrap::for_reference_model(
            5_620,
            carrick_hal::ThreadId::synthetic_for_tests(5_620),
            "base-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch("base"))));
        let base_root = carrier
            .boot_kernel_root(base, |_, _, _| Ok(()))
            .expect("base root");
        activate_first_root(&carrier, &base_root);

        let failed_container = Arc::new(Container::new(launch("failed-post-publication")));
        let failed_id = failed_container.id();
        let failed = crate::kernel::RootBootstrap::for_reference_model(
            5_621,
            carrick_hal::ThreadId::synthetic_for_tests(5_621),
            "failed-post-publication-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::clone(&failed_container));
        let failed = carrier
            .boot_kernel_root(failed, |_, _, _| Ok(()))
            .expect("publish later root before injected initialization failure");
        assert_eq!(base_root.kernel().container_count(), 2);

        failed
            .rollback_failed_initialization()
            .expect("roll back exact later root");
        assert_eq!(base_root.kernel().container_count(), 1);
        assert!(base_root.kernel().container(failed_id).is_none());
        assert!(
            base_root
                .kernel()
                .container_init(base_root.context.container().id())
                .is_some(),
            "sibling init authority must survive the failed later initialization"
        );

        let retry = crate::kernel::RootBootstrap::for_reference_model(
            5_622,
            carrick_hal::ThreadId::synthetic_for_tests(5_622),
            "retry-after-post-publication-failure".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(Container::new(launch(
            "retry-after-post-publication-failure",
        ))));
        let retry = carrier
            .boot_kernel_root(retry, |_, _, _| Ok(()))
            .expect("retry later root after exact rollback");
        assert!(!retry.is_first_boot());
        assert_eq!(base_root.kernel().container_count(), 2);
    }

    #[test]
    fn carrier_runtime_owns_prepared_running_retired_and_close_transitions() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let alpha = carrier.reserve(launch("alpha")).expect("reserve alpha");
        let alpha_id = alpha.launch().container_id;
        assert_eq!(alpha.launch().carrier_scope_id, *carrier.scope());
        assert!(alpha.launch().run_id.as_str().ends_with("-c1"));
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Open);
        assert_eq!(snapshot(&carrier).registered_containers, 1);
        assert_eq!(snapshot(&carrier).live_containers, 0);
        assert_eq!(snapshot(&carrier).live_tasks, None);
        assert_eq!(snapshot(&carrier).live_pid_regions, None);
        assert_eq!(snapshot(&carrier).live_mounts, None);
        assert_eq!(snapshot(&carrier).live_frame_leases, None);
        assert_eq!(snapshot(&carrier).live_vcpu_leases, None);
        assert_eq!(snapshot(&carrier).live_continuations, None);
        assert_eq!(snapshot(&carrier).live_job_groups, None);
        assert_eq!(snapshot(&carrier).live_workers, Some(0));
        assert_eq!(snapshot(&carrier).container_inits, None);

        alpha.mark_running().expect("start alpha");
        assert_eq!(snapshot(&carrier).live_containers, 1);
        let alpha_container = Arc::new(Container::new(alpha.launch().clone()));
        let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
        dispatcher.set_container(Arc::clone(&alpha_container));
        let mut mounts = dispatcher.prepare_mount_retirement();
        let expected_mounts = mounts.mount_count();
        alpha
            .register_mounts(expected_mounts)
            .expect("register mount census");
        assert_eq!(snapshot(&carrier).live_mounts, Some(expected_mounts));
        drop(dispatcher);
        let mut alpha = alpha;
        let teardown = retire_leased_container(alpha_container, &mut alpha, &mut mounts)
            .expect("retire alpha");
        assert_eq!(teardown.id, alpha_id);
        assert_eq!(teardown.mounts_dropped, expected_mounts);
        assert_eq!(snapshot(&carrier).registered_containers, 0);
        assert_eq!(snapshot(&carrier).live_containers, 0);
        assert_eq!(snapshot(&carrier).live_mounts, Some(0));

        let failed_prepare = carrier.reserve(launch("failed-prepare")).expect("reserve");
        drop(failed_prepare);
        assert_eq!(snapshot(&carrier).registered_containers, 0);

        carrier.begin_close().expect("begin close");
        assert!(matches!(
            carrier.reserve(launch("closing")),
            Err(RuntimeError::CarrierClosing)
        ));
        carrier.finish_close().expect("finish close");
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Closed);
        assert!(matches!(
            carrier.reserve(launch("closed")),
            Err(RuntimeError::CarrierClosed)
        ));
    }

    #[test]
    fn explicit_carrier_owns_one_cleanup_scope_and_distinct_container_run_ids() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let alpha = carrier.reserve(launch("caller-alpha")).expect("alpha");
        let beta = carrier.reserve(launch("caller-beta")).expect("beta");

        assert_eq!(alpha.launch().carrier_scope_id, *carrier.scope());
        assert_eq!(beta.launch().carrier_scope_id, *carrier.scope());
        assert_ne!(alpha.launch().run_id, beta.launch().run_id);
        assert_eq!(
            crate::dispatch::carrier_proc_label(carrier.scope().as_str(), 2),
            format!("carrick:{}: 2 containers", carrier.scope().as_str())
        );
    }

    #[test]
    fn carrier_keeps_mount_census_live_until_mount_destruction_finishes() {
        struct BlockingDropVfs {
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
        }

        impl crate::vfs::Vfs for BlockingDropVfs {
            fn lookup(&self, _path: &str) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
                Err(crate::linux_abi::LINUX_ENOENT)
            }
        }

        impl Drop for BlockingDropVfs {
            fn drop(&mut self) {
                self.entered.wait();
                self.release.wait();
            }
        }

        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let lease = carrier
            .reserve(launch("mount-clear-barrier"))
            .expect("reserve");
        lease.mark_running().expect("start");
        let container = Arc::new(Container::new(lease.launch().clone()));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
        dispatcher.set_container(Arc::clone(&container));
        dispatcher.register_mount(
            "/retirement-barrier",
            Box::new(BlockingDropVfs {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        );
        let mut mounts = dispatcher.prepare_mount_retirement();
        let expected_mounts = mounts.mount_count();
        lease
            .register_mounts(expected_mounts)
            .expect("register mount census");
        drop(dispatcher);
        let mut lease = lease;

        let worker = std::thread::spawn(move || {
            retire_leased_container(container, &mut lease, &mut mounts).expect("retire container")
        });
        entered.wait();
        let during_clear = snapshot(&carrier);
        carrier
            .begin_close()
            .expect("begin close during mount clear");
        assert!(matches!(
            carrier.finish_close(),
            Err(RuntimeError::CarrierClosing)
        ));
        release.wait();
        let teardown = worker.join().expect("retirement worker");

        assert_eq!(during_clear.registered_containers, 1);
        assert_eq!(during_clear.live_containers, 1);
        assert_eq!(during_clear.live_mounts, Some(expected_mounts));
        assert_eq!(teardown.mounts_dropped, expected_mounts);
        assert_eq!(snapshot(&carrier).registered_containers, 0);
        assert_eq!(snapshot(&carrier).live_mounts, Some(0));
        carrier
            .finish_close()
            .expect("finish close after mount clear");
    }

    #[test]
    fn prepared_close_race_never_releases_custody_before_exact_rollback() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let lease = carrier.reserve(launch("prepared-close")).expect("reserve");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let closer_carrier = carrier.clone();
        let closer_barrier = Arc::clone(&barrier);
        let destroy_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let closer_destroy_calls = Arc::clone(&destroy_calls);
        let closer = std::thread::spawn(move || {
            closer_barrier.wait();
            shutdown_carrier_with(&closer_carrier, || {
                closer_destroy_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
        });
        barrier.wait();
        assert!(matches!(
            closer.join().expect("closer join"),
            Err(RuntimeError::CarrierClosing)
        ));
        assert_eq!(destroy_calls.load(Ordering::Acquire), 0);
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Closing);
        assert_eq!(snapshot(&carrier).registered_containers, 1);

        drop(lease);
        shutdown_carrier_with(&carrier, || {
            destroy_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .expect("retry after prepared rollback");
        assert_eq!(destroy_calls.load(Ordering::Acquire), 1);
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Closed);
    }

    #[test]
    fn concurrent_shutdown_claims_the_destructor_exactly_once() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let destroy_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let destroy_entered = Arc::new(std::sync::Barrier::new(2));
        let release_destroy = Arc::new(std::sync::Barrier::new(2));

        let first_carrier = carrier.clone();
        let first_calls = Arc::clone(&destroy_calls);
        let first_entered = Arc::clone(&destroy_entered);
        let first_release = Arc::clone(&release_destroy);
        let first = std::thread::spawn(move || {
            shutdown_carrier_with(&first_carrier, || {
                first_calls.fetch_add(1, Ordering::AcqRel);
                first_entered.wait();
                first_release.wait();
                Ok(())
            })
        });

        destroy_entered.wait();
        let waiter_entered = Arc::new(std::sync::Barrier::new(2));
        let second_carrier = carrier.clone();
        let second_calls = Arc::clone(&destroy_calls);
        let second_waiter_entered = Arc::clone(&waiter_entered);
        let second = std::thread::spawn(move || {
            shutdown_carrier_with_wait_observer(
                &second_carrier,
                || {
                    second_calls.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                || {
                    second_waiter_entered.wait();
                },
            )
        });
        waiter_entered.wait();
        release_destroy.wait();
        let first_result = first.join().expect("first closer join");
        let second_result = second.join().expect("second closer join");

        let terminal = first_result.expect("first closer terminal snapshot");
        assert_eq!(
            second_result.expect("second closer terminal snapshot"),
            terminal
        );
        assert_eq!(destroy_calls.load(Ordering::Acquire), 1);

        let repeated = shutdown_carrier_with(&carrier, || {
            destroy_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .expect("closed shutdown is idempotent");
        assert_eq!(repeated, terminal);
        assert_eq!(destroy_calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn destructor_failure_releases_claim_without_publishing_close_and_retry_succeeds() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let first_calls = std::sync::atomic::AtomicUsize::new(0);
        let first = shutdown_carrier_with(&carrier, || {
            first_calls.fetch_add(1, Ordering::AcqRel);
            Err(RuntimeError::Unsupported(
                "injected carrier destructor failure".to_owned(),
            ))
        });
        assert!(matches!(
            first,
            Err(RuntimeError::Unsupported(message))
                if message == "injected carrier destructor failure"
        ));
        assert_eq!(first_calls.load(Ordering::Acquire), 1);
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Closing);
        {
            let state = carrier.inner.state.lock();
            assert_eq!(state.terminal_claim, CarrierTerminalClaim::Unclaimed);
            assert!(state.completed_lifecycle.is_none());
        }

        let retry_calls = std::sync::atomic::AtomicUsize::new(0);
        let terminal = shutdown_carrier_with(&carrier, || {
            retry_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .expect("retry closes carrier");
        assert_eq!(retry_calls.load(Ordering::Acquire), 1);
        assert_eq!(terminal.state, CarrierAdmissionState::Closed);
        assert_eq!(snapshot(&carrier), terminal);
    }

    #[test]
    fn concurrent_public_shutdown_publishes_one_artifact_and_returns_equal_results() {
        let _serial = TEST_LOCK.lock();
        let directory = tempfile::tempdir().expect("private artifact directory");
        let artifact = directory.path().join("lifecycle.json");
        let _environment = ArtifactEnvGuard::install(&artifact);
        let carrier = process_carrier().expect("implicit carrier");
        record_completed_vm(&carrier);

        let destroy_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let publish_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let destroy_entered = Arc::new(std::sync::Barrier::new(2));
        let release_destroy = Arc::new(std::sync::Barrier::new(2));
        let first_destroy_calls = Arc::clone(&destroy_calls);
        let first_publish_calls = Arc::clone(&publish_calls);
        let first_destroy_entered = Arc::clone(&destroy_entered);
        let first_release_destroy = Arc::clone(&release_destroy);
        let first = std::thread::spawn(move || {
            shutdown_with_destroy_and_hooks(
                || {
                    first_destroy_calls.fetch_add(1, Ordering::AcqRel);
                    first_destroy_entered.wait();
                    first_release_destroy.wait();
                    Ok(())
                },
                |path, completed, scope| {
                    first_publish_calls.fetch_add(1, Ordering::AcqRel);
                    publish_completed_lifecycle(path, completed, scope)
                },
                || {},
            )
        });

        destroy_entered.wait();
        let waiter_entered = Arc::new(std::sync::Barrier::new(2));
        let second_destroy_calls = Arc::clone(&destroy_calls);
        let second_publish_calls = Arc::clone(&publish_calls);
        let second_waiter_entered = Arc::clone(&waiter_entered);
        let second = std::thread::spawn(move || {
            shutdown_with_destroy_and_hooks(
                || {
                    second_destroy_calls.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                |path, completed, scope| {
                    second_publish_calls.fetch_add(1, Ordering::AcqRel);
                    publish_completed_lifecycle(path, completed, scope)
                },
                || {
                    second_waiter_entered.wait();
                },
            )
        });
        waiter_entered.wait();
        release_destroy.wait();
        let first_result = first
            .join()
            .expect("first shutdown join")
            .map_err(|error| error.to_string());
        let second_result = second
            .join()
            .expect("second shutdown join")
            .map_err(|error| error.to_string());

        assert_eq!(first_result, second_result);
        assert_eq!(first_result, Ok(()));
        assert_eq!(destroy_calls.load(Ordering::Acquire), 1);
        assert_eq!(publish_calls.load(Ordering::Acquire), 1);
        assert!(
            !std::fs::read(&artifact)
                .expect("published artifact")
                .is_empty()
        );
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Closed);
    }

    #[test]
    fn artifact_publication_failure_is_stable_and_never_retried() {
        let _serial = TEST_LOCK.lock();
        let directory = tempfile::tempdir().expect("private artifact directory");
        let artifact = directory.path().join("occupied.json");
        std::fs::write(&artifact, b"existing evidence").expect("precreate artifact");
        let _environment = ArtifactEnvGuard::install(&artifact);
        let carrier = process_carrier().expect("implicit carrier");
        record_completed_vm(&carrier);

        let destroy_calls = std::sync::atomic::AtomicUsize::new(0);
        let publish_calls = std::sync::atomic::AtomicUsize::new(0);
        let first = shutdown_with_destroy_and_hooks(
            || {
                destroy_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
            |path, completed, scope| {
                publish_calls.fetch_add(1, Ordering::AcqRel);
                publish_completed_lifecycle(path, completed, scope)
            },
            || {},
        );
        let first_error = first
            .expect_err("no-clobber publication must fail")
            .to_string();
        assert_eq!(destroy_calls.load(Ordering::Acquire), 1);
        assert_eq!(publish_calls.load(Ordering::Acquire), 1);

        let replay = shutdown_with_destroy_and_hooks(
            || {
                destroy_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
            |path, completed, scope| {
                publish_calls.fetch_add(1, Ordering::AcqRel);
                publish_completed_lifecycle(path, completed, scope)
            },
            || {},
        );
        assert_eq!(
            replay.expect_err("publication failure replay").to_string(),
            first_error
        );
        assert_eq!(destroy_calls.load(Ordering::Acquire), 1);
        assert_eq!(publish_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            std::fs::read(&artifact).expect("existing artifact unchanged"),
            b"existing evidence"
        );
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Failed);
    }

    #[test]
    fn duplicate_reserve_preserves_prepared_owner_record() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let launch = launch("duplicate-prepared");
        let owner = carrier.reserve(launch.clone()).expect("owner reserve");
        assert!(matches!(
            carrier.reserve(launch),
            Err(RuntimeError::CarrierFailed(_))
        ));
        let failed_snapshot = snapshot(&carrier);
        assert_eq!(failed_snapshot.state, CarrierAdmissionState::Failed);
        assert_eq!(failed_snapshot.registered_containers, 1);
        assert_eq!(failed_snapshot.live_containers, 0);
        assert!(matches!(
            owner.mark_running(),
            Err(RuntimeError::CarrierFailed(_))
        ));
        drop(owner);
        assert_eq!(snapshot(&carrier).registered_containers, 0);
    }

    #[test]
    fn duplicate_reserve_preserves_running_owner_record_and_census() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let launch = launch("duplicate-running");
        let owner = carrier.reserve(launch.clone()).expect("owner reserve");
        owner.mark_running().expect("owner running");
        assert!(matches!(
            carrier.reserve(launch),
            Err(RuntimeError::CarrierFailed(_))
        ));
        let failed_snapshot = snapshot(&carrier);
        assert_eq!(failed_snapshot.state, CarrierAdmissionState::Failed);
        assert_eq!(failed_snapshot.registered_containers, 1);
        assert_eq!(failed_snapshot.live_containers, 1);
        drop(owner);
        assert_eq!(snapshot(&carrier).registered_containers, 1);
        assert_eq!(snapshot(&carrier).live_containers, 1);
    }

    #[test]
    fn independent_carrier_gate_requires_closed_generation_and_final_lease_drop() {
        let _serial = TEST_LOCK.lock();
        let first = CarrierRuntime::new_explicit().expect("first carrier");
        let clone = first.clone();
        assert_eq!(first.generation(), clone.generation());
        assert!(matches!(
            CarrierRuntime::new_explicit(),
            Err(RuntimeError::CarrierAlreadyActive)
        ));
        first.begin_close().expect("begin close");
        first.finish_close().expect("finish close");
        assert!(matches!(
            CarrierRuntime::new_explicit(),
            Err(RuntimeError::CarrierAlreadyActive)
        ));
        drop(first);
        drop(clone);

        let second = CarrierRuntime::new_explicit().expect("second carrier generation");
        assert!(second.generation() > 1);
        second.begin_close().expect("begin second close");
        second.finish_close().expect("finish second close");
        drop(second);
    }

    #[test]
    fn explicit_and_implicit_owners_never_join_ambiently() {
        let _serial = TEST_LOCK.lock();
        let explicit = CarrierRuntime::new_explicit().expect("explicit carrier");
        assert!(matches!(
            process_carrier(),
            Err(RuntimeError::ExplicitCarrierBindingRequired)
        ));
        drop(explicit);

        let implicit = process_carrier().expect("implicit carrier");
        assert!(matches!(
            CarrierRuntime::new_explicit(),
            Err(RuntimeError::CarrierAlreadyActive)
        ));
        shutdown_carrier_with(&implicit, || Ok(())).expect("close implicit");
        drop(implicit);
    }

    #[test]
    fn abandoned_and_failed_explicit_generations_release_owner_gate() {
        let _serial = TEST_LOCK.lock();
        let abandoned = CarrierRuntime::new_explicit().expect("abandoned carrier");
        drop(abandoned);
        let failed = CarrierRuntime::new_explicit().expect("replacement after abandon");
        let launch = launch("fail-generation");
        let owner = failed.reserve(launch.clone()).expect("owner reserve");
        assert!(matches!(
            failed.reserve(launch),
            Err(RuntimeError::CarrierFailed(_))
        ));
        drop(failed);
        drop(owner);

        let replacement = CarrierRuntime::new_explicit().expect("replacement after failure");
        replacement.begin_close().expect("begin close");
        replacement.finish_close().expect("finish close");
        drop(replacement);
    }

    #[test]
    fn fork_child_reset_invalidates_inherited_carrier_and_window_together() {
        let _serial = TEST_LOCK.lock();
        let inherited = CarrierRuntime::new_explicit().expect("parent carrier");
        inherited.record_vm_lifecycle_for_test(0, 7);
        reset_after_fork_child();
        assert!(matches!(
            inherited.reserve(launch("inherited")),
            Err(RuntimeError::CarrierFailed(_))
        ));
        assert!(matches!(
            inherited.snapshot(),
            Err(RuntimeError::CarrierFailed(_))
        ));

        let child = CarrierRuntime::new_explicit().expect("child carrier");
        child.record_vm_lifecycle_for_test(0, 8);
        assert_eq!(child.raw_vm_lifecycle_snapshot_for_test().events.len(), 1);
        drop(inherited);
        child.begin_close().expect("begin child close");
        assert!(matches!(
            child.reserve(launch("child-rollback")),
            Err(RuntimeError::CarrierClosing)
        ));
        // The attempted create is incomplete, but closing the carrier still
        // exercises coherent owner/window teardown without consulting the
        // inherited parent ledger.
        child.record_vm_lifecycle_for_test(1, 8);
        child.record_vm_lifecycle_for_test(2, -1);
        child.record_vm_lifecycle_for_test(3, -1);
        child.record_terminal(VmRunTerminalOutcome::RuntimeError);
        child.finish_close().expect("finish child close");
    }

    #[test]
    fn dropping_running_lease_marks_carrier_failed_without_decrementing_census() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let lease = carrier.reserve(launch("running-drop")).expect("reserve");
        lease.mark_running().expect("running");
        drop(lease);
        let snapshot = snapshot(&carrier);
        assert_eq!(snapshot.state, CarrierAdmissionState::Failed);
        assert_eq!(snapshot.registered_containers, 1);
        assert_eq!(snapshot.live_containers, 1);
        assert!(matches!(
            carrier.reserve(launch("after-failure")),
            Err(RuntimeError::CarrierFailed(_))
        ));
    }

    #[test]
    fn failed_container_retirement_retains_the_exact_running_lease_for_retry() {
        let _serial = TEST_LOCK.lock();
        let carrier = CarrierRuntime::new_for_tests().expect("carrier");
        let launch = launch("retry-retirement");
        let mut lease = carrier.reserve(launch.clone()).expect("reserve");
        let container = Arc::new(Container::new(launch));
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            5_700,
            carrick_hal::ThreadId::synthetic_for_tests(5_700),
            "retry-retirement-init".to_owned(),
        )
        .expect("bootstrap")
        .with_container(Arc::clone(&container));
        let root = carrier
            .boot_kernel_root(bootstrap, |_, _, _| Ok(()))
            .expect("root");
        activate_first_root(&carrier, &root);
        lease.mark_running().expect("running");
        let reservation = root
            .kernel()
            .reserve_fork(
                root.context(),
                crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                    .expect("fork plan"),
                "block retirement".to_owned(),
                None,
            )
            .expect("reservation");

        assert!(lease.retire(Arc::clone(&container)).is_err());
        assert_eq!(snapshot(&carrier).state, CarrierAdmissionState::Open);
        assert_eq!(snapshot(&carrier).live_containers, 1);

        drop(reservation);
        lease.retire(container).expect("retry retirement");
        assert_eq!(snapshot(&carrier).registered_containers, 1);
        assert_eq!(snapshot(&carrier).live_containers, 1);
        lease.publish_retired();
        assert_eq!(snapshot(&carrier).registered_containers, 0);
        assert_eq!(snapshot(&carrier).live_containers, 0);
    }

    fn record_complete_vm_window(carrier: &CarrierRuntime, admission: i32) {
        for operation in [0_u32, 1, 2, 3] {
            carrier.record_vm_lifecycle_for_test(operation, admission);
        }
        carrier.record_terminal(VmRunTerminalOutcome::Completed {
            exit_code: 0,
            traps: 1,
            trap_limit_hit: false,
        });
    }

    #[test]
    fn lifecycle_windows_are_generation_scoped_rebased_and_capacity_safe() {
        let _serial = TEST_LOCK.lock();
        let mut previous_last_sequence = 0;
        for generation_index in 0..(crate::vm_lifecycle::MAX_RECORDED_EVENTS_FOR_TEST / 4 + 3) {
            let carrier = CarrierRuntime::new_for_tests().expect("carrier generation");
            record_complete_vm_window(&carrier, generation_index as i32);
            let raw = carrier.raw_vm_lifecycle_snapshot_for_test();
            assert_eq!(raw.events.len(), 4);
            assert!(raw.events[0].sequence.get() > previous_last_sequence);
            previous_last_sequence = raw.events.last().expect("last event").sequence.get();
            carrier.begin_close().expect("begin close");
            let snapshot = carrier.finish_close().expect("finish close");
            assert_eq!(snapshot.vm_create_success_events, 1);
            assert_eq!(snapshot.vm_lifecycle_violations, 0);

            let completed = crate::vm_lifecycle::process_snapshot();
            assert_eq!(completed.events[0].sequence.get(), 1);
            assert_eq!(completed.events[3].sequence.get(), 4);
            assert_eq!(completed.terminal.expect("terminal").sequence.get(), 5);
            assert!(
                !completed
                    .violations
                    .contains(&crate::vm_lifecycle::VmLifecycleViolation::DuplicateRunTerminal)
            );
            assert!(
                !completed
                    .violations
                    .contains(&crate::vm_lifecycle::VmLifecycleViolation::EventCapacityExceeded)
            );
        }
    }
}
