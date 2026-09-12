//! Persistent quantum jobs, task bindings, logical job completions, and process drains.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;
use parking_lot::{Condvar, Mutex};

use crate::kernel::Scheduler;
use crate::kernel::objects::ThreadKey;

use super::next_nonzero;

static NEXT_RUNNER_JOB_ID: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuantumExit {
    Runnable,
    Blocked,
    Exited,
    Failed,
}

/// What an executor-failure settlement did with the job's logical result.
///
/// There is no "someone else will publish it later" answer. A logical job's
/// `HvpatchLoopResult` is the only thing `wait_process_jobs` can wait on, and
/// nothing bounds that wait, so a settlement that ends a job without a
/// published result strands the container forever. `AlreadyPublished` is
/// therefore a statement about the past — the process terminal owner's member
/// drain published this job before the executor failure ran — and it is
/// returnable only from a branch that observed `is_published()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutorFailureSettlement {
    PublishCurrent,
    AlreadyPublished,
}

/// Object-safe job state driven by the one authoritative Task 4 executor pool.
/// Implementations own logical runtime/continuation state only; the executor
/// argument owns the backend engine and physical vCPU for the duration of one
/// resident quantum.
pub(crate) trait PersistentQuantumJob: Send + 'static {
    fn poll_quantum_with_engine(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
    ) -> crate::vcpu_loop::executor::ExecutorExit;

    fn after_terminal_settlement(&mut self) {}

    /// See `ProductionHvpatchLoopPoll::after_reaped_settlement`.
    /// The default is the terminal publication: a job with no separate reaped
    /// story still must not end unpublished.
    fn after_reaped_settlement(&mut self) {
        self.after_terminal_settlement();
    }

    fn after_executor_failure_settlement(&mut self) -> ExecutorFailureSettlement {
        self.after_terminal_settlement();
        ExecutorFailureSettlement::PublishCurrent
    }

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        None
    }

    fn apply_detached_address_space_retirement(
        &mut self,
        _commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), crate::trap::TrapError> {
        Err(crate::trap::TrapError::Hypervisor(
            "logical job has no detached address-space retirement authority".to_owned(),
        ))
    }

    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        _commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, crate::trap::TrapError> {
        Err(crate::trap::TrapError::Hypervisor(
            "logical job has no detached address-space retirement authority".to_owned(),
        ))
    }
}

pub(crate) struct HvpatchTaskQuantum {
    job: Mutex<Box<dyn PersistentQuantumJob>>,
    completion: LogicalJobCompletion,
    _physical_retirement: PhysicalJobRetirementPublisher,
}

impl HvpatchTaskQuantum {
    pub(crate) fn new(
        job: Box<dyn PersistentQuantumJob>,
        completion: LogicalJobCompletion,
    ) -> Self {
        let physical_retirement = completion.physical_retirement_publisher();
        Self {
            job: Mutex::new(job),
            completion,
            _physical_retirement: physical_retirement,
        }
    }

    pub(crate) fn poll_quantum_with_engine<E: 'static>(
        &self,
        engine: &mut E,
        control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
    ) -> crate::vcpu_loop::executor::ExecutorExit {
        self.job.lock().poll_quantum_with_engine(engine, control)
    }

    pub(crate) fn after_terminal_settlement(&self) {
        self.job.lock().after_terminal_settlement();
        self.completion.publish();
    }

    pub(crate) fn after_reaped_settlement(&self) {
        self.job.lock().after_reaped_settlement();
        self.completion.publish();
    }

    pub(crate) fn after_executor_failure_settlement(&self) {
        match self.job.lock().after_executor_failure_settlement() {
            ExecutorFailureSettlement::PublishCurrent => self.completion.publish(),
            // Fail closed on the one shape that cannot be recovered later: an
            // unpublished job whose executor is gone has no remaining
            // publisher, and its container job wait would never return.
            ExecutorFailureSettlement::AlreadyPublished => {
                if !self.completion.is_finished() {
                    tracing::error!(
                        job = self.completion.id().raw(),
                        "executor-failure settlement claimed a prior publication that never happened"
                    );
                    self.completion.publish();
                }
            }
        }
    }

    pub(crate) fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.job.lock().take_address_space_retirement()
    }

    pub(crate) fn apply_detached_address_space_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), crate::trap::TrapError> {
        self.job
            .lock()
            .apply_detached_address_space_retirement(commit)
    }

    pub(crate) fn apply_detached_address_space_retirement_with_receipt(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, crate::trap::TrapError> {
        self.job
            .lock()
            .apply_detached_address_space_retirement_with_receipt(commit)
    }
}

pub(crate) struct HvpatchTaskBinding {
    identity: crate::vcpu_loop::executor::TaskLoadIdentity,
    backend: Mutex<Option<Box<dyn std::any::Any + Send>>>,
    stage1_mm: Option<Arc<crate::hvpatch::Stage1MmLease>>,
    terminal_generation: Mutex<HvpatchBindingTerminalGeneration>,
    // Last by construction: the quantum's drop receipt may become visible
    // only after every other final-binding authority has been released.
    quantum: Arc<HvpatchTaskQuantum>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvpatchBindingTerminalGeneration {
    Active,
    ExecTransferred,
    Settled,
}

impl HvpatchTaskBinding {
    #[cfg(test)]
    pub(crate) fn new(
        identity: crate::vcpu_loop::executor::TaskLoadIdentity,
        quantum: Arc<HvpatchTaskQuantum>,
        backend: Box<dyn std::any::Any + Send>,
    ) -> Self {
        Self {
            identity,
            quantum,
            backend: Mutex::new(Some(backend)),
            stage1_mm: None,
            terminal_generation: Mutex::new(HvpatchBindingTerminalGeneration::Active),
        }
    }

    pub(crate) fn new_with_stage1_mm(
        identity: crate::vcpu_loop::executor::TaskLoadIdentity,
        quantum: Arc<HvpatchTaskQuantum>,
        backend: Box<dyn std::any::Any + Send>,
        stage1_mm: Arc<crate::hvpatch::Stage1MmLease>,
    ) -> Result<Self, crate::trap::TrapError> {
        if identity.asid_generation != stage1_mm.asid_generation().generation() {
            return Err(crate::trap::TrapError::Hypervisor(
                "HVPatch task binding rejected mismatched strong ASID generation".to_owned(),
            ));
        }
        Ok(Self {
            identity,
            quantum,
            backend: Mutex::new(Some(backend)),
            stage1_mm: Some(stage1_mm),
            terminal_generation: Mutex::new(HvpatchBindingTerminalGeneration::Active),
        })
    }

    pub(crate) const fn identity(&self) -> crate::vcpu_loop::executor::TaskLoadIdentity {
        self.identity
    }

    #[cfg(test)]
    pub(crate) fn replacement(
        &self,
        identity: crate::vcpu_loop::executor::TaskLoadIdentity,
    ) -> Self {
        Self {
            identity,
            quantum: Arc::clone(&self.quantum),
            backend: Mutex::new(None),
            stage1_mm: self.stage1_mm.clone(),
            terminal_generation: Mutex::new(HvpatchBindingTerminalGeneration::Active),
        }
    }

    pub(crate) fn replacement_with_stage1_mm(
        &self,
        identity: crate::vcpu_loop::executor::TaskLoadIdentity,
        stage1_mm: Arc<crate::hvpatch::Stage1MmLease>,
    ) -> Result<Self, crate::trap::TrapError> {
        if identity.asid_generation != stage1_mm.asid_generation().generation() {
            return Err(crate::trap::TrapError::Hypervisor(
                "HVPatch exec binding rejected replacement ASID generation".to_owned(),
            ));
        }
        Ok(Self {
            identity,
            quantum: Arc::clone(&self.quantum),
            backend: Mutex::new(None),
            stage1_mm: Some(stage1_mm),
            terminal_generation: Mutex::new(HvpatchBindingTerminalGeneration::Active),
        })
    }

    /// Whether this binding's address space has stopped admitting loads.
    ///
    /// Asked AFTER a rejected load to classify it: a rejection here means some
    /// other thread's `execve` or exit is retiring this address space, which
    /// on Linux terminates this thread -- an ordinary outcome, not a failure of
    /// the executor that tried to run it. The generation only moves forward
    /// (Live -> RetirementPrepared -> Retired), so a `true` answer after the
    /// rejection is sound: it was already retiring when the load was refused.
    pub(crate) fn address_space_is_retiring(&self) -> bool {
        self.stage1_mm
            .as_ref()
            .is_none_or(|stage1_mm| stage1_mm.is_retiring())
    }

    pub(crate) fn begin_asid_load(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<crate::hvpatch::AsidLoad, crate::trap::TrapError> {
        let stage1_mm = self.stage1_mm.as_ref().ok_or_else(|| {
            crate::trap::TrapError::Hypervisor(
                "HVPatch task binding has no strong stage-1/ASID lease".to_owned(),
            )
        })?;
        if self.identity.asid_generation != stage1_mm.asid_generation().generation() {
            return Err(crate::trap::TrapError::Hypervisor(
                "HVPatch task binding strong ASID generation drifted".to_owned(),
            ));
        }
        stage1_mm.begin_asid_load(executor).map_err(|error| {
            crate::trap::TrapError::Hypervisor(format!("HVPatch ASID load rejected: {error}"))
        })
    }

    pub(crate) fn service_pending_cow_invalidation<E>(
        &self,
        observer: &crate::hvpatch::CowInvalidationObserver,
        invalidate: impl FnOnce(crate::hvpatch::AsidGeneration) -> Result<(), E>,
    ) -> Result<(), E> {
        self.stage1_mm
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "HvpatchTaskBinding missing stage-1 MM lease when servicing pending COW invalidations: mm={:?}",
                    self.identity.mm
                );
            })
            .service_pending_cow_invalidation(observer, invalidate)
    }

    pub(crate) fn cow_invalidation_observer(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> crate::hvpatch::CowInvalidationObserver {
        self.stage1_mm
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "HvpatchTaskBinding missing stage-1 MM lease when obtaining COW invalidation observer: mm={:?}, executor={:?}",
                    self.identity.mm,
                    executor
                );
            })
            .cow_invalidation_observer(executor)
    }

    pub(crate) fn foreign_stage1_identity(&self) -> carrick_hal::ForeignStage1Identity {
        self.stage1_mm
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "HvpatchTaskBinding missing stage-1 MM lease when extracting foreign stage-1 identity: mm={:?}",
                    self.identity.mm
                );
            })
            .foreign_stage1_identity(self.identity.mm)
    }

    pub(crate) fn pending_cow_invalidation(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Option<crate::hvpatch::CowInvalidationTicket> {
        self.stage1_mm.as_ref()?.pending_cow_invalidation(executor)
    }

    pub(crate) fn acknowledge_cow_invalidation(
        &self,
        executor: crate::kernel::objects::ExecutorId,
        ticket: crate::hvpatch::CowInvalidationTicket,
    ) -> Result<(), crate::hvpatch::CowInvalidationError> {
        self.stage1_mm
            .as_ref()
            .ok_or(crate::hvpatch::CowInvalidationError::StaleGeneration)?
            .acknowledge_cow_invalidation(executor, ticket)
    }

    pub(crate) fn validate_state(
        &self,
        state: &crate::kernel::objects::MigratableTaskState,
    ) -> Result<(), crate::trap::TrapError> {
        if self.identity.mm != state.mm
            || self.identity.asid_generation != state.asid_generation
            || self.identity.abi != state.cpu.guest_abi()
            || self.identity.version != state.cpu.version()
        {
            return Err(crate::trap::TrapError::Hypervisor(
                "HVPatch task binding rejected stale MM/ASID generation".to_owned(),
            ));
        }
        if let (Some(stage1_mm), carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu)) =
            (&self.stage1_mm, &state.cpu)
        {
            let expected = stage1_mm.binding().ttbr0.raw();
            if cpu.ttbr0 != expected || cpu.ttbr1 != expected {
                return Err(crate::trap::TrapError::Hypervisor(format!(
                    "HVPatch task binding rejected CPU TTBR pair 0x{:x}/0x{:x}; expected 0x{expected:x}",
                    cpu.ttbr0, cpu.ttbr1
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn quantum(&self) -> &Arc<HvpatchTaskQuantum> {
        &self.quantum
    }

    pub(crate) fn after_terminal_settlement(&self) {
        let publish_logical_result = {
            let mut generation = self.terminal_generation.lock();
            match *generation {
                HvpatchBindingTerminalGeneration::Active => {
                    *generation = HvpatchBindingTerminalGeneration::Settled;
                    true
                }
                HvpatchBindingTerminalGeneration::ExecTransferred => {
                    *generation = HvpatchBindingTerminalGeneration::Settled;
                    crate::event_ring::rec_hvpatch_settle_step(0, self.identity.mm.raw(), 6);
                    false
                }
                HvpatchBindingTerminalGeneration::Settled => {
                    crate::event_ring::rec_hvpatch_settle_step(0, self.identity.mm.raw(), 7);
                    return;
                }
            }
        };
        if publish_logical_result {
            crate::event_ring::rec_hvpatch_settle_step(0, self.identity.mm.raw(), 5);
            self.quantum.after_terminal_settlement();
        }
    }

    /// The reaped-settlement twin of [`Self::after_terminal_settlement`],
    /// sharing its one-shot gate: an exec-transferred binding still must not
    /// publish over its successor's result, and a binding already settled
    /// stays settled.
    pub(crate) fn after_reaped_settlement(&self) {
        let publish_logical_result = {
            let mut generation = self.terminal_generation.lock();
            match *generation {
                HvpatchBindingTerminalGeneration::Active => {
                    *generation = HvpatchBindingTerminalGeneration::Settled;
                    true
                }
                HvpatchBindingTerminalGeneration::ExecTransferred => {
                    *generation = HvpatchBindingTerminalGeneration::Settled;
                    false
                }
                HvpatchBindingTerminalGeneration::Settled => return,
            }
        };
        if publish_logical_result {
            self.quantum.after_reaped_settlement();
        }
    }

    pub(crate) fn after_executor_failure_settlement(&self) {
        let publish_logical_result = {
            let mut generation = self.terminal_generation.lock();
            match *generation {
                HvpatchBindingTerminalGeneration::Active => {
                    *generation = HvpatchBindingTerminalGeneration::Settled;
                    true
                }
                HvpatchBindingTerminalGeneration::ExecTransferred => {
                    *generation = HvpatchBindingTerminalGeneration::Settled;
                    false
                }
                HvpatchBindingTerminalGeneration::Settled => return,
            }
        };
        if publish_logical_result {
            self.quantum.after_executor_failure_settlement();
        }
    }

    pub(crate) fn mark_exec_transferred(&self) -> Result<(), crate::trap::TrapError> {
        let mut generation = self.terminal_generation.lock();
        if *generation != HvpatchBindingTerminalGeneration::Active {
            return Err(crate::trap::TrapError::Hypervisor(
                "exec predecessor binding terminal role was already consumed".to_owned(),
            ));
        }
        *generation = HvpatchBindingTerminalGeneration::ExecTransferred;
        Ok(())
    }

    pub(crate) fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.quantum.take_address_space_retirement()
    }

    pub(crate) fn retire_detached_address_space(
        &self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, crate::trap::TrapError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let backend = self.backend.lock().take().ok_or_else(|| {
                crate::trap::TrapError::Hypervisor(
                    "detached address-space cleanup has no saved backend".to_owned(),
                )
            })?;
            let mut backend = backend
                .downcast::<crate::vcpu_loop::executor::HvpatchTaskEngineBindingState>()
                .map_err(|_| {
                    crate::trap::TrapError::Hypervisor(
                        "detached address-space cleanup backend type mismatch".to_owned(),
                    )
                })?;
            // Report a retirement failure BEFORE `backend` drops. Dropping it
            // runs `HvpatchTaskMmAuthority::drop`, which finds the inventory
            // still `Active` and aborts the carrier with the generic
            // "published HVPatch inventory dropped before exact retirement" —
            // masking the error that actually caused it. The abort is correct
            // (a published inventory must never leak), but for months it was
            // the only thing an operator saw.
            let retired = backend.retire_detached_address_space_with(
                root_ticket,
                |commit| {
                    self.quantum
                        .apply_detached_address_space_retirement_with_receipt(commit)
                },
                |commit| self.quantum.apply_detached_address_space_retirement(commit),
            );
            if let Err(error) = &retired {
                eprintln!(
                    "carrick: FATAL: detached address-space retirement failed \
                     (the MM-authority drop abort that follows is a CONSEQUENCE of \
                     this, not the cause): {error}"
                );
            }
            let root_receipt = retired?;
            drop(backend);
            Ok(root_receipt)
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        Err(crate::trap::TrapError::Hypervisor(
            "detached HVPatch cleanup requires macOS/aarch64 HVF".to_owned(),
        ))
    }

    pub(crate) fn cancel_dormant_backend(&self) -> Result<(), crate::trap::TrapError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            if let Some(backend) = self.backend.lock().as_mut() {
                if let Some(backend) = backend
                    .downcast_mut::<crate::vcpu_loop::executor::HvpatchTaskEngineBindingState>(
                ) {
                    backend.cancel_dormant()?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn retire_detached_shared_mm_edge(&self) -> Result<(), crate::trap::TrapError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let backend = self.backend.lock().take().ok_or_else(|| {
                crate::trap::TrapError::Hypervisor(
                    "shared-MM edge cleanup has no saved backend".to_owned(),
                )
            })?;
            backend
                .downcast::<crate::vcpu_loop::executor::HvpatchTaskEngineBindingState>()
                .map_err(|_| {
                    crate::trap::TrapError::Hypervisor(
                        "shared-MM edge cleanup backend type mismatch".to_owned(),
                    )
                })?;
            Ok(())
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        Err(crate::trap::TrapError::Hypervisor(
            "detached HVPatch cleanup requires macOS/aarch64 HVF".to_owned(),
        ))
    }

    pub(crate) fn retire_detached_exec_predecessor(
        &self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, crate::trap::TrapError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let mut slot = self.backend.lock();
            let backend = slot.as_mut().ok_or_else(|| {
                crate::trap::TrapError::Hypervisor(
                    "detached exec cleanup has no saved successor backend".to_owned(),
                )
            })?;
            let backend = backend
                .downcast_mut::<crate::vcpu_loop::executor::HvpatchTaskEngineBindingState>()
                .ok_or_else(|| {
                    crate::trap::TrapError::Hypervisor(
                        "detached exec cleanup backend type mismatch".to_owned(),
                    )
                })?;
            backend.retire_detached_exec_predecessor(root_ticket)
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        Err(crate::trap::TrapError::Hypervisor(
            "detached HVPatch exec cleanup requires macOS/aarch64 HVF".to_owned(),
        ))
    }

    pub(crate) fn take_backend<T: Send + 'static>(&self) -> Result<T, crate::trap::TrapError> {
        Ok(*(self
            .backend
            .lock()
            .take()
            .ok_or_else(|| {
                crate::trap::TrapError::Hypervisor("task binding already loaded".into())
            })?
            .downcast::<T>()
            .map_err(|_| {
                crate::trap::TrapError::Hypervisor("task binding backend type mismatch".into())
            })?))
    }

    pub(crate) fn inspect_backend<T: Send + 'static, R>(
        &self,
        inspect: impl FnOnce(&T) -> Result<R, crate::trap::TrapError>,
    ) -> Result<R, crate::trap::TrapError> {
        let slot = self.backend.lock();
        let backend = slot.as_ref().ok_or_else(|| {
            crate::trap::TrapError::Hypervisor("task binding already loaded".into())
        })?;
        let backend = backend.downcast_ref::<T>().ok_or_else(|| {
            crate::trap::TrapError::Hypervisor("task binding backend type mismatch".into())
        })?;
        inspect(backend)
    }

    pub(crate) fn put_backend<T: Send + 'static>(
        &self,
        backend: T,
    ) -> Result<(), crate::trap::TrapError> {
        let mut slot = self.backend.lock();
        if slot.is_some() {
            return Err(crate::trap::TrapError::Hypervisor(
                "task binding backend already present".into(),
            ));
        }
        *slot = Some(Box::new(backend));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId(u64);

impl JobId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

type JobCompletionCallback = Arc<dyn Fn(JobId) + Send + Sync + 'static>;

struct JobCompletionState {
    done: AtomicBool,
    physically_retired: Mutex<bool>,
    physical_retirement_changed: Condvar,
    next_listener: AtomicU64,
    listeners: Mutex<BTreeMap<u64, JobCompletionCallback>>,
}

#[derive(Clone)]
pub struct LogicalJobCompletion {
    id: JobId,
    state: Arc<JobCompletionState>,
}

impl std::fmt::Debug for LogicalJobCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogicalJobCompletion")
            .field("id", &self.id)
            .field("done", &self.is_finished())
            .finish()
    }
}

impl LogicalJobCompletion {
    pub(crate) fn pending() -> Self {
        Self {
            id: JobId(next_nonzero(&NEXT_RUNNER_JOB_ID)),
            state: Arc::new(JobCompletionState {
                done: AtomicBool::new(false),
                physically_retired: Mutex::new(false),
                physical_retirement_changed: Condvar::new(),
                next_listener: AtomicU64::new(1),
                listeners: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    pub const fn id(&self) -> JobId {
        self.id
    }

    pub fn is_finished(&self) -> bool {
        self.state.done.load(Ordering::Acquire)
    }

    pub(crate) fn publish(&self) {
        if self.state.done.swap(true, Ordering::AcqRel) {
            return;
        }
        let callbacks = std::mem::take(&mut *self.state.listeners.lock())
            .into_values()
            .collect::<Vec<_>>();
        for callback in callbacks {
            callback(self.id);
        }
    }

    /// Wait until the executor has released the final binding that owned this
    /// job's kernel graph. Logical result publication deliberately precedes
    /// that release, so container teardown must observe this distinct phase.
    pub(crate) fn wait_for_physical_retirement(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut retired = self.state.physically_retired.lock();
        while !*retired {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            if self
                .state
                .physical_retirement_changed
                .wait_for(&mut retired, remaining)
                .timed_out()
                && !*retired
            {
                return false;
            }
        }
        true
    }

    fn physical_retirement_publisher(&self) -> PhysicalJobRetirementPublisher {
        PhysicalJobRetirementPublisher {
            completion: self.clone(),
        }
    }

    fn publish_physical_retirement(&self) {
        let mut retired = self.state.physically_retired.lock();
        if *retired {
            return;
        }
        *retired = true;
        self.state.physical_retirement_changed.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn publish_physical_retirement_for_test(&self) {
        self.publish_physical_retirement();
    }

    fn subscribe(&self, callback: JobCompletionCallback) -> Option<JobCompletionSubscription> {
        let mut listeners = self.state.listeners.lock();
        if self.is_finished() {
            return None;
        }
        let listener = next_nonzero(&self.state.next_listener);
        listeners.insert(listener, callback);
        Some(JobCompletionSubscription {
            completion: self.clone(),
            listener,
        })
    }
}

/// Drop-only publication guard placed after the quantum's job field. Rust
/// drops struct fields in declaration order, so this receipt becomes visible
/// only after the job (and its Kernel/VFS ownership) has been destroyed.
struct PhysicalJobRetirementPublisher {
    completion: LogicalJobCompletion,
}

impl Drop for PhysicalJobRetirementPublisher {
    fn drop(&mut self) {
        self.completion.publish_physical_retirement();
    }
}

struct JobCompletionSubscription {
    completion: LogicalJobCompletion,
    listener: u64,
}

impl Drop for JobCompletionSubscription {
    fn drop(&mut self) {
        self.completion
            .state
            .listeners
            .lock()
            .remove(&self.listener);
    }
}

struct ProcessDrainState {
    remaining: AtomicUsize,
    waker: Mutex<Option<Waker>>,
    scheduler_wake: Option<(Weak<Scheduler>, ThreadKey)>,
}

pub struct ProcessDrain {
    state: Arc<ProcessDrainState>,
    _subscriptions: Vec<JobCompletionSubscription>,
}

impl ProcessDrain {
    pub fn excluding(current: LogicalJobCompletion, jobs: Vec<LogicalJobCompletion>) -> Self {
        let pending = jobs
            .into_iter()
            .filter(|job| job.id() != current.id() && !job.is_finished())
            .collect::<Vec<_>>();
        let state = Arc::new(ProcessDrainState {
            remaining: AtomicUsize::new(pending.len()),
            waker: Mutex::new(None),
            scheduler_wake: None,
        });
        let mut subscriptions = Vec::with_capacity(pending.len());
        for job in pending {
            let callback_state = Arc::clone(&state);
            match job.subscribe(Arc::new(move |_| {
                let previous = callback_state.remaining.fetch_sub(1, Ordering::AcqRel);
                if previous == 0 {
                    carrick_fatal!(
                        "vcpu_loop::process_drain",
                        "underflow in job completion subscription count indicates double-completion"
                    );
                }
                let waker = if previous == 1 {
                    callback_state.waker.lock().take()
                } else {
                    None
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
                if previous == 1
                    && let Some((scheduler, thread)) = &callback_state.scheduler_wake
                    && let Some(scheduler) = scheduler.upgrade()
                {
                    let _ = scheduler.wake(*thread);
                }
            })) {
                Some(subscription) => subscriptions.push(subscription),
                None => {
                    state.remaining.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
        Self {
            state,
            _subscriptions: subscriptions,
        }
    }

    /// Persistent-executor sibling drain. Completion is durable and wakes the
    /// exact Kernel thread through the one scheduler; the job retains only
    /// logical completion subscriptions and never an engine or worker handle.
    pub(crate) fn for_scheduler(
        thread: ThreadKey,
        scheduler: &Arc<Scheduler>,
        current: JobId,
        jobs: Vec<LogicalJobCompletion>,
    ) -> Self {
        let pending = jobs
            .into_iter()
            .filter(|job| job.id() != current && !job.is_finished())
            .collect::<Vec<_>>();
        let state = Arc::new(ProcessDrainState {
            remaining: AtomicUsize::new(pending.len()),
            waker: Mutex::new(None),
            scheduler_wake: Some((Arc::downgrade(scheduler), thread)),
        });
        let mut subscriptions = Vec::with_capacity(pending.len());
        for job in pending {
            let callback_state = Arc::clone(&state);
            match job.subscribe(Arc::new(move |_| {
                let previous = callback_state.remaining.fetch_sub(1, Ordering::AcqRel);
                if previous == 0 {
                    carrick_fatal!(
                        "vcpu_loop::process_drain",
                        "underflow in scheduler job completion subscription count indicates double-completion"
                    );
                }
                if previous == 1
                    && let Some((scheduler, thread)) = &callback_state.scheduler_wake
                    && let Some(scheduler) = scheduler.upgrade()
                {
                    let _ = scheduler.wake(*thread);
                }
            })) {
                Some(subscription) => subscriptions.push(subscription),
                None => {
                    state.remaining.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
        Self {
            state,
            _subscriptions: subscriptions,
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.state.remaining.load(Ordering::Acquire) == 0
    }

    /// Member jobs this drain is still waiting on.
    pub(crate) fn remaining(&self) -> usize {
        self.state.remaining.load(Ordering::Acquire)
    }
}

impl Future for ProcessDrain {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.state.remaining.load(Ordering::Acquire) == 0 {
            return Poll::Ready(());
        }
        let incoming_waker = context.waker().clone();
        let displaced_waker = {
            let mut waker = self.state.waker.lock();
            waker.replace(incoming_waker)
        };
        drop(displaced_waker);
        if self.state.remaining.load(Ordering::Acquire) == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use carrick_hal::threaded::GuestCpuState;

    use crate::kernel::Scheduler;

    use super::super::tests::bootstrap;
    use super::*;
    #[test]
    fn hvpatch_persistent_quantum_and_binding_exclude_executor_authority() {
        fn assert_send<T: Send>() {}
        assert_send::<HvpatchTaskQuantum>();
        assert_send::<HvpatchTaskBinding>();

        let source = include_str!("quantum.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production continuation source");
        let quantum = source
            .split_once("pub(crate) struct HvpatchTaskQuantum")
            .expect("persistent HVPatch quantum job")
            .1
            .split_once('}')
            .expect("quantum job body")
            .0;
        let binding = source
            .split_once("pub(crate) struct HvpatchTaskBinding")
            .expect("no-vCPU HVPatch task binding")
            .1
            .split_once('}')
            .expect("task binding body")
            .0;
        for prohibited in [
            "ThreadedEngine",
            "HvfAarch64Engine",
            "Vcpu",
            "Mailbox",
            "ThreadId",
            "VcpuKick",
        ] {
            assert!(
                !quantum.contains(prohibited),
                "quantum retained {prohibited}"
            );
            assert!(
                !binding.contains(prohibited),
                "binding retained {prohibited}"
            );
        }
    }

    #[test]
    fn hvpatch_loop_job_is_send_and_contains_only_logical_state() {
        fn assert_send<T: Send>() {}
        fn assert_persistent_job<T: PersistentQuantumJob>() {}
        assert_send::<crate::vcpu_loop::HvpatchLoopJob<FakeInjectedLoopEngine>>();
        assert_persistent_job::<crate::vcpu_loop::HvpatchLoopJob<FakeInjectedLoopEngine>>();
        assert_send::<crate::vcpu_loop::quiesce::PreparedVforkSuspension>();
        assert_send::<crate::vcpu_loop::ExecCloneAdmission>();
        assert_send::<crate::vcpu_loop::exec::PreparedExecve>();

        let source = include_str!("../binding.rs")
            .split_once("struct HvpatchLoopJob")
            .expect("real HVPatch loop job")
            .1
            .split_once('}')
            .expect("HVPatch loop job body")
            .0;
        for prohibited in [
            "engine:",
            "OwnerThreadEngine",
            "Box<E>",
            "Option<E>",
            "HvfAarch64Engine",
            "Vcpu",
        ] {
            assert!(
                !source.contains(prohibited),
                "HVPatch loop job retained executor authority {prohibited}"
            );
        }
    }

    #[derive(Default)]
    struct FakeInjectedLoopEngine {
        resumes: Vec<crate::vcpu_loop::HvpatchLoopSuspension>,
    }

    impl crate::vcpu_loop::ScriptedHvpatchLoopEngine for FakeInjectedLoopEngine {
        fn record_injected_resume(&mut self, resumed: &[crate::vcpu_loop::HvpatchLoopSuspension]) {
            self.resumes.clear();
            self.resumes.extend_from_slice(resumed);
        }
    }

    #[test]
    fn fake_engine_resumes_across_all_seven_hvpatch_loop_suspensions() {
        use crate::vcpu_loop::{HvpatchLoopJob, HvpatchLoopPoll, HvpatchLoopSuspension};

        let expected = [
            HvpatchLoopSuspension::InitialAdmission,
            HvpatchLoopSuspension::BlockedContinuation,
            HvpatchLoopSuspension::SchedulerYield,
            HvpatchLoopSuspension::ExecSiblingDrain,
            HvpatchLoopSuspension::VforkParent,
            HvpatchLoopSuspension::Preemption,
            HvpatchLoopSuspension::TerminalSiblingDrain,
        ];
        let mut job = HvpatchLoopJob::<FakeInjectedLoopEngine>::scripted_for_test(expected);

        for (index, boundary) in expected.into_iter().enumerate() {
            let mut engine = FakeInjectedLoopEngine::default();
            assert_eq!(
                job.poll_quantum_with_engine(&mut engine, false),
                HvpatchLoopPoll::Suspended(boundary)
            );
            assert_eq!(engine.resumes, expected[..=index]);
            assert_eq!(
                job.suspended_at(),
                Some(boundary),
                "logical suspension must survive after the injected engine is dropped"
            );
        }

        let mut terminal_engine = FakeInjectedLoopEngine::default();
        assert_eq!(
            job.poll_quantum_with_engine(&mut terminal_engine, false),
            HvpatchLoopPoll::Exited
        );
        assert_eq!(terminal_engine.resumes, expected);
    }

    #[test]
    fn task4_quantum_drives_the_real_hvpatch_job_across_all_seven_boundaries() {
        use crate::kernel::Scheduler;
        use crate::vcpu_loop::executor::{
            ExecutorExit, ExecutorSubmissionContext, HvpatchQuantumControl,
        };
        use crate::vcpu_loop::{HvpatchLoopJob, HvpatchLoopSuspension};

        let boundaries = [
            HvpatchLoopSuspension::InitialAdmission,
            HvpatchLoopSuspension::BlockedContinuation,
            HvpatchLoopSuspension::SchedulerYield,
            HvpatchLoopSuspension::ExecSiblingDrain,
            HvpatchLoopSuspension::VforkParent,
            HvpatchLoopSuspension::Preemption,
            HvpatchLoopSuspension::TerminalSiblingDrain,
        ];
        let expected = [
            ExecutorExit::Quiesced,
            ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::HostWait),
            ExecutorExit::Yielded,
            ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
            ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
            ExecutorExit::Preempted,
            ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
        ];
        let completion = LogicalJobCompletion::pending();
        let quantum = HvpatchTaskQuantum::new(
            Box::new(HvpatchLoopJob::<FakeInjectedLoopEngine>::scripted_for_test(
                boundaries,
            )),
            completion.clone(),
        );
        let (kernel, _) = bootstrap(15_473);
        let scheduler = Scheduler::new(kernel);
        let reject_descendant = |_, _| {
            Err(crate::trap::TrapError::Hypervisor(
                "seven-boundary test publishes no descendants".to_owned(),
            ))
        };
        let mut submission = ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &reject_descendant,
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let need_resched = AtomicBool::new(false);
        let mut control = HvpatchQuantumControl::for_test(&need_resched, &mut submission);

        for expected in expected {
            let mut engine = FakeInjectedLoopEngine::default();
            let exit = quantum.poll_quantum_with_engine(&mut engine, &mut control);
            assert_eq!(
                std::mem::discriminant(&exit),
                std::mem::discriminant(&expected)
            );
        }
        let mut engine = FakeInjectedLoopEngine::default();
        assert!(matches!(
            quantum.poll_quantum_with_engine(&mut engine, &mut control),
            ExecutorExit::Exited
        ));
        quantum.after_terminal_settlement();
        assert!(completion.is_finished());
    }

    #[test]
    fn exec_predecessor_binding_settlement_never_completes_successor_logical_job() {
        let (_kernel, context) = bootstrap(15_474);
        let state = crate::vcpu_loop::executor::tests::task_state(&context, 474);
        let predecessor =
            crate::vcpu_loop::executor::tests::hvpatch_test_binding(&context, &state, 474);
        let completion = predecessor.quantum().completion.clone();
        let successor = predecessor.replacement(predecessor.identity());

        predecessor.mark_exec_transferred().unwrap();
        predecessor.after_terminal_settlement();
        assert!(
            !completion.is_finished(),
            "exec predecessor retirement must not complete the shared logical job"
        );
        successor.after_terminal_settlement();
        assert!(completion.is_finished());
    }

    #[test]
    fn hvpatch_binding_rejects_aarch64_cpu_ttbr_drift_with_matching_generations() {
        struct ExitJob;

        impl PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
            ) -> crate::vcpu_loop::executor::ExecutorExit {
                crate::vcpu_loop::executor::ExecutorExit::Exited
            }
        }

        let (_kernel, context) = bootstrap(15_475);
        let mut state = crate::vcpu_loop::executor::tests::task_state(&context, 475);
        let (_pool, stage1_mm) = crate::hvpatch::Stage1MmPool::new_root_for_tests(0x8000, 2)
            .expect("stage-1 test lease");
        let asid_generation = stage1_mm.asid_generation().generation();
        let expected_ttbr = stage1_mm.binding().ttbr0.raw();
        let GuestCpuState::Aarch64V1(cpu) = &state.cpu else {
            panic!("test state must be AArch64");
        };
        let mut cpu = (**cpu).clone();
        cpu.ttbr0 = expected_ttbr;
        cpu.ttbr1 = expected_ttbr;
        cpu.asid_generation = asid_generation;
        state.cpu = GuestCpuState::from_aarch64_v1(cpu.clone());
        state.asid_generation = asid_generation;

        let binding = HvpatchTaskBinding::new_with_stage1_mm(
            crate::vcpu_loop::executor::TaskLoadIdentity {
                abi: state.cpu.guest_abi(),
                version: state.cpu.version(),
                mm: state.mm,
                asid_generation,
            },
            Arc::new(HvpatchTaskQuantum::new(
                Box::new(ExitJob),
                LogicalJobCompletion::pending(),
            )),
            Box::new(()),
            Arc::clone(&stage1_mm),
        )
        .expect("exact HVPatch binding");
        binding.validate_state(&state).expect("exact TTBR pair");

        cpu.ttbr1 ^= 0x1000;
        state.cpu = GuestCpuState::from_aarch64_v1(cpu);
        let error = binding
            .validate_state(&state)
            .expect_err("matching generations cannot authorize a stale TTBR");
        assert!(error.to_string().contains("CPU TTBR pair"));
    }

    #[test]
    fn physical_retirement_waits_for_every_final_binding_field() {
        struct ExitJob;
        impl PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
            ) -> crate::vcpu_loop::executor::ExecutorExit {
                crate::vcpu_loop::executor::ExecutorExit::Exited
            }
        }
        struct BlockingBackendDrop {
            entered: std::sync::mpsc::SyncSender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Drop for BlockingBackendDrop {
            fn drop(&mut self) {
                self.entered.send(()).expect("report backend drop");
                self.release.recv().expect("release backend drop");
            }
        }

        let (_kernel, context) = bootstrap(15_476);
        let state = crate::vcpu_loop::executor::tests::task_state(&context, 476);
        let completion = LogicalJobCompletion::pending();
        let quantum = Arc::new(HvpatchTaskQuantum::new(
            Box::new(ExitJob),
            completion.clone(),
        ));
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let binding = HvpatchTaskBinding::new(
            crate::vcpu_loop::executor::TaskLoadIdentity {
                abi: state.cpu.guest_abi(),
                version: state.cpu.version(),
                mm: state.mm,
                asid_generation: state.asid_generation,
            },
            Arc::clone(&quantum),
            Box::new(BlockingBackendDrop {
                entered: entered_tx,
                release: release_rx,
            }),
        );
        drop(quantum);
        completion.publish();
        let dropper = std::thread::spawn(move || drop(binding));
        entered_rx.recv().expect("backend drop entered");
        assert!(
            !completion.wait_for_physical_retirement(Duration::from_millis(20)),
            "receipt must remain pending while another binding field is dropping"
        );
        release_tx.send(()).expect("release backend");
        dropper.join().expect("binding dropper");
        assert!(completion.wait_for_physical_retirement(Duration::from_secs(1)));
    }

    #[test]
    fn exec_replacement_keeps_physical_retirement_pending() {
        struct ExitJob;
        impl PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
            ) -> crate::vcpu_loop::executor::ExecutorExit {
                crate::vcpu_loop::executor::ExecutorExit::Exited
            }
        }

        let (_kernel, context) = bootstrap(15_477);
        let state = crate::vcpu_loop::executor::tests::task_state(&context, 477);
        let identity = crate::vcpu_loop::executor::TaskLoadIdentity {
            abi: state.cpu.guest_abi(),
            version: state.cpu.version(),
            mm: state.mm,
            asid_generation: state.asid_generation,
        };
        let completion = LogicalJobCompletion::pending();
        let quantum = Arc::new(HvpatchTaskQuantum::new(
            Box::new(ExitJob),
            completion.clone(),
        ));
        let predecessor = HvpatchTaskBinding::new(identity, Arc::clone(&quantum), Box::new(()));
        let successor = predecessor.replacement(identity);
        drop(quantum);
        completion.publish();
        drop(predecessor);
        assert!(
            !completion.wait_for_physical_retirement(Duration::from_millis(20)),
            "exec predecessor must not retire the successor's shared quantum"
        );
        drop(successor);
        assert!(completion.wait_for_physical_retirement(Duration::from_secs(1)));
    }

    #[test]
    fn production_hvpatch_thread_clone_never_reaches_host_thread_or_vcpu_materialization() {
        let source = include_str!("../binding.rs");
        let production = source
            .split_once("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopJob<E>")
            .expect("production HVPatch job")
            .1
            .split_once("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll")
            .expect("end of production HVPatch job")
            .0;
        let clone_arm = production
            .split_once("DispatchOutcome::CloneThread")
            .expect("production HVPatch CloneThread arm")
            .1
            .split_once("DispatchOutcome::SetMemoryModel")
            .expect("end of production clone arm")
            .0;
        let clone_helper = production
            .split_once("fn spawn_persistent_hvpatch_clone_thread")
            .expect("production task-only clone helper")
            .1
            .split_once("fn leave_executor")
            .expect("end of production task-only clone helper")
            .0;
        let lifecycle = include_str!("../lifecycle.rs");
        let backend_ops = lifecycle
            .split_once("for ProductionHvpatchCloneBackendOps")
            .expect("production clone backend ops")
            .1
            .split_once("enum HvpatchCloneFailpoint")
            .expect("end of production clone backend ops")
            .0;
        assert!(clone_arm.contains("spawn_persistent_hvpatch_clone_thread"));
        for prohibited in [
            "spawn_clone_thread",
            "Builder::new",
            "materialize_sibling",
            "wait_for_vcpu_slot",
            "VcpuThreadHandle::Host",
            "fresh_fork_kicker",
            "child_kicker.register",
            "VcpuLeaseGuard",
            "reserve_thread_clone_eventually",
            "reserve_publication_eventually",
            "wait_for_reservation_change",
            "_eventually",
            "Condvar",
            "yield_now",
            "thread::sleep",
            ".close_for_fork(",
        ] {
            assert!(
                !clone_helper.contains(prohibited),
                "production HVPatch thread clone retained {prohibited}"
            );
        }
        assert!(
            backend_ops.contains("materialize_hvpatch_sibling_without_vcpu"),
            "production HVPatch backend ops omitted task-only materialization"
        );
        assert!(
            production.contains("ProductionHvpatchCloneBackendOps"),
            "production clone callgraph omitted concrete backend ops"
        );
        for required in [
            "ops.prepare",
            "HvpatchSubmissionShape::SameTaskSibling",
            "prepare_hvpatch_submission",
            "take_opened_start_gate",
            "dormant.activate",
        ] {
            assert!(
                clone_helper.contains(required),
                "production HVPatch thread clone omitted {required}"
            );
        }
    }

    #[test]
    fn production_hvpatch_process_fork_never_reaches_host_thread_or_vcpu_materialization() {
        let quiesce = include_str!("../quiesce.rs");
        let lifecycle = include_str!("../lifecycle.rs");
        let production = include_str!("../binding.rs");
        let backend_ops = lifecycle
            .split_once("for ProductionHvpatchProcessBackendOps")
            .expect("production HVPatch process backend ops")
            .1
            .split_once("struct ProductionHvpatchCloneBackendOps")
            .expect("end of production HVPatch process backend ops")
            .0;
        let terminal_finalizer = production
            .split_once("fn finalize_persistent_process_terminal")
            .expect("persistent process terminal finalizer")
            .1
            .split_once("fn begin_persistent_process_terminal")
            .expect("end persistent process terminal finalizer")
            .0;
        let fork = quiesce
            .split_once("fn prepare_in_process_fork")
            .expect("production HVPatch process-fork state machine")
            .1
            .split_once("#[cfg(test)]")
            .expect("end of production HVPatch process-fork state machine")
            .0;
        for prohibited in [
            "Builder::new",
            "materialize_process(",
            "launch_vcpu_until_exit",
            "VcpuLeaseGuard",
            "sync_channel",
            "ready_rx",
            "start_rx",
            "JoinHandle",
            "reserve_thread_clone_eventually",
            "reserve_publication_eventually",
            "wait_for_reservation_change",
            "_eventually",
            "Condvar",
            "yield_now",
            "thread::sleep",
            ".close_for_fork(",
        ] {
            assert!(
                !fork.contains(prohibited),
                "production HVPatch process fork retained {prohibited}"
            );
        }
        for required in [
            "ops.prepare",
            "prepare_hvpatch_logical_job",
            "HvpatchSubmissionShape::Descendant",
            "HvpatchSubmissionShape::PeerRoot",
            "take_opened_start_gate",
            "let dormant",
            ".activate(",
            "PreparedInProcessFork::SuspendVfork",
            "if is_external_exec || request.clone_parent",
            "PreparedInProcessFork::Retry",
            "subscribe_lease_drain",
            "try_acquire_topology_lock",
            "subscribe_topology_release",
            "fork_barrier_participants",
        ] {
            assert!(
                fork.contains(required),
                "production HVPatch process fork omitted {required}"
            );
        }
        assert!(
            backend_ops.contains("materialize_hvpatch_process_without_vcpu"),
            "production HVPatch process ops omitted task-only materialization"
        );
        assert!(
            (production.contains("bootstrap_hvpatch_process_child(")
                || lifecycle.contains("bootstrap_hvpatch_process_child("))
                && (production.contains("refresh_fork_process_state")
                    || lifecycle.contains("refresh_fork_process_state"))
                && (production.contains("stamp_identity_page")
                    || lifecycle.contains("stamp_identity_page"))
                && (production.contains("stamp_ns_visible_guest_tid")
                    || lifecycle.contains("stamp_ns_visible_guest_tid")),
            "process child refresh/identity/tid bootstrap is not mandatory on first load"
        );
        for required in [
            "begin_persistent_process_terminal",
            "finalize_persistent_process_terminal",
            "publish_exit_status",
            "notify_hvpatch_parent_exit",
            "unregister_hvpatch_runtime_endpoint",
            "publish_process_terminal(terminal_publication)",
            "ExecutorExit::Quiesced",
            "notify_quiesced_progress",
            "stamp_ns_visible_guest_tid",
            "restore vfork parent identity page",
            "try_claim_persistent_process_exit",
            "clone_admission.subscribe_change",
            "withdraw_persistent_terminal_owner_runtime",
            "TerminalClaimRetry",
            "TerminalRetireRetry",
            "trap_watchdog_decision",
        ] {
            assert!(
                production.contains(required) || lifecycle.contains(required),
                "persistent fork failure/quiesce contract omitted {required}"
            );
        }
        let poll = production
            .split_once("fn poll_with_engine")
            .expect("persistent production poll")
            .1
            .split_once("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll")
            .expect("end persistent production poll")
            .0;
        let terminal_stop = poll
            .find("thread_should_finish_for_exec_replacement")
            .expect("run-top exact terminal stop");
        let quiesce = poll
            .find("suspend_for_process_quiesce")
            .expect("run-top quiesce check");
        let preempt = poll.find("control.need_resched").expect("preemption check");
        let guest = poll.find("engine.next_syscall").expect("guest entry");
        assert!(terminal_stop < quiesce && quiesce < preempt && preempt < guest);
        assert!(poll.contains("VcpuLoopOutcome::TrapLimit"));
        let exec_source = include_str!("../exec.rs");
        assert!(exec_source.contains("pending_exec_replacement.replace"));
        assert!(exec_source.contains("carrick_fatal"));
        let exec_resume = production
            .split_once("fn finish_exec_suffix(")
            .expect("post-exec suffix boundary")
            .1
            .split_once("fn service_outcome(")
            .expect("post-exec worker boundary")
            .0;
        assert!(exec_resume.contains("self.publish_exec_replacement(control)"));
        assert!(exec_resume.contains("ExecutorExit::Preempted"));
        assert!(exec_resume.contains("HvpatchLoopSuspension::Preemption"));
        assert!(!terminal_finalizer.contains("retire_task_address_space"));
        assert!(terminal_finalizer.contains("begin_address_space_retirement"));
        assert!(!terminal_finalizer.contains("retire_in_process_address_space"));
        let thread_exit = production
            .split_once("DispatchOutcome::ThreadExit { code } =>")
            .expect("persistent thread-exit branch")
            .1
            .split_once("DispatchOutcome::Exit { code } =>")
            .expect("end persistent thread-exit branch")
            .0;
        assert!(
            !thread_exit.contains("live_count()"),
            "persistent thread exit must route from the atomic withdrawal result"
        );
        assert!(
            thread_exit.contains("settle_persistent_thread_exit"),
            "the ThreadExit arm must route through the shared settle seam"
        );
        let settle_seam = production
            .split_once("fn settle_persistent_thread_exit")
            .expect("thread-exit settle seam")
            .1
            .split_once("fn park_thread_exit_retry")
            .expect("end thread-exit settle seam")
            .0;
        assert!(settle_seam.contains("VcpuLoopOutcome::ThreadDone"));
        assert!(settle_seam.contains("VcpuLoopOutcome::ProcessExit"));
        assert!(settle_seam.contains("begin_persistent_process_terminal"));
        assert!(
            !terminal_finalizer
                .contains("let topology = crate::fork_quiesce::acquire_topology_lock")
        );
        for prohibited in [
            "materialize_process(",
            "launch_vcpu_until_exit",
            "Builder::new",
            "JoinHandle",
        ] {
            assert!(
                !backend_ops.contains(prohibited),
                "production HVPatch process backend retained {prohibited}"
            );
        }
    }

    #[test]
    fn persistent_process_drain_is_engine_free_and_ready_only_after_all_siblings() {
        fn assert_send<T: Send>() {}
        assert_send::<ProcessDrain>();

        let (kernel, context) = bootstrap(15_472);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let current = LogicalJobCompletion::pending();
        let first = LogicalJobCompletion::pending();
        let second = LogicalJobCompletion::pending();
        let drain = ProcessDrain::for_scheduler(
            context.thread().key(),
            &scheduler,
            current.id(),
            vec![current.clone(), first.clone(), second.clone()],
        );
        assert!(!drain.is_ready());
        current.publish();
        assert!(!drain.is_ready(), "self completion must be excluded");
        first.publish();
        assert!(!drain.is_ready());
        second.publish();
        assert!(drain.is_ready());
    }
}
