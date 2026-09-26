//! Normal native execution admission. This owns the exact-MM running handshake,
//! not memory access or code publication. Carrier data must still be activated
//! under separately authenticated mapping/owner/leaf authority.

use super::{
    MmExecutorAdmissionRecipe, MmExecutorParticipation, SyscallDispatcher, outcome::DispatchError,
};
use crate::kernel::{
    KernelContext, MmAccessError,
    objects::{ExecutionGeneration, ExecutorId, ThreadExecutionLease},
};
use carrick_hal::{InGuestFlag, ThreadId};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

const EXTERNAL_STOP: u8 = 1;
const MEMORY_PAUSE: u8 = 2;

/// The occupancy port owns this exact state directly. Registry
/// replacement/removal can neither conceal its running flag nor redirect a
/// page-table drain's request.
pub(crate) struct NativeExecutorState {
    tid: ThreadId,
    running: InGuestFlag,
    requests: AtomicU8,
}
impl NativeExecutorState {
    fn new(tid: ThreadId) -> Self {
        Self {
            tid,
            running: InGuestFlag::for_guest_thread(),
            requests: AtomicU8::new(0),
        }
    }
    pub(crate) fn tid(&self) -> ThreadId {
        self.tid
    }
    pub(crate) fn is_running(&self) -> bool {
        self.running.is_in_guest()
    }
    pub(crate) fn watch_running(
        &self,
        wake: &Arc<carrick_hal::GuestLeaveWake>,
    ) -> carrick_hal::GuestLeaveWatch {
        self.running.watch_leave(wake)
    }
    pub(crate) fn request_memory_pause(&self) {
        self.requests.fetch_or(MEMORY_PAUSE, Ordering::SeqCst);
    }
    pub(crate) fn request_stop(&self) {
        self.requests.fetch_or(EXTERNAL_STOP, Ordering::SeqCst);
    }
}

/// Request-only control endpoint. A request does not acknowledge a safe point.
/// The owner must return from native code and drop its `NativeExecution` first.
#[derive(Clone)]
pub struct NativeExecutionInterrupt(Arc<NativeExecutorState>);
impl NativeExecutionInterrupt {
    pub fn request_stop(&self) {
        self.0.request_stop();
    }
}
impl carrick_hal::VcpuKick for NativeExecutionInterrupt {
    fn kick(&self) {
        self.request_stop();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LeaseIdentity {
    generation: ExecutionGeneration,
    executor: ExecutorId,
    epoch: u64,
}
impl LeaseIdentity {
    fn of(lease: &ThreadExecutionLease) -> Self {
        Self {
            generation: lease.generation(),
            executor: lease.executor(),
            epoch: lease.executor_epoch(),
        }
    }
}

/// One exact task/executor quantum, reusable across synchronous native entries.
/// Setup occupies a host-only execution slot once (native execution has no
/// vCPU). Entry/exit takes no occupancy lock and
/// holds no MM mutation authority. Drop this admission before scheduler handoff;
/// a successor lease must receive a fresh admission and control endpoint.
///
/// This is only the execution facet. It neither registers an HVF vCPU nor
/// services carrier COW invalidation tickets or delivers Linux signal handlers.
pub struct NativeExecutor {
    // Vacates the slot before `_slot` frees it.
    participant: MmExecutorParticipation,
    _slot: crate::kernel::HostExecutionSlot,
    state: Arc<NativeExecutorState>,
    lease: LeaseIdentity,
    _thread: PhantomData<Rc<()>>,
}
impl NativeExecutor {
    pub fn interrupt_handle(&self) -> NativeExecutionInterrupt {
        NativeExecutionInterrupt(Arc::clone(&self.state))
    }
    /// Consume the request at a host safe point. The mutable borrow prevents
    /// acknowledging it while an execution scope still exists. A subsequent
    /// concurrent request remains sticky for the next entry check.
    pub fn take_stop_request(&mut self) -> bool {
        self.state.requests.swap(0, Ordering::SeqCst) != 0
    }
    /// Cheap host checkpoint query; admission still authenticates the exact
    /// lease and rechecks the barrier before publishing guest execution.
    pub fn memory_pause_pending(&self) -> bool {
        self.state.requests.load(Ordering::SeqCst) & MEMORY_PAUSE != 0
            || self.participant.authority.pt_quiesce().is_quiescing()
    }
    /// Ordinary dispatch may borrow the admitted executor only outside native
    /// execution. This preserves the existing exact-MM dispatch/mutation path.
    pub fn dispatch_participation(&mut self) -> &mut MmExecutorParticipation {
        &mut self.participant
    }
}

/// The running half of admission. Only dropping this scope clears the flag
/// observed by an exact-MM drain. Future native data capabilities must borrow
/// this scope, so all pointers expire before that acknowledgement.
///
/// ```compile_fail
/// use carrick_kernel::{dispatch::{SyscallDispatcher, native_execution::NativeExecutor}, kernel::{KernelContext, objects::ThreadExecutionLease}};
/// fn acknowledge_while_running(d: &SyscallDispatcher, n: &mut NativeExecutor, c: &KernelContext, e: &mut ThreadExecutionLease) {
///     let scope = d.enter_native_execution(n, c, e).unwrap();
///     n.take_stop_request();
///     drop(scope);
/// }
/// ```
/// ```compile_fail
/// use carrick_kernel::{dispatch::{SyscallDispatcher, native_execution::NativeExecutor}, kernel::{KernelContext, objects::ThreadExecutionLease}};
/// fn migrate_while_running(d: &SyscallDispatcher, n: &mut NativeExecutor, c: &KernelContext, mut e: ThreadExecutionLease) {
///     let scope = d.enter_native_execution(n, c, &mut e).unwrap();
///     c.thread().yield_from_executor(e).unwrap();
///     drop(scope);
/// }
/// ```
pub struct NativeExecution<'scope> {
    executor: &'scope mut NativeExecutor,
    context: &'scope KernelContext,
    _lease: &'scope mut ThreadExecutionLease,
}
impl NativeExecution<'_> {
    /// Authenticate content-use scopes against the actual running task/lease.
    /// No caller-supplied numeric identity can stand in for this scope.
    pub(crate) fn instruction_context(
        &self,
    ) -> Result<(&KernelContext, &ThreadExecutionLease), MmAccessError> {
        self.context.validate_current_execution_mm(self._lease)?;
        if self.stop_requested() {
            return Err(MmAccessError::NativeDataControlPending);
        }
        Ok((self.context, self._lease))
    }

    /// Authenticate the mutation authority that originally prepared a data pin
    /// against this scope's actual pause/coordinator objects, not MM IDs.
    pub(crate) fn data_context(
        &self,
        mutation: &super::mm_mutation::ForeignMmMutationAuthority,
    ) -> Result<&KernelContext, MmAccessError> {
        if !mutation.matches_native_authority(&self.executor.participant.authority) {
            return Err(MmAccessError::ForeignMutationAuthorityMismatch);
        }
        self.context.validate_current_execution_mm(self._lease)?;
        if self.stop_requested() {
            return Err(MmAccessError::NativeDataControlPending);
        }
        Ok(self.context)
    }

    /// The translator must reach a bounded checkpoint and end this scope when
    /// true. This only observes control; it never clears running or a request.
    pub fn stop_requested(&self) -> bool {
        self.executor.state.requests.load(Ordering::SeqCst) != 0
            || self
                .executor
                .participant
                .authority
                .pt_quiesce()
                .is_quiescing()
            || self
                .executor
                .participant
                .authority
                .fork_quiesce()
                .is_quiescing()
            || self.context.thread().may_have_pending_signals()
    }
}
impl Drop for NativeExecution<'_> {
    fn drop(&mut self) {
        self.executor.state.running.leave_guest();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NativeExecutionError {
    #[error(transparent)]
    Memory(#[from] MmAccessError),
    #[error(transparent)]
    Dispatch(#[from] DispatchError),
    #[error(transparent)]
    Admission(#[from] crate::kernel::MmOccupancyError),
    #[error("native admission belongs to another execution lease")]
    ChangedExecutionLease,
    #[error("native admission lost its exact running endpoint")]
    EndpointMismatch,
    #[error("native execution is already active")]
    AlreadyRunning,
    #[error("native entry requires a host control safe point")]
    ControlPending,
}

impl SyscallDispatcher {
    /// Test-only adapter to the production carrier fixture's exact authority.
    /// The normal authentication and occupancy admission path remains unchanged.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_native_mm_for_test(authority: Arc<super::DispatchMmAuthority>) -> Self {
        let dispatcher = Self::new();
        dispatcher.mm_binding.current.store(authority);
        dispatcher
    }

    pub fn admit_native_executor(
        &self,
        context: &KernelContext,
        execution: &ThreadExecutionLease,
    ) -> Result<NativeExecutor, NativeExecutionError> {
        context.validate_current_execution_mm(execution)?;
        let authority = self.mm_binding.current.load_full();
        let state = Arc::new(NativeExecutorState::new(context.thread().registry_id()));
        let slot = crate::kernel::HostExecutionSlot::allocate()?;
        let admission = MmExecutorAdmissionRecipe::NativeThread {
            thread: context.thread().clone(),
            state: Arc::clone(&state),
        };
        let occupancy = admission.enter(&authority, Some(slot.slot()))?;
        let participant = MmExecutorParticipation {
            authority,
            admission,
            occupancy,
        };
        // Admission can wait behind a mutator. Re-authenticate after joining,
        // then fail closed on exec/MM drift; never carry a stale owner forward.
        self.validate_current_mm_executor(&participant, context, execution)?;
        context.validate_current_execution_mm(execution)?;
        Ok(NativeExecutor {
            participant,
            _slot: slot,
            state,
            lease: LeaseIdentity::of(execution),
            _thread: PhantomData,
        })
    }

    fn validate_native_executor(
        &self,
        executor: &NativeExecutor,
        context: &KernelContext,
        execution: &ThreadExecutionLease,
    ) -> Result<(), NativeExecutionError> {
        if !matches!(&executor.participant.admission,
            MmExecutorAdmissionRecipe::NativeThread { state, .. } if Arc::ptr_eq(state, &executor.state))
        {
            return Err(NativeExecutionError::EndpointMismatch);
        }
        if executor.state.is_running() {
            return Err(NativeExecutionError::AlreadyRunning);
        }
        if executor.lease != LeaseIdentity::of(execution) {
            return Err(NativeExecutionError::ChangedExecutionLease);
        }
        self.validate_current_mm_executor(&executor.participant, context, execution)?;
        context.validate_current_execution_mm(execution)?;
        if executor.participant.is_released() {
            return Err(DispatchError::MmExecutorParticipationUnavailable.into());
        }
        Ok(())
    }

    /// Wait at the host safe point for the exact-MM memory pause to end.
    /// This borrows admission exclusively: no native scope/data pointer can
    /// survive into the wait. The caller must hold no mutation or dispatch
    /// serializer while parking. Uses the shared condition variable, not polling.
    ///
    /// Native execution has no hardware TLB. This neither consumes a hardware
    /// COW ticket nor acknowledges one. Only memory-pause requests are cleared;
    /// external stops, signals and fork control remain their owners' work.
    /// Success is not permission to run: entry authenticates and checks again.
    pub fn service_native_memory_control(
        &self,
        executor: &mut NativeExecutor,
        context: &KernelContext,
        execution: &ThreadExecutionLease,
    ) -> Result<(), NativeExecutionError> {
        self.validate_native_executor(executor, context, execution)?;
        let barrier = executor.participant.authority.pt_quiesce();
        // No-work service needs no wait-state lock (including its lazy host
        // allocation). If a new pause starts after this observation, entry's
        // publish-before-check handshake still prevents crossing the mutation.
        if barrier.is_quiescing() {
            barrier.park();
        }
        self.validate_native_executor(executor, context, execution)?;
        executor
            .state
            .requests
            .fetch_and(!MEMORY_PAUSE, Ordering::SeqCst);
        // A later pause cannot be hidden by clearing its request here: the
        // publish-before-check entry handshake still observes the live barrier.
        Ok(())
    }

    pub fn enter_native_execution<'scope>(
        &self,
        executor: &'scope mut NativeExecutor,
        context: &'scope KernelContext,
        execution: &'scope mut ThreadExecutionLease,
    ) -> Result<NativeExecution<'scope>, NativeExecutionError> {
        self.validate_native_executor(executor, context, execution)?;
        // SeqCst publish-before-check is the existing page-table entry
        // handshake: either we see the barrier or the drain sees us. Nothing
        // here holds an occupancy lock, so simultaneous readers remain possible.
        executor.state.running.enter_guest();
        let scope = NativeExecution {
            executor,
            context,
            _lease: execution,
        };
        if scope.stop_requested() {
            return Err(NativeExecutionError::ControlPending);
        }
        Ok(scope)
    }
}

#[cfg(test)]
mod tests;
