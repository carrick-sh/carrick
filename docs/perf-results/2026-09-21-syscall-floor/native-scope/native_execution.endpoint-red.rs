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
        atomic::{AtomicBool, Ordering},
    },
};

/// The census owns this exact state directly. Registry replacement/removal can
/// neither conceal its running flag nor redirect a page-table drain's request.
pub(crate) struct NativeExecutorState {
    tid: ThreadId,
    running: InGuestFlag,
    stop: AtomicBool,
}
impl NativeExecutorState {
    fn new(tid: ThreadId) -> Self {
        Self {
            tid,
            running: InGuestFlag::for_guest_thread(),
            stop: AtomicBool::new(false),
        }
    }
    pub(crate) fn tid(&self) -> ThreadId {
        self.tid
    }
    pub(crate) fn is_running(&self) -> bool {
        self.running.is_in_guest()
    }
    pub(crate) fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
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
/// Setup allocates its census endpoint once. Entry/exit takes no census lock and
/// holds no MM mutation authority. Drop this admission before scheduler handoff;
/// a successor lease must receive a fresh admission and control endpoint.
///
/// This is only the execution facet. It neither registers an HVF vCPU nor
/// services carrier COW invalidation tickets or delivers Linux signal handlers.
pub struct NativeExecutor {
    participant: MmExecutorParticipation,
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
        self.state.stop.swap(false, Ordering::SeqCst)
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
    /// The translator must reach a bounded checkpoint and end this scope when
    /// true. This only observes control; it never clears running or a request.
    pub fn stop_requested(&self) -> bool {
        self.executor.state.stop.load(Ordering::SeqCst)
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
    Admission(#[from] crate::kernel::GuestExecutorCensusError),
    #[error("native admission belongs to another execution lease")]
    ChangedExecutionLease,
    #[error("native entry requires a host control safe point")]
    ControlPending,
}

impl SyscallDispatcher {
    pub fn admit_native_executor(
        &self,
        context: &KernelContext,
        execution: &ThreadExecutionLease,
    ) -> Result<NativeExecutor, NativeExecutionError> {
        context.validate_current_execution_mm(execution)?;
        let authority = self.mm_binding.current.load_full();
        let state = Arc::new(NativeExecutorState::new(context.thread().registry_id()));
        let admission = MmExecutorAdmissionRecipe::NativeThread {
            thread: context.thread().clone(),
            state: Arc::clone(&state),
        };
        let participation = admission.enter(&authority)?;
        let participant = MmExecutorParticipation {
            authority,
            admission,
            participation: Some(participation),
        };
        // Admission can wait behind a mutator. Re-authenticate after joining,
        // then fail closed on exec/MM drift; never carry a stale owner forward.
        self.validate_current_mm_executor(&participant, context, execution)?;
        context.validate_current_execution_mm(execution)?;
        Ok(NativeExecutor {
            participant,
            state,
            lease: LeaseIdentity::of(execution),
            _thread: PhantomData,
        })
    }

    pub fn enter_native_execution<'scope>(
        &self,
        executor: &'scope mut NativeExecutor,
        context: &'scope KernelContext,
        execution: &'scope mut ThreadExecutionLease,
    ) -> Result<NativeExecution<'scope>, NativeExecutionError> {
        if executor.lease != LeaseIdentity::of(execution) {
            return Err(NativeExecutionError::ChangedExecutionLease);
        }
        self.validate_current_mm_executor(&executor.participant, context, execution)?;
        context.validate_current_execution_mm(execution)?;
        if executor.participant.participation.is_none() {
            return Err(DispatchError::MmExecutorParticipationUnavailable.into());
        }
        // SeqCst publish-before-check is the existing page-table entry
        // handshake: either we see the barrier or the drain sees us. Nothing
        // here holds the census lock, so simultaneous readers remain possible.
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
