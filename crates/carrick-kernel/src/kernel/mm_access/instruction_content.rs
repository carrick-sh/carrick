//! Scoped content use for a future native publication permit. This binds the
//! participating-host-write drain to the kernel's real execution lifetime; it
//! deliberately grants no executable pointer or native publication authority.
use super::*;
use crate::dispatch::native_execution::NativeExecution;
use crate::kernel::objects::{ExecutionGeneration, ExecutorId, ThreadKey};
use carrick_hal::{ForeignMmLiveAuthority, foreign_mm::ForeignInstructionContentStatus};

type ExecutionIdentity = (ThreadKey, ExecutionGeneration, ExecutorId, u64);
fn identity(execution: &ThreadExecutionLease) -> ExecutionIdentity {
    (
        execution.thread_key(),
        execution.generation(),
        execution.executor(),
        execution.executor_epoch(),
    )
}

/// An authenticated copy plus participating-write dependencies. Keeping it does
/// not hold the execution lease or a running handshake. Hardware writes, private
/// RX admission, links and executable publication require additional authority.
/// This object never exposes a host executable address.
pub struct PreparedInstructionContent {
    kernel: Arc<Kernel>,
    task: TaskKey,
    mm: Arc<Mm>,
    execution: ExecutionIdentity,
    snapshot: ProjectedForeignMmSnapshot,
    bytes: Vec<u8>,
    receipt: Box<dyn carrick_hal::ForeignMmReadReceipt>,
    _thread: PhantomData<std::rc::Rc<()>>,
}

impl InstructionRead<'_> {
    pub fn prepare_tracked_content(self) -> Result<PreparedInstructionContent, MmAccessError> {
        self.validate_tracked_content()?;
        Ok(PreparedInstructionContent {
            kernel: Arc::clone(&self.context.kernel),
            task: self.context.task.key(),
            mm: self.mm,
            execution: identity(self.execution),
            snapshot: self.snapshot,
            bytes: self.bytes,
            receipt: self.receipt,
            _thread: PhantomData,
        })
    }
}

impl PreparedInstructionContent {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn validate_scope(&self, scope: &NativeExecution<'_>) -> Result<(), MmAccessError> {
        let (context, execution) = scope.instruction_context()?;
        if !Arc::ptr_eq(&context.kernel, &self.kernel)
            || context.task.key() != self.task
            || !Arc::ptr_eq(&context.shared.mm(), &self.mm)
            || identity(execution) != self.execution
        {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&self.mm),
        };
        if !live
            .matches_authenticated_snapshot(&self.snapshot, Instant::now() + MM_SNAPSHOT_TIMEOUT)
            .map_err(MmAccessError::ForeignTransport)?
        {
            return Err(MmAccessError::StaleInstructionRead);
        }
        Ok(())
    }

    pub fn activate<'active, 'scope>(
        &'active mut self,
        scope: &'active NativeExecution<'scope>,
    ) -> Result<ActiveInstructionContent<'active, 'scope>, MmAccessError> {
        self.validate_scope(scope)?;
        // Install cleanup before the fallible backend callback; partial
        // admission and unwind must both end before the running handshake.
        let active = ActiveInstructionContent {
            prepared: self,
            scope,
        };
        active
            .prepared
            .receipt
            .begin_instruction_content()
            .map_err(MmAccessError::ForeignTransport)?;
        active.prepared.validate_scope(scope)?;
        if active.stop_requested() {
            return Err(MmAccessError::StaleInstructionContent);
        }
        Ok(active)
    }
}

/// Only participating host writers are excluded until drop. This is one facet
/// of publication, not permission to execute translated code. A future native
/// consumer must check stop_requested at bounded checkpoints and end this scope
/// before dispatch, MM mutation, or acknowledging its running handshake.
///
/// ```compile_fail,E0505
/// use carrick_kernel::{kernel::mm_access::PreparedInstructionContent, dispatch::native_execution::NativeExecution};
/// fn drop_while_active(mut p: PreparedInstructionContent, scope: NativeExecution<'_>) {
///     let active = p.activate(&scope).unwrap();
///     drop(scope);
///     active.stop_requested();
/// }
/// ```
/// ```compile_fail,E0499
/// use carrick_kernel::{kernel::mm_access::PreparedInstructionContent, dispatch::native_execution::NativeExecution};
/// fn duplicate(p: &mut PreparedInstructionContent, scope: &NativeExecution<'_>) {
///     let a = p.activate(scope).unwrap();
///     let b = p.activate(scope).unwrap();
///     drop((a, b));
/// }
/// ```
pub struct ActiveInstructionContent<'active, 'scope> {
    prepared: &'active mut PreparedInstructionContent,
    scope: &'active NativeExecution<'scope>,
}
impl ActiveInstructionContent<'_, '_> {
    pub fn stop_requested(&self) -> bool {
        self.scope.stop_requested()
            || self.prepared.receipt.instruction_content_status()
                != ForeignInstructionContentStatus::UnchangedTrackedWrites
    }
}
impl Drop for ActiveInstructionContent<'_, '_> {
    fn drop(&mut self) {
        self.prepared.receipt.finish_instruction_content();
    }
}

#[cfg(test)]
mod types {
    use super::*;
    static_assertions::assert_not_impl_any!(PreparedInstructionContent: Send, Sync, Clone, Copy);
    static_assertions::assert_not_impl_any!(ActiveInstructionContent<'static, 'static>: Send, Sync, Clone, Copy);
}
