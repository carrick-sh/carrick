//! Range-scoped syscall input reuse. Cold preparation authenticates contents;
//! warm copies re-observe non-reusing live authorities and the carrier leaf.
use super::*;
use crate::kernel::objects::{ExecutionGeneration, ExecutorId, ThreadKey};
use carrick_hal::{ForeignMmLiveAuthority, ForeignMmTransportError};

/// Retains authority and a backing pin, never a copy of guest bytes. It is
/// thread-local and tied to the exact execution incarnation that prepared it.
pub struct CurrentReadWindow {
    kernel: Arc<Kernel>,
    task: TaskKey,
    mm: Arc<Mm>,
    execution: (ThreadKey, ExecutionGeneration, ExecutorId, u64),
    snapshot: ProjectedForeignMmSnapshot,
    transport: Box<dyn carrick_hal::ForeignMmReadWindow>,
    start: GuestVa,
    len: usize,
    _thread: PhantomData<std::rc::Rc<()>>,
}

impl CurrentReadWindow {
    fn covers(&self, start: GuestVa, len: usize) -> bool {
        start.raw() >= self.start.raw()
            && start
                .raw()
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.start.raw() + self.len as u64)
    }

    fn matches_execution(
        &self,
        context: &KernelContext,
        mm: &Arc<Mm>,
        execution: &ThreadExecutionLease,
    ) -> bool {
        Arc::ptr_eq(&self.kernel, &context.kernel)
            && self.task == context.task.key()
            && Arc::ptr_eq(&self.mm, mm)
            && self.execution
                == (
                    execution.thread_key(),
                    execution.generation(),
                    execution.executor(),
                    execution.executor_epoch(),
                )
    }

    /// Fail closed on stale execution, MM, permissions, translation or owner.
    /// Callers may explicitly prepare a new window for a later incarnation.
    pub fn copy_into(
        &self,
        context: &KernelContext,
        execution: &ThreadExecutionLease,
        start: GuestVa,
        dst: &mut [u8],
    ) -> Result<(), MmAccessError> {
        let mm = context.authenticate_current_mm(execution)?;
        if !self.matches_execution(context, &mm, execution) || !self.covers(start, dst.len()) {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let live = RetainedMmLiveAuthority { mm };
        self.transport
            .copy_into(
                &live,
                &self.snapshot,
                start,
                dst,
                Instant::now() + MM_SNAPSHOT_TIMEOUT,
            )
            .map_err(MmAccessError::ForeignTransport)?;
        context.authenticate_current_mm(execution)?;
        Ok(())
    }
}

/// One input window per host checkpoint stream. Misses prepare once using live
/// authority; unsupported ranges use the original copy path. Revocation errors
/// during a copy are returned directly, never retried through weaker checks.
#[derive(Default)]
pub struct CurrentReadCache {
    window: Option<CurrentReadWindow>,
}

impl KernelContext {
    pub fn prepare_current_read_window(
        &self,
        execution: &ThreadExecutionLease,
        start: GuestVa,
        len: usize,
    ) -> Result<CurrentReadWindow, MmAccessError> {
        let mm = self.authenticate_current_mm(execution)?;
        let current = self.current_mm(execution)?;
        current
            .token
            .read_range(start, len)?
            .ok_or(MmAccessError::ForeignRangeAuthorityMismatch)?;
        let snapshot = ProjectedForeignMmSnapshot::from_backend(mm.id(), &current.token.snapshot)?;
        let lease = current
            .token
            .foreign_lease
            .read()
            .clone()
            .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&mm),
        };
        let deadline = Instant::now() + MM_SNAPSHOT_TIMEOUT;
        let transport = lease
            .prepare_read_window(&live, &snapshot, start, len, deadline)
            .map_err(MmAccessError::ForeignTransport)?;
        if !transport.authenticates(&snapshot, start, len)
            || !live
                .matches_authenticated_snapshot(&snapshot, deadline)
                .map_err(MmAccessError::ForeignTransport)?
        {
            return Err(MmAccessError::ForeignReceiptMismatch);
        }
        self.authenticate_current_mm(execution)?;
        Ok(CurrentReadWindow {
            kernel: Arc::clone(&self.kernel),
            task: self.task.key(),
            mm,
            execution: (
                execution.thread_key(),
                execution.generation(),
                execution.executor(),
                execution.executor_epoch(),
            ),
            snapshot,
            transport,
            start,
            len,
            _thread: PhantomData,
        })
    }

    pub fn copy_current_into_cached(
        &self,
        execution: &ThreadExecutionLease,
        start: GuestVa,
        dst: &mut [u8],
        cache: &mut CurrentReadCache,
    ) -> Result<(), MmAccessError> {
        let mm = self.authenticate_current_mm(execution)?;
        if dst.is_empty() {
            return Ok(());
        }
        let reusable = if let Some(window) = &cache.window {
            window.matches_execution(self, &mm, execution)
                && window.covers(start, dst.len())
                && RetainedMmLiveAuthority {
                    mm: Arc::clone(&mm),
                }
                .matches_authenticated_snapshot(
                    &window.snapshot,
                    Instant::now() + MM_SNAPSHOT_TIMEOUT,
                )
                .map_err(MmAccessError::ForeignTransport)?
        } else {
            false
        };
        if !reusable {
            cache.window = None;
            match self.prepare_current_read_window(execution, start, dst.len()) {
                Ok(window) => cache.window = Some(window),
                Err(MmAccessError::ForeignTransport(
                    ForeignMmTransportError::AuthorityUnavailable,
                )) => return self.copy_current_into(execution, start, dst),
                Err(error) => return Err(error),
            }
        }
        let result = cache
            .window
            .as_ref()
            .ok_or(MmAccessError::ForeignRangeAuthorityMismatch)?
            .copy_into(self, execution, start, dst);
        if result.is_err() {
            cache.window = None;
        }
        result
    }
}
