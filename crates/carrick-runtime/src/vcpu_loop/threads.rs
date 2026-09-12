//! THREAD concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

pub(super) fn clear_persistent_child_tid_and_wake<M: carrick_guest_mem::CurrentMmMemory>(
    memory: &mut M,
    registry: &ThreadRegistry,
    futex: &FutexTable,
    tid: ThreadId,
) {
    if let Some(address) = registry.clear_child_tid(tid)
        && address != 0
    {
        let _ = memory.write_bytes(address, &0_i32.to_le_bytes());
        let woken = futex.wake(address, 1);
        crate::event_ring::rec_futex_wake(address, woken);
    }
}

pub(super) enum CloneThreadSpawn {
    Started {
        internal: crate::kernel::LinuxTid,
        visible: i32,
    },
    Errno(crate::linux_abi::LinuxErrno),
}

pub(super) struct CloneTidOutputTransaction {
    parent_address: u64,
    parent_preimage: Option<Vec<u8>>,
    child_address: u64,
    child_preimage: Option<Vec<u8>>,
}

pub(super) trait CloneTidMemory {
    fn read_clone_tid_bytes(
        &self,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError>;
    fn write_clone_tid_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError>;
}

impl<E: ThreadedEngine> CloneTidMemory for E {
    fn read_clone_tid_bytes(
        &self,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        self.read_bytes(address, len)
    }

    fn write_clone_tid_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        self.write_bytes(address, bytes)
    }
}

impl CloneTidOutputTransaction {
    pub(super) fn capture<E: CloneTidMemory>(
        engine: &E,
        parent_address: u64,
        child_address: u64,
    ) -> Result<Self, crate::linux_abi::LinuxErrno> {
        let read = |address: u64| {
            if address == 0 {
                Some(None)
            } else {
                engine
                    .read_clone_tid_bytes(address, std::mem::size_of::<i32>())
                    .ok()
                    .map(Some)
            }
        };
        Ok(Self {
            parent_address,
            parent_preimage: read(parent_address).ok_or(crate::linux_abi::LINUX_EFAULT)?,
            child_address,
            child_preimage: read(child_address).ok_or(crate::linux_abi::LINUX_EFAULT)?,
        })
    }

    pub(super) fn publish<E: CloneTidMemory>(
        &self,
        engine: &mut E,
        visible_tid: i32,
        backend_tid: ThreadId,
    ) -> bool {
        let bytes = visible_tid.to_le_bytes();
        self.publish_one(
            engine,
            backend_tid,
            carrick_observability::probes::HvpatchCloneTidOutput::Parent,
            self.parent_address,
            &bytes,
        ) && self.publish_one(
            engine,
            backend_tid,
            carrick_observability::probes::HvpatchCloneTidOutput::Child,
            self.child_address,
            &bytes,
        )
    }

    fn publish_one<E: CloneTidMemory>(
        &self,
        engine: &mut E,
        backend_tid: ThreadId,
        output: carrick_observability::probes::HvpatchCloneTidOutput,
        address: u64,
        bytes: &[u8],
    ) -> bool {
        if address == 0 {
            return true;
        }
        let result = engine.write_clone_tid_bytes(address, bytes);
        let result_kind = match &result {
            Ok(()) => carrick_observability::probes::HvpatchCloneTidWriteResult::Success,
            Err(carrick_guest_mem::MemoryError::OutOfBounds { .. }) => {
                carrick_observability::probes::HvpatchCloneTidWriteResult::OutOfBounds
            }
            Err(carrick_guest_mem::MemoryError::Unsupported) => {
                carrick_observability::probes::HvpatchCloneTidWriteResult::Unsupported
            }
            Err(carrick_guest_mem::MemoryError::HostMap(detail))
                if detail.starts_with("HVPatch sparse mmap backing:") =>
            {
                carrick_observability::probes::HvpatchCloneTidWriteResult::SparseBacking
            }
            Err(carrick_guest_mem::MemoryError::HostMap(detail))
                if detail.starts_with("HVPatch frame COW:") =>
            {
                carrick_observability::probes::HvpatchCloneTidWriteResult::FrameCow
            }
            Err(carrick_guest_mem::MemoryError::HostMap(_)) => {
                carrick_observability::probes::HvpatchCloneTidWriteResult::HostMap
            }
        };
        crate::probes::mn_clone_tid_output(backend_tid.raw(), output, address, result_kind);
        result.is_ok()
    }

    pub(super) fn rollback<E: CloneTidMemory>(
        &self,
        engine: &mut E,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let mut failure = None;
        if let Some(bytes) = self.parent_preimage.as_ref() {
            if let Err(error) = engine.write_clone_tid_bytes(self.parent_address, bytes) {
                failure = Some(error);
            }
        }
        if let Some(bytes) = self.child_preimage.as_ref() {
            if let Err(error) = engine.write_clone_tid_bytes(self.child_address, bytes)
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// A guest thread's handle in the process-private thread list. The retired
/// `Job` variant carried a transitional-runner task receipt, which nothing on
/// the persistent path ever produced.
pub(crate) enum VcpuThreadHandle {
    Persistent {
        terminal_settlement: HvpatchExternalTerminalSettlement,
    },
}

impl VcpuThreadHandle {
    pub(crate) fn completion(&self) -> continuation::LogicalJobCompletion {
        match self {
            Self::Persistent {
                terminal_settlement,
            } => terminal_settlement.completion(),
        }
    }

    /// Settle a drained member externally. Returns whether THIS call
    /// published the member's `ThreadDone` (false for the current job and
    /// for a member that already finished its own job).
    pub(crate) fn finish_completed(
        self,
        current: continuation::JobId,
    ) -> Result<bool, RuntimeError> {
        match self {
            Self::Persistent {
                terminal_settlement,
            } if terminal_settlement.completion().id() == current => Ok(false),
            Self::Persistent {
                terminal_settlement,
            } => {
                let published =
                    terminal_settlement.publish_member(Ok(VcpuLoopOutcome::ThreadDone))?;
                if !terminal_settlement.is_published()
                    || !terminal_settlement.completion().is_finished()
                {
                    return Err(RuntimeError::Configuration(
                        "external persistent terminal settlement violated result-before-completion"
                            .to_owned(),
                    ));
                }
                Ok(published)
            }
        }
    }
}

pub(crate) fn enroll_persistent_process_member(
    threads: &VcpuThreadRegistry,
    terminal_settlement: &HvpatchExternalTerminalSettlement,
) {
    if !threads.register(terminal_settlement) {
        carrick_fatal!(
            "vcpu_loop::process_membership",
            "Duplicate terminal settlement registration in persistent process handle list"
        );
    }
}

pub(crate) fn remove_persistent_process_member(
    threads: &VcpuThreadRegistry,
    completion: continuation::JobId,
) {
    let _ = threads.take_by_id(completion);
}

/// Settle every enrolled member externally; returns how many member
/// `ThreadDone` results this drain published (members that never finished
/// their own job).
///
/// The CURRENT job's own handle is put back: it is the survivor of an exec
/// (or the owner of an exit) and must stay a member so the process's NEXT
/// drain waits for it. Draining it too (2026-09-12) left every process that
/// had exec'd once with no leader entry — an exec from a non-leader thread
/// then found an empty drain, proceeded at once, and the still-running
/// leader became the stale `Runnable` kernel thread behind the
/// `execfromthread`/`forkexecstorm`/go-net_http aborts and hangs.
pub(crate) fn finish_persistent_process_handles(
    threads: &VcpuThreadRegistry,
    current: &continuation::LogicalJobCompletion,
) -> Result<(usize, Vec<continuation::LogicalJobCompletion>), RuntimeError> {
    let handles = threads.drain();
    let mut completions = handles
        .iter()
        .map(VcpuThreadHandle::completion)
        .collect::<Vec<_>>();
    if !completions
        .iter()
        .any(|completion| completion.id() == current.id())
    {
        completions.push(current.clone());
    }
    let mut published = 0;
    for handle in handles {
        if handle.completion().id() == current.id() {
            threads.register_handle(handle);
            continue;
        }
        if handle.finish_completed(current.id())? {
            published += 1;
        }
    }
    Ok((published, completions))
}

pub(crate) fn publish_unexpected_executor_failure_retirement(
    kernel: &Kernel,
    threads: &VcpuThreadRegistry,
    current: &continuation::LogicalJobCompletion,
) -> Result<(), RuntimeError> {
    let (_published, completions) = finish_persistent_process_handles(threads, current)?;
    kernel.process_physical_retirement.publish(completions)?;
    kernel.publish_process_terminal(Err(()));
    Ok(())
}

pub(crate) struct PersistentProcessMemberPublication {
    threads: VcpuThreadRegistry,
    completion: continuation::JobId,
    armed: bool,
}

impl PersistentProcessMemberPublication {
    pub(crate) fn new(
        threads: VcpuThreadRegistry,
        terminal_settlement: &HvpatchExternalTerminalSettlement,
    ) -> Self {
        enroll_persistent_process_member(&threads, terminal_settlement);
        Self {
            threads,
            completion: terminal_settlement.completion().id(),
            armed: true,
        }
    }

    pub(crate) fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for PersistentProcessMemberPublication {
    fn drop(&mut self) {
        if self.armed {
            remove_persistent_process_member(&self.threads, self.completion);
        }
    }
}

/// Encapsulates the collection of active persistent vCPU thread handles for a process.
#[derive(Clone, Default)]
pub(crate) struct VcpuThreadRegistry(Arc<parking_lot::Mutex<Vec<VcpuThreadHandle>>>);

impl VcpuThreadRegistry {
    pub(crate) fn new() -> Self {
        Self(Arc::new(parking_lot::Mutex::new(Vec::new())))
    }

    pub(crate) fn register(&self, terminal_settlement: &HvpatchExternalTerminalSettlement) -> bool {
        self.register_handle(VcpuThreadHandle::Persistent {
            terminal_settlement: terminal_settlement.clone(),
        })
    }

    pub(crate) fn register_handle(&self, handle: VcpuThreadHandle) -> bool {
        let mut handles = self.0.lock();
        if handles
            .iter()
            .any(|h| h.completion().id() == handle.completion().id())
        {
            return false;
        }
        handles.push(handle);
        true
    }

    pub(crate) fn take_by_id(&self, completion: continuation::JobId) -> Option<VcpuThreadHandle> {
        let mut handles = self.0.lock();
        let index = handles
            .iter()
            .position(|handle| handle.completion().id() == completion)?;
        Some(handles.remove(index))
    }

    pub(crate) fn drain(&self) -> Vec<VcpuThreadHandle> {
        let mut handles = self.0.lock();
        std::mem::take(&mut *handles)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }

    pub(crate) fn completions(&self) -> Vec<continuation::LogicalJobCompletion> {
        self.0
            .lock()
            .iter()
            .map(VcpuThreadHandle::completion)
            .collect()
    }
}

impl From<Arc<parking_lot::Mutex<Vec<VcpuThreadHandle>>>> for VcpuThreadRegistry {
    fn from(handles: Arc<parking_lot::Mutex<Vec<VcpuThreadHandle>>>) -> Self {
        Self(handles)
    }
}

impl From<VcpuThreadRegistry> for Arc<parking_lot::Mutex<Vec<VcpuThreadHandle>>> {
    fn from(registry: VcpuThreadRegistry) -> Self {
        registry.0
    }
}

#[cfg(test)]
mod clone_tid_output_tests {
    use super::*;

    #[derive(Default)]
    struct Memory {
        bytes: std::collections::BTreeMap<u64, Vec<u8>>,
        fail_write: Option<u64>,
    }

    impl CloneTidMemory for Memory {
        fn read_clone_tid_bytes(
            &self,
            address: u64,
            _len: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            self.bytes
                .get(&address)
                .cloned()
                .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length: 4 })
        }

        fn write_clone_tid_bytes(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            if self.fail_write == Some(address) {
                return Err(carrick_guest_mem::MemoryError::HostMap(
                    "injected clone TID copyout failure".to_owned(),
                ));
            }
            self.bytes.insert(address, bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn second_tid_copyout_failure_restores_both_exact_preimages() {
        let parent = 0x1000;
        let child = 0x2000;
        let mut memory = Memory::default();
        memory.bytes.insert(parent, 11_i32.to_le_bytes().to_vec());
        memory.bytes.insert(child, 22_i32.to_le_bytes().to_vec());
        let transaction = CloneTidOutputTransaction::capture(&memory, parent, child).unwrap();
        memory.fail_write = Some(child);
        assert!(!transaction.publish(&mut memory, 7, ThreadId::synthetic_for_tests(77),));
        memory.fail_write = None;
        transaction.rollback(&mut memory).unwrap();
        assert_eq!(memory.bytes[&parent], 11_i32.to_le_bytes());
        assert_eq!(memory.bytes[&child], 22_i32.to_le_bytes());
    }

    #[test]
    fn rollback_write_failure_is_reported_after_attempting_every_preimage() {
        let parent = 0x3000;
        let child = 0x4000;
        let mut memory = Memory::default();
        memory.bytes.insert(parent, 31_i32.to_le_bytes().to_vec());
        memory.bytes.insert(child, 41_i32.to_le_bytes().to_vec());
        let transaction = CloneTidOutputTransaction::capture(&memory, parent, child).unwrap();
        memory.bytes.insert(parent, 99_i32.to_le_bytes().to_vec());
        memory.bytes.insert(child, 99_i32.to_le_bytes().to_vec());
        memory.fail_write = Some(parent);

        assert!(transaction.rollback(&mut memory).is_err());
        assert_eq!(memory.bytes[&parent], 99_i32.to_le_bytes());
        assert_eq!(memory.bytes[&child], 41_i32.to_le_bytes());
    }

    /// The exec-from-thread teardown class (execfromthread, forkexecstorm,
    /// Go `os/exec` in net_http; 2026-09-12): the sibling drain drains the
    /// WHOLE member registry, including the surviving job's own handle, and
    /// nothing re-enrolls the survivor. A process that has exec'd once
    /// therefore has no leader entry in its next drain: an exec from a
    /// non-leader thread then finds an empty drain, proceeds at once, and
    /// the still-running leader is the stale `Runnable` kernel thread every
    /// post-mortem showed. The survivor must remain a member.
    #[test]
    fn sibling_drain_keeps_the_surviving_job_enrolled() {
        let registry = VcpuThreadRegistry::new();
        let survivor = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        let sibling = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        assert!(registry.register(&survivor));
        assert!(registry.register(&sibling));

        let (published, completions) =
            finish_persistent_process_handles(&registry, &survivor.completion())
                .expect("drain settles the sibling");
        assert_eq!(published, 1, "the sibling is settled externally");
        assert_eq!(completions.len(), 2);
        assert!(sibling.is_published());
        assert!(
            !survivor.is_published(),
            "the survivor keeps its own settlement"
        );

        let remaining: Vec<_> = registry
            .completions()
            .into_iter()
            .map(|completion| completion.id())
            .collect();
        assert_eq!(
            remaining,
            vec![survivor.completion().id()],
            "the surviving job must stay enrolled so the NEXT exec/exit drain waits for it"
        );
    }

    #[test]
    fn vcpu_thread_registry_encapsulates_lifecycle_operations() {
        let registry = VcpuThreadRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        let settlement1 = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        let id1 = settlement1.completion().id();

        let settlement2 = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        let id2 = settlement2.completion().id();

        assert!(registry.register(&settlement1));
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());

        // Duplicate registration must fail.
        assert!(!registry.register(&settlement1));
        assert_eq!(registry.len(), 1);

        assert!(registry.register(&settlement2));
        assert_eq!(registry.len(), 2);

        // Take by id removes the matching handle.
        let taken = registry.take_by_id(id1);
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().completion().id(), id1);
        assert_eq!(registry.len(), 1);
        assert!(registry.take_by_id(id1).is_none());

        // Drain takes remaining handles and leaves registry empty.
        let drained = registry.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].completion().id(), id2);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn persistent_sibling_stop_authority(
        &self,
    ) -> Result<PersistentSiblingStopAuthority, RuntimeError> {
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent sibling stop lost exact Kernel context".to_owned(),
            )
        })?;
        Ok(PersistentSiblingStopAuthority {
            registry: Arc::clone(&self.registry),
            keeper: self.this_tid,
            kicker: Arc::clone(&self.kicker),
            futex: Arc::clone(&self.futex),
            platform_futex: Arc::clone(&self.platform_futex),
            context: context.retain_exact(),
        })
    }

    /// Attempt to publish this thread's live vCPU into the kicker: the fresh
    /// kick handle AND the thread's lifetime in-guest flag, in one entry.
    ///
    /// This is the ONLY production caller of
    /// [`carrick_hal::VcpuRegistry::subscribe_register`]. Every rebind path
    /// (blocking-wait reclaim, fork park, post-fork rebuild) funnels through
    /// here, so a re-registration cannot restore one facet and silently drop
    /// the other or publish through a sibling lease freeze.
    pub(super) fn subscribe_register_vcpu(
        &self,
        engine: &E,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> carrick_hal::VcpuRegistrationEnrollment {
        let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
        let enrollment =
            self.kicker
                .subscribe_register(self.this_tid, handle, &self.in_guest, callback);
        if matches!(
            enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ) {
            self.registry
                .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
        }
        enrollment
    }

    pub(super) fn prepare_persistent_sibling_drain(
        &self,
        kernel: &Kernel,
        current: continuation::JobId,
    ) -> Result<continuation::ProcessDrain, RuntimeError> {
        let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch persistent sibling drain has no shared scheduler".to_owned(),
            )
        })?;
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch persistent sibling drain lost exact Kernel context".to_owned(),
            )
        })?;
        let (scheduler, _service) = directory.continuation_services(context.kernel());
        let thread = self.kernel_thread.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch persistent sibling drain lost exact Kernel thread".to_owned(),
            )
        })?;
        let completions = self.threads.completions();
        let members = completions.len();
        let drain = continuation::ProcessDrain::for_scheduler(
            thread.key(),
            &scheduler,
            current,
            completions,
        );
        tracing::debug!(
            tid = self.this_tid.raw(),
            members,
            pending = drain.remaining(),
            "HVPatch persistent sibling drain prepared"
        );
        Ok(drain)
    }

    pub(super) fn publish_persistent_sibling_stop(
        &self,
        kernel: &Kernel,
    ) -> Result<(), RuntimeError> {
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent sibling stop lost exact Kernel context".to_owned(),
            )
        })?;
        publish_persistent_sibling_stop_with(
            &self.registry,
            self.this_tid,
            self.kicker.as_ref(),
            &self.futex,
            self.platform_futex.as_ref(),
            context,
            kernel,
        )
    }
}

pub(super) struct PersistentSiblingStopAuthority {
    registry: Arc<ThreadRegistry>,
    keeper: ThreadId,
    kicker: Arc<dyn VcpuRegistry>,
    futex: Arc<FutexTable>,
    platform_futex: Arc<dyn PlatformFutex>,
    context: crate::kernel::KernelContext,
}

impl PersistentSiblingStopAuthority {
    pub(super) fn publish(&self, kernel: &Kernel) -> Result<(), RuntimeError> {
        publish_persistent_sibling_stop_with(
            &self.registry,
            self.keeper,
            self.kicker.as_ref(),
            &self.futex,
            self.platform_futex.as_ref(),
            &self.context,
            kernel,
        )
    }
}

fn publish_persistent_sibling_stop_with(
    registry: &ThreadRegistry,
    keeper: ThreadId,
    kicker: &dyn VcpuRegistry,
    futex: &FutexTable,
    platform_futex: &dyn PlatformFutex,
    context: &crate::kernel::KernelContext,
    kernel: &Kernel,
) -> Result<(), RuntimeError> {
    let removed = registry.remove_all_except(keeper);
    kicker.kick_all_except(keeper);
    futex.notify_signal_pending();
    platform_futex.notify_signal_pending();
    kernel.signal_arrival.wake_all_waiters();
    let scheduler = kernel
        .hvpatch_runtime
        .as_ref()
        .ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent sibling stop has no shared scheduler".to_owned(),
            )
        })?
        .continuation_services(context.kernel())
        .0;
    wake_removed_persistent_sibling_threads(context, &scheduler, &removed)
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn begin_persistent_exec_sibling_drain(
        &self,
        kernel: &Kernel,
        current: continuation::JobId,
    ) -> Result<continuation::ProcessDrain, RuntimeError> {
        self.publish_persistent_sibling_stop(kernel)?;
        self.prepare_persistent_sibling_drain(kernel, current)
    }

    pub(super) fn begin_persistent_exit_sibling_drain(
        &self,
        kernel: &Kernel,
        current: continuation::JobId,
    ) -> Result<continuation::ProcessDrain, RuntimeError> {
        kernel.begin_process_exit();
        self.publish_persistent_sibling_stop(kernel)?;
        self.prepare_persistent_sibling_drain(kernel, current)
    }

    pub(super) fn finish_persistent_sibling_drain(
        &self,
        current: &continuation::LogicalJobCompletion,
    ) -> Result<Vec<continuation::LogicalJobCompletion>, RuntimeError> {
        let (published, completions) = finish_persistent_process_handles(&self.threads, current)?;
        if published > 0 {
            self.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::MembersDrainedByOwner,
                i32::try_from(published).unwrap_or(i32::MAX),
            );
        }
        Ok(completions)
    }

    /// Logical HVPatch exit while the physical vCPU remains owned by the
    /// persistent worker. Kernel execution settlement and vCPU detach are
    /// deliberately left to Task 4 after this method returns `Exited`.
    pub(super) fn withdraw_persistent_terminal_owner_runtime(
        &self,
        kernel: &Kernel,
        engine: &mut E,
    ) -> bool {
        let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 1);
        clear_persistent_child_tid_and_wake(engine, &self.registry, &self.futex, self.this_tid);
        let last = self.registry.exit(self.this_tid);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 2);
        crate::run_state::clear_guest_tid(self.this_tid.raw());
        self.kicker.unregister(self.this_tid);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 3);
        crate::host_signal::forget_thread(self.this_tid.raw());
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 4);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 5);
        last
    }

    pub(super) fn handle_persistent_thread_exit(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        code: i32,
        traps: usize,
    ) -> PersistentThreadExitDisposition {
        if !self.thread_exit_withdrawn {
            let _ = self.stash_parked_registers(engine);
            if self.publish_crash_registers_if_requested(engine).is_err() {
                self.withdraw_from_crash_capture();
            }
        }
        // Sibling signals (e.g. glibc setxid tgkill) must see this thread as
        // undeliverable (ESRCH) BEFORE clear_child_tid wakes futex / stack
        // allocators or runtime state is withdrawn. In HVPatch, retiring the
        // thread from the authoritative task graph first closes the window
        // where a signal could be posted to or delivered on a torn-down stack.
        let mut last = false;
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            match process.exit_thread(self.linux_tid) {
                Ok(crate::hvpatch::ProcessThreadExit::Retired(retired)) => {
                    kernel.dispatcher.close_draining_file_table(
                        process.kernel_graph(),
                        &retired.files(),
                        Some(retired.owner()),
                        None,
                    );
                }
                Ok(crate::hvpatch::ProcessThreadExit::AlreadyRetired) => {}
                Ok(crate::hvpatch::ProcessThreadExit::Busy { observed_epoch }) => {
                    return PersistentThreadExitDisposition::Busy { observed_epoch };
                }
                Ok(crate::hvpatch::ProcessThreadExit::LastThread) | Err(_) => last = true,
            }
        }
        // Runtime withdrawal (registry exit, kick unregister, host-signal
        // forget) runs EXACTLY ONCE after the thread is retired (or across
        // Busy retries): it is not re-entrant, and the registry census it
        // returns is only meaningful on the first pass.
        if !self.thread_exit_withdrawn {
            self.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::GuestThreadExit,
                code,
            );
            let registry_last = self.withdraw_persistent_terminal_owner_runtime(kernel, engine);
            self.thread_exit_withdrawn = true;
            if kernel.hvpatch_process.is_none() {
                last = registry_last;
            }
        }
        PersistentThreadExitDisposition::Done(if last {
            VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                kernel, code, None, traps, false,
            )))
        } else {
            VcpuLoopOutcome::ThreadDone
        })
    }
}

/// What became of a persistent guest thread's logical exit.
pub(super) enum PersistentThreadExitDisposition {
    /// The exit completed; the job finishes with this outcome.
    Done(VcpuLoopOutcome),
    /// The kernel graph holds a task reservation (a sibling exec/fork/exit
    /// transaction). The job parks as a scheduler-visible retry subscribed
    /// to the reservation-change epoch — blocking the executor here
    /// deadlocks against a holder that needs this executor's
    /// command-service point (the execfromthread ABBA wedge).
    Busy { observed_epoch: u64 },
}

pub(super) fn wake_removed_persistent_sibling_threads(
    context: &crate::kernel::KernelContext,
    scheduler: &Arc<crate::kernel::Scheduler>,
    removed: &[ThreadId],
) -> Result<(), RuntimeError> {
    for thread in context.task().threads() {
        if !removed
            .iter()
            .any(|tid| tid.raw() == thread.key().tid.raw())
        {
            continue;
        }
        if let Err(error) = scheduler.wake_control(thread.key())
            && !matches!(error, crate::kernel::SchedulerError::UnknownThread)
            && !matches!(
                thread.execution_state(),
                crate::kernel::objects::ThreadExecutionState::Exited { .. }
                    | crate::kernel::objects::ThreadExecutionState::Failed { .. }
            )
        {
            return Err(RuntimeError::Configuration(format!(
                "wake exact persistent sibling for terminal transition: {error}"
            )));
        }
    }
    Ok(())
}
