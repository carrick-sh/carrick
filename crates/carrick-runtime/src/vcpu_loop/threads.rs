//! THREAD concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

pub(super) fn clear_persistent_child_tid_and_wake<M: carrick_guest_mem::GuestMemory>(
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
    Started(crate::kernel::LinuxTid),
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
        linux_tid: crate::kernel::LinuxTid,
        backend_tid: ThreadId,
    ) -> bool {
        let bytes = linux_tid.raw().to_le_bytes();
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
        let linux_tid = crate::kernel::LinuxTid::for_task_leader(
            crate::kernel::TaskId::for_root_bootstrap(77).unwrap(),
        );
        assert!(!transaction.publish(&mut memory, linux_tid, ThreadId::synthetic_for_tests(77),));
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
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    /// Publish this thread's live vCPU into the kicker: the fresh kick handle
    /// AND the thread's lifetime in-guest flag, in one entry.
    ///
    /// This is the ONLY production caller of
    /// [`carrick_hal::VcpuRegistry::register`]. Every rebind path (blocking-wait
    /// reclaim, fork park, post-fork rebuild) funnels through here, so a
    /// re-registration cannot restore one facet and silently drop the other.
    pub(super) fn register_vcpu(&self, engine: &E) {
        let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
        self.kicker.register(self.this_tid, handle, &self.in_guest);
        self.registry
            .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
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
        let completions = self
            .threads
            .lock()
            .iter()
            .map(VcpuThreadHandle::completion)
            .collect::<Vec<_>>();
        Ok(continuation::ProcessDrain::for_scheduler(
            thread.key(),
            &scheduler,
            current,
            completions,
        ))
    }

    fn publish_persistent_sibling_stop(&self, kernel: &Kernel) -> Result<(), RuntimeError> {
        let removed = self.registry.remove_all_except(self.this_tid);
        self.kicker.kick_all_except(self.this_tid);
        self.futex.notify_signal_pending();
        self.platform_futex.notify_signal_pending();
        kernel.signal_arrival.wake_all_waiters();
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent sibling stop lost exact Kernel context".to_owned(),
            )
        })?;
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
        current: continuation::JobId,
    ) -> Result<(), RuntimeError> {
        finish_persistent_process_handles(&self.threads, current)
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
        &self,
        kernel: &Kernel,
        engine: &mut E,
        code: i32,
        traps: usize,
    ) -> VcpuLoopOutcome {
        let mut last = self.withdraw_persistent_terminal_owner_runtime(kernel, engine);
        if !last && let Some(process) = kernel.hvpatch_process.as_ref() {
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
                Ok(crate::hvpatch::ProcessThreadExit::LastThread) | Err(_) => last = true,
            }
        }
        if last {
            VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                kernel, code, None, traps, false,
            )))
        } else {
            VcpuLoopOutcome::ThreadDone
        }
    }
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
        if let Err(error) = scheduler.wake(thread.key())
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
