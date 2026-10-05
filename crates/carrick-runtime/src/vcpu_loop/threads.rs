#![cfg_attr(
    all(not(target_os = "macos"), not(test)),
    expect(
        dead_code,
        reason = "bound by the KVM carrier at M5: docs/superpowers/plans/2026-10-04-kvm-hvpatch-carrier.md"
    )
)]

//! THREAD concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

pub(crate) struct PendingChildTidClear {
    clear: carrick_thread::thread::ChildTidClear,
    context: carrick_kernel::kernel::KernelContext,
    mm: carrick_kernel::kernel::MmId,
}

impl PendingChildTidClear {
    fn new(
        clear: carrick_thread::thread::ChildTidClear,
        context: &carrick_kernel::kernel::KernelContext,
    ) -> Result<Self, RuntimeError> {
        if clear.tid().raw() != context.thread().key().tid.raw() {
            return Err(RuntimeError::Configuration(
                "clear-child-tid claim differs from its captured thread".to_owned(),
            ));
        }
        Ok(Self {
            clear,
            context: context.retain_exact(),
            mm: context.shared().mm().id(),
        })
    }

    fn validate(
        &self,
        current: &carrick_kernel::kernel::KernelContext,
    ) -> Result<(), RuntimeError> {
        if self.context.task().key() != current.task().key()
            || self.mm != current.shared().mm().id()
            || !Arc::ptr_eq(self.context.kernel(), current.kernel())
        {
            return Err(RuntimeError::Configuration(
                "clear-child-tid crossed its retained task or MM incarnation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A clear's physical authority is local to one retirement attempt. Dropping
/// this value on a graph reservation refusal cancels every owner permit.
enum PreparedChildTidClear<'a, M> {
    Owner(Box<dyn carrick_guest_mem::PreparedGuestWrite + 'a>),
    Legacy { memory: &'a mut M, address: u64 },
    Invalid,
}

impl<'a, M: carrick_guest_mem::CurrentMmMemory> PreparedChildTidClear<'a, M> {
    fn prepare(
        memory: &'a mut M,
        address: carrick_guest_mem::GuestVa,
    ) -> Result<Self, carrick_guest_mem::MemoryPrepareError> {
        use carrick_guest_mem::{GuestWriteRange, MemoryPrepareError, UserMemoryVenue};
        if memory.user_memory_venue() == UserMemoryVenue::Legacy {
            return Ok(Self::Legacy {
                memory,
                address: address.raw(),
            });
        }
        let Some(range) = GuestWriteRange::new(address, 4) else {
            return Ok(Self::Invalid);
        };
        match memory.prepare_write(&[range]) {
            Ok(write) => Ok(Self::Owner(write)),
            Err(MemoryPrepareError::Fault(carrick_guest_mem::MemoryError::OutOfBounds {
                ..
            })) => Ok(Self::Invalid),
            Err(error) => Err(error),
        }
    }

    fn commit(self) {
        match self {
            Self::Owner(write) => write.commit(&[&0_i32.to_le_bytes()]),
            Self::Legacy { memory, address } => {
                // Legacy backends have no owner suspension protocol. Preserve
                // their invalid-address exit disposition.
                let _ = memory.write_bytes(address, &0_i32.to_le_bytes());
            }
            Self::Invalid => {}
        }
    }
}

/// Prepare while the exact thread is still signal-visible; only a successful
/// graph retirement permits clear and wake. No permit survives a refusal.
pub(super) fn retire_with_child_tid_clear<M, R, D>(
    memory: &mut M,
    clear: &carrick_thread::thread::ChildTidClear,
    retire: impl FnOnce() -> Result<R, D>,
    wake: impl FnOnce(),
) -> Result<Result<R, D>, carrick_guest_mem::MemoryPrepareError>
where
    M: carrick_guest_mem::CurrentMmMemory,
{
    let prepared = PreparedChildTidClear::prepare(memory, clear.address())?;
    match retire() {
        Ok(retired) => {
            prepared.commit();
            wake();
            Ok(Ok(retired))
        }
        Err(deferred) => {
            drop(prepared);
            Ok(Err(deferred))
        }
    }
}

fn wake_persistent_child_tid(
    kernel: &Kernel,
    futex: &FutexTable,
    address: u64,
    zone_mm: Option<u64>,
) {
    let count = if let Some((zone, mm)) = zone::zone_for(zone_mm) {
        let woken = carrick_kernel::el1_zone::wake(zone, mm, address, u32::MAX, 1);
        zone::publish_zone_handbacks(kernel, &woken.handed);
        woken.count
    } else {
        futex.wake(address, 1)
    };
    carrick_kernel::event_ring::rec_futex_wake(address, count);
}

pub(super) enum CloneThreadSpawn {
    Started {
        internal: carrick_kernel::kernel::LinuxTid,
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
            Err(carrick_guest_mem::MemoryError::MetadataAllocation) => {
                carrick_observability::probes::HvpatchCloneTidWriteResult::MetadataAllocation
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
            Err(
                carrick_guest_mem::MemoryError::ReadSuspended(_)
                | carrick_guest_mem::MemoryError::Physical(_)
                | carrick_guest_mem::MemoryError::OwnerWait(_)
                | carrick_guest_mem::MemoryError::Supply(_),
            ) => carrick_observability::probes::HvpatchCloneTidWriteResult::Suspended,
            Err(carrick_guest_mem::MemoryError::OwnerRetired(_)) => {
                carrick_observability::probes::HvpatchCloneTidWriteResult::OwnerRetired
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

#[derive(Default)]
struct ChildTidDrainCustody {
    pending: Vec<PendingChildTidClear>,
    births: std::collections::BTreeSet<carrick_kernel::kernel::ThreadKey>,
}

/// Encapsulates the collection of active persistent vCPU thread handles for a process.
#[derive(Clone, Default)]
pub(crate) struct VcpuThreadRegistry(
    Arc<parking_lot::Mutex<Vec<VcpuThreadHandle>>>,
    Arc<parking_lot::Mutex<ChildTidDrainCustody>>,
);

impl VcpuThreadRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn retain_clear(&self, clear: PendingChildTidClear) {
        self.1.lock().pending.push(clear);
    }

    pub(super) fn take_drained_clears(&self) -> Vec<PendingChildTidClear> {
        std::mem::take(&mut self.1.lock().pending)
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
        Self(handles, Arc::default())
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
        refuse_metadata: bool,
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
                if self.refuse_metadata {
                    return Err(carrick_guest_mem::MemoryError::MetadataAllocation);
                }
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
    fn metadata_refusal_during_tid_copyout_retains_rollback_preimages() {
        let parent = 0x1000;
        let child = 0x2000;
        let mut memory = Memory::default();
        memory.bytes.insert(parent, 11_i32.to_le_bytes().to_vec());
        memory.bytes.insert(child, 22_i32.to_le_bytes().to_vec());
        let transaction = CloneTidOutputTransaction::capture(&memory, parent, child).unwrap();
        memory.fail_write = Some(child);
        memory.refuse_metadata = true;
        assert!(!transaction.publish(&mut memory, 7, ThreadId::synthetic_for_tests(77)));
        assert_eq!(memory.bytes[&parent], 7_i32.to_le_bytes());
        assert_eq!(memory.bytes[&child], 22_i32.to_le_bytes());
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
            threads: self.threads.clone(),
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
            &self.threads,
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
    threads: VcpuThreadRegistry,
    registry: Arc<ThreadRegistry>,
    keeper: ThreadId,
    kicker: Arc<dyn VcpuRegistry>,
    futex: Arc<FutexTable>,
    platform_futex: Arc<dyn PlatformFutex>,
    context: carrick_kernel::kernel::KernelContext,
}

impl PersistentSiblingStopAuthority {
    pub(super) fn publish(&self, kernel: &Kernel) -> Result<(), RuntimeError> {
        publish_persistent_sibling_stop_with(
            &self.threads,
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
    threads: &VcpuThreadRegistry,
    registry: &ThreadRegistry,
    keeper: ThreadId,
    kicker: &dyn VcpuRegistry,
    futex: &FutexTable,
    platform_futex: &dyn PlatformFutex,
    context: &carrick_kernel::kernel::KernelContext,
    kernel: &Kernel,
) -> Result<(), RuntimeError> {
    // Clone/adoption admission is already closed and drained by the caller.
    // Bind before removing numeric membership; retained contexts pin exact
    // thread claims across a concurrent retirement and subsequent TID reuse.
    let witnesses = context.task_binding().capture_threads().map_err(|error| {
        RuntimeError::Configuration(format!("capture sibling clear custody: {error}"))
    })?;
    for witness in witnesses {
        if witness.thread().key().tid.raw() == keeper.raw() {
            continue;
        }
        let tid = ThreadId::from_kernel_thread_identity(witness.thread().key().tid.raw());
        if let Some(clear) = registry.claim_clear_child_tid(tid) {
            threads.retain_clear(PendingChildTidClear::new(clear, &witness)?);
        } else if witness.thread().execution_state().generation().is_none()
            && !witness.thread().child_tid_cleared_in_zone()
            && threads.1.lock().births.insert(witness.thread().key())
            && let Some(clear) = registry
                .claim_detached_child_tid(tid, witness.thread().control_slot().clear_child_tid())
        {
            threads.retain_clear(PendingChildTidClear::new(clear, &witness)?);
        }
    }
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
        &mut self,
        kernel: &Kernel,
        _engine: &mut E,
    ) -> bool {
        let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 1);
        let last = self.registry.exit(self.this_tid);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 2);
        carrick_kernel::run_state::clear_guest_tid(self.this_tid.raw());
        self.kicker.unregister(self.this_tid);
        self.kicker.retire_kernel_wake_debt(self.this_tid);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 3);
        carrick_signal_linux::forget_thread(self.this_tid.raw());
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 4);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 5);
        last
    }

    pub(super) fn commit_terminal_child_tid<R, D>(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        retire: impl FnOnce() -> Result<R, D>,
    ) -> Result<Result<R, D>, carrick_guest_mem::MemoryPrepareError> {
        let Some(clear) = self.child_tid_clear.as_ref() else {
            return Ok(retire());
        };
        let result = retire_with_child_tid_clear(engine, &clear.clear, retire, || {
            wake_persistent_child_tid(
                kernel,
                &self.futex,
                clear.clear.address().raw(),
                self.zone_mm,
            );
        })?;
        if result.is_ok()
            && let Some(clear) = self.child_tid_clear.take()
        {
            clear.clear.settle();
        }
        Ok(result)
    }

    pub(super) fn drain_child_tid_clears(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
    ) -> Result<(), PersistentThreadExitDisposition> {
        let pending = self
            .drained_child_tid_clears
            .get_or_insert_with(|| self.threads.take_drained_clears());
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            PersistentThreadExitDisposition::Failed(RuntimeError::Configuration(
                "clear drain lost live owner context".to_owned(),
            ))
        })?;
        let process = kernel.hvpatch_process.as_ref().ok_or_else(|| {
            PersistentThreadExitDisposition::Failed(RuntimeError::Configuration(
                "clear drain lost carrier process".to_owned(),
            ))
        })?;
        while let Some(clear) = pending.pop() {
            // settled() may have folded an EL1 exit since the census. Its
            // exact-incarnation receipt survives ABI EntryRef reuse: never
            // clear a stack the completed in-zone wake already released.
            if clear.context.thread().child_tid_cleared_in_zone() {
                clear.clear.settle();
                continue;
            }
            if let Err(error) = clear.validate(context) {
                pending.push(clear);
                return Err(PersistentThreadExitDisposition::Failed(error));
            }
            let result = retire_with_child_tid_clear(
                engine,
                &clear.clear,
                || {
                    let retired = process.exit_exact_thread(&clear.context);
                    if clear.context.thread().child_tid_cleared_in_zone() {
                        return Err(retired);
                    }
                    match retired {
                        retired @ Ok(
                            carrick_kernel::kernel::ProcessThreadExit::Retired(_)
                            | carrick_kernel::kernel::ProcessThreadExit::AlreadyRetired,
                        ) => Ok(retired),
                        deferred => Err(deferred),
                    }
                },
                || {
                    wake_persistent_child_tid(
                        kernel,
                        &self.futex,
                        clear.clear.address().raw(),
                        self.zone_mm,
                    )
                },
            );
            match result {
                Ok(Ok(Ok(retired))) => {
                    clear.clear.settle();
                    if let carrick_kernel::kernel::ProcessThreadExit::Retired(retired) = retired {
                        kernel.dispatcher.close_draining_file_table(
                            process.kernel_graph(),
                            &retired.files(),
                            Some(retired.owner()),
                            None,
                        );
                    }
                }
                Ok(Err(Ok(carrick_kernel::kernel::ProcessThreadExit::AlreadyRetired)))
                    if clear.context.thread().child_tid_cleared_in_zone() =>
                {
                    clear.clear.settle();
                }
                result => {
                    pending.push(clear);
                    return Err(match result {
                        Err(error) => PersistentThreadExitDisposition::Memory(error),
                        Ok(Err(Ok(carrick_kernel::kernel::ProcessThreadExit::Busy {
                            observed_epoch,
                        }))) => PersistentThreadExitDisposition::Busy { observed_epoch },
                        other => {
                            PersistentThreadExitDisposition::Failed(RuntimeError::Configuration(
                                format!("clear drain could not retire exact sibling: {other:?}"),
                            ))
                        }
                    });
                }
            }
        }
        Ok(())
    }

    pub(super) fn finish_child_tid_drain(&mut self) {
        self.drained_child_tid_clears = None;
        self.threads.1.lock().births.clear();
    }

    pub(super) fn capture_child_tid_clear(&mut self) -> Result<(), RuntimeError> {
        if self.child_tid_clear.is_none()
            && let Some(clear) = self.registry.claim_clear_child_tid(self.this_tid)
        {
            let context = self.service_kernel_context.as_ref().ok_or_else(|| {
                RuntimeError::Configuration("clear-child-tid lost exact context".to_owned())
            })?;
            self.child_tid_clear = Some(PendingChildTidClear::new(clear, context)?);
        }
        Ok(())
    }

    pub(super) fn handoff_child_tid_clear(&mut self) {
        if let Some(clear) = self.child_tid_clear.take() {
            self.threads.retain_clear(clear);
        }
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
        if let Err(error) = self.capture_child_tid_clear() {
            return PersistentThreadExitDisposition::Failed(error);
        }
        let mut last = false;
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            let Some(context) = self.service_kernel_context.as_ref() else {
                return PersistentThreadExitDisposition::Failed(RuntimeError::Configuration(
                    "thread exit lost its exact Kernel context".to_owned(),
                ));
            };
            let retire = || {
                let context = self
                    .child_tid_clear
                    .as_ref()
                    .map_or(context, |clear| &clear.context);
                match process.exit_exact_thread(context) {
                    retired @ Ok(
                        carrick_kernel::kernel::ProcessThreadExit::Retired(_)
                        | carrick_kernel::kernel::ProcessThreadExit::AlreadyRetired,
                    ) => Ok(retired),
                    deferred => Err(deferred),
                }
            };
            let retirement = if let Some(clear) = self.child_tid_clear.as_ref() {
                if let Err(error) = clear.validate(context) {
                    return PersistentThreadExitDisposition::Failed(error);
                }
                match retire_with_child_tid_clear(engine, &clear.clear, retire, || {
                    wake_persistent_child_tid(
                        kernel,
                        &self.futex,
                        clear.clear.address().raw(),
                        self.zone_mm,
                    );
                }) {
                    Ok(Ok(retired)) => {
                        if let Some(clear) = self.child_tid_clear.take() {
                            clear.clear.settle();
                        }
                        retired
                    }
                    Ok(Err(deferred)) => deferred,
                    Err(wait) => return PersistentThreadExitDisposition::Memory(wait),
                }
            } else {
                match retire() {
                    Ok(result) | Err(result) => result,
                }
            };
            match retirement {
                Ok(carrick_kernel::kernel::ProcessThreadExit::Retired(retired)) => {
                    // No physical permit or execution loan survives the clear
                    // and wake above into these potentially blocking closes.
                    kernel.dispatcher.close_draining_file_table(
                        process.kernel_graph(),
                        &retired.files(),
                        Some(retired.owner()),
                        None,
                    );
                }
                Ok(carrick_kernel::kernel::ProcessThreadExit::AlreadyRetired) => {}
                Ok(carrick_kernel::kernel::ProcessThreadExit::Busy { observed_epoch }) => {
                    return PersistentThreadExitDisposition::Busy { observed_epoch };
                }
                Ok(carrick_kernel::kernel::ProcessThreadExit::LastThread) => last = true,
                Err(error) => {
                    return PersistentThreadExitDisposition::Failed(RuntimeError::Configuration(
                        format!("retire exact clear-child-tid thread: {error}"),
                    ));
                }
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
    Memory(carrick_guest_mem::MemoryPrepareError),
    Failed(RuntimeError),
    /// The kernel graph holds a task reservation (a sibling exec/fork/exit
    /// transaction). The job parks as a scheduler-visible retry subscribed
    /// to the reservation-change epoch — blocking the executor here
    /// deadlocks against a holder that needs this executor's
    /// command-service point (the execfromthread ABBA wedge).
    Busy {
        observed_epoch: u64,
    },
}

pub(super) fn wake_removed_persistent_sibling_threads(
    context: &carrick_kernel::kernel::KernelContext,
    scheduler: &Arc<carrick_kernel::kernel::Scheduler>,
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
            && !matches!(error, carrick_kernel::kernel::SchedulerError::UnknownThread)
            && !matches!(
                thread.execution_state(),
                carrick_kernel::kernel::objects::ThreadExecutionState::Exited { .. }
                    | carrick_kernel::kernel::objects::ThreadExecutionState::Failed { .. }
            )
        {
            return Err(RuntimeError::Configuration(format!(
                "wake exact persistent sibling for terminal transition: {error}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod child_tid_owner_tests {
    use super::*;
    use carrick_el1::personality::mm_portal::{
        GuestVa as OwnerVa, MmError, MmPortal, TransferIntent,
        test_support::{IPA, NoPin, ROOT, Region, Tables, VA, admit_notified, nodes, residency},
    };
    use carrick_guest_mem::{GuestMemory, MemoryError, UserMemoryVenue};
    use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct OwnerClearMemory<'a> {
        portal: &'a MmPortal<'a, NoPin>,
        handle: carrick_el1_abi::El1MmHandle,
        tables: &'a Tables,
        bytes: [u8; 4],
        waits: usize,
    }
    impl GuestMemory for OwnerClearMemory<'_> {
        fn user_memory_venue(&self) -> UserMemoryVenue {
            UserMemoryVenue::Owner
        }
        fn prepare_write(
            &mut self,
            ranges: &[carrick_guest_mem::GuestWriteRange],
        ) -> Result<
            Box<dyn carrick_guest_mem::PreparedGuestWrite + '_>,
            carrick_guest_mem::MemoryPrepareError,
        > {
            assert_eq!(ranges.len(), 1);
            match self.write_bytes_raw(ranges[0].address().raw(), &0_i32.to_le_bytes()) {
                Err(MemoryError::OwnerWait(wait)) => {
                    Err(carrick_guest_mem::MemoryPrepareError::OwnerWait(wait))
                }
                other => panic!("closed real owner gate unexpectedly prepared: {other:?}"),
            }
        }
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            assert_eq!((address, length), (VA, 4));
            Ok(self.bytes.to_vec())
        }
        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            assert_eq!((address, bytes.len()), (VA, 4));
            let transfer = self
                .portal
                .begin(
                    self.handle,
                    OwnerVa::new(address),
                    4,
                    TransferIntent::UserWrite,
                    0,
                )
                .unwrap();
            let result = self.portal.select(
                &transfer,
                &self.tables.live(&CallerInvalidatesAsid),
                &mut carrick_el1::fault::NoopPreparedResolver,
                &mut carrick_el1::fault::NoopCowResolver,
                &residency(),
                0,
            );
            match result {
                Err(MmError::Wait(wait)) => {
                    assert_eq!(wait.handle(), self.handle);
                    assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Gate);
                    self.waits += 1;
                    Err(MemoryError::OwnerWait(wait))
                }
                other => panic!("closed owner gate must refuse before copying: {other:?}"),
            }
        }
    }
    impl carrick_guest_mem::CurrentMmMemory for OwnerClearMemory<'_> {}

    #[test]
    fn owner_clear_child_tid_wait_must_not_wake_joiner_before_clear() {
        let region = Region::new();
        let zone = region.zone();
        let mm = admit_notified(&region, 77, ROOT, 1, 0);
        let view = nodes(&region);
        let portal = MmPortal::new(
            NonZeroU64::new(1).unwrap(),
            region.table(),
            &zone.spaces,
            &view,
        )
        .with_zone(zone)
        .unwrap();
        let handle = portal.admitted_handle(mm, 0).unwrap();
        let tables = Tables::new(ROOT, IPA, 1);
        let owner = ThreadId::synthetic_for_tests(70_303);
        let registry = ThreadRegistry::new(owner);
        registry.set_clear_child_tid(owner, VA);
        let futex = FutexTable::new();
        let wait = futex.prepare_wait(VA);
        let wakes = Arc::new(AtomicUsize::new(0));
        let observer = Arc::clone(&wakes);
        let enrollment = futex.subscribe_generation(
            wait,
            Arc::new(move |_| {
                observer.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let mut memory = OwnerClearMemory {
            portal: &portal,
            handle,
            tables: &tables,
            bytes: owner.raw().to_le_bytes(),
            waits: 0,
        };
        let access =
            carrick_el1::sched::object_wait::space_access(zone, carrick_sched_core::SlotId::new(1));
        let index = zone.spaces.find(mm.raw()).unwrap();
        access.raise(index);
        let clear = registry.claim_clear_child_tid(owner).unwrap();
        let result = retire_with_child_tid_clear(
            &mut memory,
            &clear,
            || -> Result<(), ()> { panic!("owner wait retired the signal-visible thread") },
            || {
                futex.wake(VA, 1);
            },
        );
        assert!(matches!(
            result,
            Err(carrick_guest_mem::MemoryPrepareError::OwnerWait(_))
        ));
        access.lower(index);
        assert_eq!(memory.waits, 1, "must exercise the production owner's gate");
        assert_eq!(memory.bytes, owner.raw().to_le_bytes());
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            0,
            "owner wait must retain clear_child_tid before waking or retiring the thread"
        );
        drop(enrollment);
    }

    #[derive(Debug, Default)]
    struct ClearDependency(std::sync::atomic::AtomicBool);
    impl carrick_guest_mem::PhysicalMemoryWait for ClearDependency {
        fn is_ready(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn enroll(
            &self,
            _wake: Arc<dyn Fn() + Send + Sync>,
        ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool) {
            (Box::new(()), self.is_ready())
        }
    }

    fn clear_state(
        kernel: &Kernel,
        context: &carrick_kernel::kernel::KernelContext,
        registry: Arc<ThreadRegistry>,
        threads: VcpuThreadRegistry,
    ) -> ThreadRuntimeState<super::super::tests::CrashCaptureTestEngine> {
        use super::super::tests::{CrashCaptureTestEngine, NoopPlatformFutex};
        let tid = ThreadId::from_kernel_thread_identity(context.thread().key().tid.raw());
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            registry,
            Arc::new(FutexTable::new()),
            Arc::new(NoopPlatformFutex),
            Arc::new(|_| Arc::new(NoopPlatformFutex)),
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(context.thread())),
            Some(context.task().key().id.raw()),
            context.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            tid,
            threads,
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(context.retain_exact());
        state
    }

    fn clear_kernel(pid: i32) -> (Kernel, carrick_kernel::kernel::KernelContext) {
        use super::super::tests::{EndpointTestSignalArrival, EndpointTestSignalPump};
        let (process, root) = crate::hvpatch::process_context_for_tests(pid);
        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(Arc::new(process.clone()));
        (
            Arc::new(KernelState::new(
                dispatcher,
                Arc::new(EndpointTestSignalPump),
                Arc::new(EndpointTestSignalArrival),
                Some(process),
                None,
            )),
            root,
        )
    }

    fn clear_sibling(
        root: &carrick_kernel::kernel::KernelContext,
    ) -> carrick_kernel::kernel::KernelContext {
        root.kernel()
            .reserve_thread_clone(
                root,
                carrick_kernel::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::THREAD
                        | carrick_abi::LinuxCloneFlags::SIGHAND
                        | carrick_abi::LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(
                root.thread().key().tid.raw() + 1,
            ))
            .unwrap()
            .commit()
            .unwrap()
            .start_thread()
            .unwrap()
            .into_context()
    }

    fn clear_engine(
        context: &carrick_kernel::kernel::KernelContext,
        dependency: &Arc<ClearDependency>,
    ) -> super::super::tests::CrashCaptureTestEngine {
        let mut engine = super::super::tests::CrashCaptureTestEngine {
            prepare_dependency: Some(carrick_guest_mem::OwnedMemoryWait(dependency.clone())),
            prepared_write_context: Some(context.retain_exact()),
            ..Default::default()
        };
        engine
            .guest_memory
            .insert(VA, context.thread().key().tid.raw().to_le_bytes().to_vec());
        engine
    }

    fn clear_wakes(futex: &FutexTable) -> (Arc<AtomicUsize>, impl Sized + use<>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&wakes);
        let subscription = futex.subscribe_generation(
            futex.prepare_wait(VA),
            Arc::new(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
            }),
        );
        (wakes, subscription)
    }

    #[test]
    fn serial_host_normal_child_tid_exit_waits_and_cancels_permit_before_graph_retry() {
        let (kernel, root) = clear_kernel(72_510);
        let sibling = clear_sibling(&root);
        let tid = ThreadId::from_kernel_thread_identity(sibling.thread().key().tid.raw());
        let registry = Arc::new(ThreadRegistry::new(tid));
        registry.set_clear_child_tid(tid, VA);
        let mut state = clear_state(
            &kernel,
            &sibling,
            registry.clone(),
            VcpuThreadRegistry::new(),
        );
        let dependency = Arc::new(ClearDependency::default());
        let mut engine = clear_engine(&sibling, &dependency);
        let (wakes, _subscription) = clear_wakes(&state.futex);
        assert!(matches!(
            state.handle_persistent_thread_exit(&kernel, &mut engine, 0, 0),
            PersistentThreadExitDisposition::Memory(
                carrick_guest_mem::MemoryPrepareError::Physical(_)
            )
        ));
        assert!(sibling.exact_thread_is_live());
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        dependency.0.store(true, Ordering::Release);
        let reservation = root
            .kernel()
            .prepare_task_exit_key(
                root.task().key(),
                carrick_kernel::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .unwrap();
        assert!(matches!(
            state.handle_persistent_thread_exit(&kernel, &mut engine, 0, 0),
            PersistentThreadExitDisposition::Busy { .. }
        ));
        assert_eq!((engine.prepared_cancels, engine.prepared_commits), (1, 0));
        assert!(sibling.exact_thread_is_live());
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        drop(reservation);
        assert!(matches!(
            state.handle_persistent_thread_exit(&kernel, &mut engine, 0, 0),
            PersistentThreadExitDisposition::Done(VcpuLoopOutcome::ThreadDone)
        ));
        assert_eq!(engine.guest_memory[&VA], [0; 4]);
        assert_eq!(engine.prepared_commits, 1);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert!(!registry.is_clear_child_tid_addr(VA));
    }

    #[test]
    fn serial_host_terminal_owner_child_tid_wait_keeps_graph_live_until_commit() {
        let (kernel, root) = clear_kernel(72_520);
        let tid = ThreadId::from_kernel_thread_identity(root.thread().key().tid.raw());
        let registry = Arc::new(ThreadRegistry::new(tid));
        registry.set_clear_child_tid(tid, VA);
        let mut state = clear_state(&kernel, &root, registry.clone(), VcpuThreadRegistry::new());
        state.capture_child_tid_clear().unwrap();
        let dependency = Arc::new(ClearDependency::default());
        let mut engine = clear_engine(&root, &dependency);
        let (wakes, _subscription) = clear_wakes(&state.futex);
        state.withdraw_persistent_terminal_owner_runtime(&kernel, &mut engine);
        let prepare = || {
            root.kernel()
                .prepare_task_exit_key(
                    root.task().key(),
                    carrick_kernel::kernel::LinuxWaitStatus::from_wait_encoding(0),
                    None,
                )
                .unwrap()
        };
        let graph_exit = prepare();
        assert!(matches!(
            state.commit_terminal_child_tid(&kernel, &mut engine, || graph_exit
                .retire_notifying(|_| {})),
            Err(carrick_guest_mem::MemoryPrepareError::Physical(_))
        ));
        assert!(root.exact_thread_is_live());
        assert!(root.kernel().task_key_is_live(root.task().key()));
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        assert!(registry.is_clear_child_tid_addr(VA));
        dependency.0.store(true, Ordering::Release);
        let graph_exit = prepare();
        let publication = state
            .commit_terminal_child_tid(&kernel, &mut engine, || graph_exit.retire_notifying(|_| {}))
            .unwrap()
            .unwrap();
        assert_eq!(engine.guest_memory[&VA], [0; 4]);
        assert_eq!(engine.prepared_commits, 1);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert!(!registry.is_clear_child_tid_addr(VA));
        publication.publish().unwrap();
    }

    #[test]
    fn serial_host_unadopted_child_tid_is_captured_without_runtime_member() {
        let (kernel, root) = clear_kernel(72_540);
        let sibling = clear_sibling(&root);
        assert!(sibling.thread().execution_state().generation().is_none());
        sibling.thread().control_slot().set_clear_child_tid(VA);
        let root_tid = ThreadId::from_kernel_thread_identity(root.thread().key().tid.raw());
        let registry = Arc::new(ThreadRegistry::new(root_tid));
        let threads = VcpuThreadRegistry::new();
        let mut owner = clear_state(&kernel, &root, registry.clone(), threads.clone());
        let receipt = kernel.try_claim_persistent_process_exit(root_tid).unwrap();
        assert_eq!(receipt.claim, ProcessExitClaim::Owner);
        // No runtime row, scheduler activation or member completion exists for
        // this born thread. The closed-admission graph census is its authority.
        owner.publish_persistent_sibling_stop(&kernel).unwrap();
        owner.publish_persistent_sibling_stop(&kernel).unwrap();
        assert_eq!(threads.1.lock().pending.len(), 1);
        let dependency = Arc::new(ClearDependency::default());
        dependency.0.store(true, Ordering::Release);
        let mut engine = clear_engine(&sibling, &dependency);
        let (wakes, _subscription) = clear_wakes(&owner.futex);
        assert!(owner.drain_child_tid_clears(&kernel, &mut engine).is_ok());
        assert!(!sibling.exact_thread_is_live());
        assert_eq!(engine.guest_memory[&VA], [0; 4]);
        assert_eq!(engine.prepared_commits, 1);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert!(!registry.is_clear_child_tid_addr(VA));
    }

    #[test]
    fn serial_host_retired_loser_child_tid_moves_to_live_drain_before_completion() {
        let (kernel, root) = clear_kernel(72_530);
        let sibling = clear_sibling(&root);
        let root_tid = ThreadId::from_kernel_thread_identity(root.thread().key().tid.raw());
        let tid = ThreadId::from_kernel_thread_identity(sibling.thread().key().tid.raw());
        let registry = Arc::new(ThreadRegistry::new(root_tid));
        registry.register_child_with_tid(tid, VA);
        let threads = VcpuThreadRegistry::new();
        let mut loser = clear_state(&kernel, &sibling, registry.clone(), threads.clone());
        let mut owner = clear_state(&kernel, &root, registry.clone(), threads.clone());
        let dependency = Arc::new(ClearDependency::default());
        let mut engine = clear_engine(&sibling, &dependency);
        let (wakes, _subscription) = clear_wakes(&owner.futex);
        loser.capture_child_tid_clear().unwrap();
        registry.remove_all_except(root_tid);
        root.kernel().exit_thread(&sibling, None).unwrap();
        loser.handoff_child_tid_clear();
        drop(loser);
        assert!(matches!(
            owner.drain_child_tid_clears(&kernel, &mut engine),
            Err(PersistentThreadExitDisposition::Memory(
                carrick_guest_mem::MemoryPrepareError::Physical(_)
            ))
        ));
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        assert!(registry.is_clear_child_tid_addr(VA));
        assert!(
            threads.take_drained_clears().is_empty(),
            "retry must retain its batch, not reclaim the population"
        );
        dependency.0.store(true, Ordering::Release);
        assert!(owner.drain_child_tid_clears(&kernel, &mut engine).is_ok());
        assert!(owner.drain_child_tid_clears(&kernel, &mut engine).is_ok());
        assert_eq!(engine.guest_memory[&VA], [0; 4]);
        assert_eq!(engine.prepared_commits, 1);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert!(!registry.is_clear_child_tid_addr(VA));
    }
}
