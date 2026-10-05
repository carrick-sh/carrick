//! sched_setaffinity(2) / sched_getaffinity(2) name a thread, including a
//! thread-group leader when a sibling supplies getpid(). Numeric names are
//! resolved in the caller's namespace and retained as exact kernel objects.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use carrick_abi::{LinuxCloneFlags, syscall::nr};
use carrick_hal::{CpuAffinity, GuestCpuId, NullGuestTimerBridge, NullHostSignalBridge, ThreadId};
use carrick_kernel::compat::{CompatReporter, SyscallArgs};
use carrick_kernel::dispatch::{
    CarrierBridges, DispatchOutcome, SyscallDispatcher, SyscallRequest, ThreadCtx,
};
use carrick_kernel::kernel::{CarrierProcess, ClonePlan, KernelContext};
use carrick_kernel::thread::{FutexTable, ThreadRegistry};
use carrick_kernel_example::{AddressSpace, AsidAllocator, ExampleProcess, TaskMemory};
use std::sync::Arc;

struct Fixture {
    root: KernelContext,
    sibling: KernelContext,
    peer: KernelContext,
    _peer_process: Arc<ExampleProcess>,
    dispatcher: SyscallDispatcher,
    registry: ThreadRegistry,
    futex: FutexTable,
    memory: TaskMemory,
}

impl Fixture {
    fn new() -> Self {
        let asids = AsidAllocator::new();
        let space = AddressSpace::allocate(&asids).unwrap();
        let (process, root) = ExampleProcess::boot_root(
            1,
            "affinity syscall target",
            Arc::new(NullHostSignalBridge::default()),
            space,
        )
        .unwrap();
        root.thread().set_affinity(CpuAffinity::all(2));
        let sibling = root
            .kernel()
            .reserve_thread_clone(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(59_401))
            .unwrap()
            .commit()
            .unwrap()
            .start_thread()
            .unwrap()
            .into_context();
        sibling
            .thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));
        let reservation = root
            .kernel()
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "affinity peer".to_owned(),
                None,
            )
            .unwrap();
        let tid = ThreadId::from_guest_supplied_tid(reservation.visible_child_id());
        let space = AddressSpace::allocate(&asids).unwrap();
        let (peer, _) = reservation
            .prepare_with_mm_backend(space.mm_backend(), tid)
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap();
        peer.thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));
        let peer_process = Arc::new(ExampleProcess::new(&peer, space));
        let dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
            host_signal: Arc::new(NullHostSignalBridge::default()),
            timers: Arc::new(NullGuestTimerBridge::default()),
        });
        dispatcher.bind_hvpatch_process(Arc::new(process) as Arc<dyn CarrierProcess>);
        let registry = ThreadRegistry::new(root.thread().registry_id());
        registry.register_child_with_tid(
            ThreadId::from_guest_supplied_tid(sibling.thread().key().tid.raw()),
            0,
        );
        Self {
            root,
            sibling,
            peer,
            _peer_process: peer_process,
            dispatcher,
            registry,
            futex: FutexTable::new(),
            memory: TaskMemory::new(),
        }
    }

    fn dispatch(
        &mut self,
        caller: &KernelContext,
        nr: carrick_abi::CanonicalNr,
        pid: u64,
        bytes: &[u8],
    ) -> DispatchOutcome {
        let caller = caller
            .task_binding()
            .capture(caller.thread().key().tid)
            .unwrap();
        let address = self.memory.put(bytes).unwrap();
        let mut executor = self.dispatcher.enter_mm_executor().unwrap();
        self.dispatcher
            .dispatch_threaded_with_mm_executor(
                &mut executor,
                &caller,
                SyscallRequest::new(
                    nr.raw(),
                    SyscallArgs::from([pid, bytes.len() as u64, address, 0, 0, 0]),
                ),
                &mut self.memory.linear,
                &CompatReporter::default(),
                ThreadCtx::new(caller.thread().registry_id(), &self.registry, &self.futex),
            )
            .unwrap()
    }

    fn get_mask(&mut self, caller: &KernelContext, target: &KernelContext) -> u64 {
        let caller = caller
            .task_binding()
            .capture(caller.thread().key().tid)
            .unwrap();
        let address = self.memory.alloc_zeroed(128).unwrap();
        let mut executor = self.dispatcher.enter_mm_executor().unwrap();
        let outcome = self
            .dispatcher
            .dispatch_threaded_with_mm_executor(
                &mut executor,
                &caller,
                SyscallRequest::new(
                    nr::SCHED_GETAFFINITY.raw(),
                    SyscallArgs::from([
                        target.thread().key().tid.raw() as u64,
                        128,
                        address,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut self.memory.linear,
                &CompatReporter::default(),
                ThreadCtx::new(caller.thread().registry_id(), &self.registry, &self.futex),
            )
            .unwrap();
        assert!(
            matches!(outcome, DispatchOutcome::Returned { value } if value > 0),
            "{outcome:?}"
        );
        u64::from_le_bytes(self.memory.read(address, 8).unwrap().try_into().unwrap())
    }
}

#[test]
fn sibling_setaffinity_changes_only_the_named_thread() {
    let mut f = Fixture::new();
    let caller = f.root.retain_exact();
    let sibling = f.sibling.retain_exact();
    let outcome = f.dispatch(
        &caller,
        nr::SCHED_SETAFFINITY,
        sibling.thread().key().tid.raw() as u64,
        &2u64.to_le_bytes(),
    );
    assert!(
        matches!(outcome, DispatchOutcome::Returned { value: 0 }),
        "{outcome:?}"
    );
    assert_eq!(
        sibling.thread().affinity().words()[0],
        2,
        "named sibling must change"
    );
    assert_eq!(
        caller.thread().affinity().words()[0],
        3,
        "caller must retain its mask"
    );
    assert_eq!(f.get_mask(&caller, &sibling), 2);
    assert_eq!(f.get_mask(&sibling, &sibling), 2);
}

#[test]
fn other_process_setaffinity_changes_only_the_named_thread() {
    let mut f = Fixture::new();
    let caller = f.root.retain_exact();
    let peer = f.peer.retain_exact();
    let outcome = f.dispatch(
        &caller,
        nr::SCHED_SETAFFINITY,
        peer.thread().key().tid.raw() as u64,
        &2u64.to_le_bytes(),
    );
    assert!(
        matches!(outcome, DispatchOutcome::Returned { value: 0 }),
        "{outcome:?}"
    );
    assert_eq!(
        peer.thread().affinity().words()[0],
        2,
        "named other process must change"
    );
    assert_eq!(
        caller.thread().affinity().words()[0],
        3,
        "caller must retain its mask"
    );
    assert_eq!(f.get_mask(&caller, &peer), 2);
}

#[test]
fn getaffinity_reads_the_named_thread_including_the_leader_from_a_sibling() {
    let mut f = Fixture::new();
    let caller = f.root.retain_exact();
    let sibling = f.sibling.retain_exact();
    let peer = f.peer.retain_exact();
    assert_eq!(
        f.get_mask(&caller, &sibling),
        1,
        "sibling query must not read caller"
    );
    assert_eq!(
        f.get_mask(&caller, &peer),
        1,
        "other process query must not read caller"
    );
    assert_eq!(
        f.get_mask(&sibling, &caller),
        3,
        "getpid names the leader, not the calling sibling"
    );
}

#[test]
fn affinity_errors_leave_both_masks_unchanged() {
    let mut f = Fixture::new();
    let caller = f.root.retain_exact();
    let peer = f.peer.retain_exact();
    let empty = f.dispatch(
        &caller,
        nr::SCHED_SETAFFINITY,
        peer.thread().key().tid.raw() as u64,
        &0u64.to_le_bytes(),
    );
    assert!(
        matches!(empty, DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_EINVAL),
        "empty intersection: {empty:?}"
    );
    let missing = f.dispatch(
        &caller,
        nr::SCHED_SETAFFINITY,
        i32::MAX as u64,
        &2u64.to_le_bytes(),
    );
    assert!(
        matches!(missing, DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_ESRCH),
        "missing thread: {missing:?}"
    );
    let dropped_uid = f.dispatch(&caller, nr::SETUID, 100, &[]);
    assert!(
        matches!(dropped_uid, DispatchOutcome::Returned { value: 0 }),
        "{dropped_uid:?}"
    );
    let denied = f.dispatch(
        &caller,
        nr::SCHED_SETAFFINITY,
        peer.thread().key().tid.raw() as u64,
        &2u64.to_le_bytes(),
    );
    assert!(
        matches!(denied, DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_EPERM),
        "cross-owner permission: {denied:?}"
    );
    assert_eq!(caller.thread().affinity().words()[0], 3);
    assert_eq!(peer.thread().affinity().words()[0], 1);
    assert_eq!(
        f.get_mask(&caller, &peer),
        1,
        "queries require no ownership permission"
    );
}
