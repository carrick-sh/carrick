use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use carrick_hal::{InGuestFlag, ThreadId, VcpuRegistrationEnrollment, VcpuRegistry};

use super::*;
use crate::kernel::{Kernel, KernelContext, RootBootstrap};

fn bootstrap_thread(pid: i32) -> (Arc<Kernel>, KernelContext) {
    let input = RootBootstrap::for_reference_model(
        pid,
        ThreadId::synthetic_for_tests(pid),
        "root".to_owned(),
    )
    .expect("bootstrap input");
    Kernel::bootstrap_root(input).expect("kernel")
}

fn mm(raw: u64) -> MmId {
    MmId::from_registry_allocation(std::num::NonZeroU64::new(raw).unwrap())
}

fn fence() -> MmFence {
    Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new())
}

#[derive(Clone)]
struct CountKick(Arc<AtomicUsize>);
impl carrick_hal::VcpuKick for CountKick {
    fn kick(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A registered vCPU: its registry, flag and kick counter.
struct Vcpu {
    registry: Arc<carrick_hal::GenericVcpuRegistry>,
    tid: ThreadId,
    flag: Arc<InGuestFlag>,
    kicks: Arc<AtomicUsize>,
}

impl Vcpu {
    fn new(tid: i32) -> Self {
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let tid = ThreadId::synthetic_for_tests(tid);
        let flag = Arc::new(InGuestFlag::for_guest_thread());
        let kicks = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            registry.subscribe_register(
                tid,
                Box::new(CountKick(kicks.clone())),
                &flag,
                Arc::new(|| {})
            ),
            VcpuRegistrationEnrollment::Registered
        ));
        Self {
            registry,
            tid,
            flag,
            kicks,
        }
    }

    fn occupy(
        &self,
        slot: &HostExecutionSlot,
        mm: MmId,
        fence: &MmFence,
    ) -> Result<MmOccupancy, MmOccupancyError> {
        MmOccupancy::install_registered_for_test(
            slot.slot(),
            mm,
            fence,
            self.registry.clone(),
            self.tid,
        )
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        self.registry.unregister(self.tid);
    }
}

/// Green of the red-first `kernel.mm.address-space-occupancy` case (the red
/// ran against the exact-MM census at 3c52608b8): a vCPU whose executor
/// loaded a thread of Y but which now runs Z is drained by a pause of Z and
/// not waited for by a pause of Y.
#[test]
fn a_pause_of_z_drains_a_vcpu_switched_from_y_to_z() {
    let (y, z) = (mm(41_001), mm(41_002));
    let (fence_y, fence_z) = (fence(), fence());
    let slot = HostExecutionSlot::allocate().unwrap();
    let vcpu = Vcpu::new(41_010);
    let mut occupancy = vcpu.occupy(&slot, y, &fence_y).unwrap();
    occupancy.switch_for_test(z, &fence_z);
    vcpu.flag.enter_guest();

    assert!(residents(y, &fence_y, None).is_empty());
    let tid = ThreadId::synthetic_for_tests(41_011);
    let refused = crate::dispatch::mm_quiesce::try_acquire_pt_pause_for_test(
        &fence_z,
        z,
        tid,
        crate::dispatch::mm_quiesce::PtPauseBudget::DEFAULT,
    );
    assert!(
        matches!(
            refused,
            Err(crate::dispatch::mm_quiesce::PtPauseTryError::SiblingInGuest)
        ),
        "a pause of Z must not be granted while a vCPU running Z is in guest"
    );
    assert_eq!(vcpu.kicks.load(Ordering::SeqCst), 1, "the pause kicks it");
    vcpu.flag.leave_guest();
    let Ok(granted) = crate::dispatch::mm_quiesce::try_acquire_pt_pause_for_test(
        &fence_z,
        z,
        tid,
        crate::dispatch::mm_quiesce::PtPauseBudget::DEFAULT,
    ) else {
        panic!("granted once the vCPU left the guest");
    };
    assert_eq!(granted.drained_count(), 1);
    drop(granted);
    drop(occupancy);
    assert!(residents(z, &fence_z, None).is_empty());
}

/// Two processes share an MM (the vfork shape): the population of the MM is
/// every vCPU running it, whichever process's thread its executor loaded.
#[test]
fn every_vcpu_running_an_mm_is_counted_whatever_process_it_loaded() {
    let (_parent_kernel, _parent) = bootstrap_thread(41_100);
    let (_child_kernel, _child) = bootstrap_thread(41_200);
    let shared = mm(41_101);
    let shared_fence = fence();
    let (a, b) = (
        HostExecutionSlot::allocate().unwrap(),
        HostExecutionSlot::allocate().unwrap(),
    );
    let (parent_vcpu, child_vcpu) = (Vcpu::new(41_110), Vcpu::new(41_210));
    let _parent = MmOccupancy::install_registered_for_test(
        a.slot(),
        shared,
        &shared_fence,
        parent_vcpu.registry.clone(),
        parent_vcpu.tid,
    )
    .unwrap();
    let _child = MmOccupancy::install_registered_for_test(
        b.slot(),
        shared,
        &shared_fence,
        child_vcpu.registry.clone(),
        child_vcpu.tid,
    )
    .unwrap();
    let everyone = residents(shared, &shared_fence, None);
    let mut tids = everyone.tids();
    tids.sort_by_key(|tid| tid.raw());
    assert_eq!(tids, [parent_vcpu.tid, child_vcpu.tid]);
    assert_eq!(
        residents(shared, &shared_fence, Some(a.slot())).tids(),
        [child_vcpu.tid]
    );
    assert_eq!(kick_running(shared, &shared_fence, Some(a.slot())), 1);
    assert_eq!(parent_vcpu.kicks.load(Ordering::SeqCst), 0);
    assert_eq!(child_vcpu.kicks.load(Ordering::SeqCst), 1);
    // The same MM id under another kernel graph's fence is another MM.
    assert!(residents(shared, &fence(), None).is_empty());
    assert!(is_running_anywhere(shared, &shared_fence));
}

/// `kernel.mm.executor-admission`: a rejected install on an occupied slot
/// leaves the running occupant and its exact endpoint in place, and a drain
/// kicks only that endpoint.
#[test]
fn rejected_install_preserves_live_pause_endpoint() {
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use sha2::{Digest, Sha256};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry_contracts = ContractRegistry::load(root).unwrap();
    let mut observations = Vec::new();
    for scale in [1, 8, 32, 128] {
        let (_kernel, _context) = bootstrap_thread(41_300 + scale);
        let space = mm(41_300 + scale as u64);
        let space_fence = fence();
        let slot = HostExecutionSlot::allocate().unwrap();
        let running = Vcpu::new(41_400 + scale);
        let displaced = Vcpu::new(41_500 + scale);
        let original = MmOccupancy::install_registered_for_test(
            slot.slot(),
            space,
            &space_fence,
            running.registry.clone(),
            running.tid,
        )
        .unwrap();
        running.flag.enter_guest();
        let mut original_visible = true;
        for _ in 0..scale {
            assert!(matches!(
                MmOccupancy::install_registered_for_test(
                    slot.slot(),
                    mm(41_999),
                    &fence(),
                    displaced.registry.clone(),
                    displaced.tid,
                ),
                Err(MmOccupancyError::SlotBusy { .. })
            ));
            let held = residents(space, &space_fence, None);
            assert_eq!(held.len(), 1);
            original_visible &=
                held.any_in_guest() && held.first_in_guest_tid() == Some(running.tid);
            held.kick_all_in_guest();
        }
        let original_calls = running.kicks.load(Ordering::SeqCst) as u64;
        let rejected_calls = displaced.kicks.load(Ordering::SeqCst) as u64;
        let mut work = WorkSnapshot::new();
        work.insert(
            WorkMetric::HostBackendCalls,
            original_calls + rejected_calls,
        )
        .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.mm.executor-admission").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: format!(
                "sha256:{:x}",
                Sha256::digest(include_bytes!("../mm_occupancy.rs"))
            ),
            fixture_identity: "unit:duplicate-admission-live-endpoint".into(),
            scale: scale as u64,
            semantic_assertions: vec![
                SemanticAssertion {
                    name: "rejected_duplicate_preserves_running_owner".into(),
                    passed: original_visible,
                    detail: None,
                },
                SemanticAssertion {
                    name: "drain_kicks_only_original_owner".into(),
                    passed: original_calls == scale as u64 && rejected_calls == 0,
                    detail: Some(format!(
                        "original={original_calls}, rejected={rejected_calls}"
                    )),
                },
            ],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
        running.flag.leave_guest();
        assert!(!residents(space, &space_fence, None).any_in_guest());
        drop(original);
        assert_eq!(occupant_count_for_probe(space, &space_fence), 0);
    }
    evaluate(
        registry_contracts
            .require("kernel.mm.executor-admission")
            .unwrap(),
        &observations,
    )
    .unwrap();
}

/// A drain started while a rejected installer contends for the slot still
/// waits for the original occupant before granting mutation.
#[test]
fn rejected_install_still_drains_original_before_granting_mutation() {
    #[derive(Clone)]
    struct ParkOriginal {
        flag: Arc<InGuestFlag>,
        calls: Arc<AtomicUsize>,
    }
    impl carrick_hal::VcpuKick for ParkOriginal {
        fn kick(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Deterministic safe point: the kick is what makes it leave.
            self.flag.leave_guest();
        }
    }
    let space = mm(41_600);
    let space_fence = fence();
    let slot = HostExecutionSlot::allocate().unwrap();
    let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
    let flag = Arc::new(InGuestFlag::for_guest_thread());
    let calls = Arc::new(AtomicUsize::new(0));
    let tid = ThreadId::synthetic_for_tests(41_601);
    assert!(matches!(
        registry.subscribe_register(
            tid,
            Box::new(ParkOriginal {
                flag: flag.clone(),
                calls: calls.clone()
            }),
            &flag,
            Arc::new(|| {})
        ),
        VcpuRegistrationEnrollment::Registered
    ));
    let original = MmOccupancy::install_registered_for_test(
        slot.slot(),
        space,
        &space_fence,
        registry.clone(),
        tid,
    )
    .unwrap();
    flag.enter_guest();
    let wrong = Arc::new(carrick_hal::GenericVcpuRegistry::new());
    assert!(matches!(
        MmOccupancy::install_registered_for_test(slot.slot(), space, &space_fence, wrong, tid),
        Err(MmOccupancyError::SlotBusy { .. })
    ));
    let pause = crate::dispatch::mm_quiesce::acquire_pt_pause(
        &space_fence,
        space,
        ThreadId::synthetic_for_tests(41_602),
        crate::dispatch::mm_quiesce::PtPauseBudget::DEFAULT,
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        !flag.is_in_guest(),
        "mutation cannot overlap original execution"
    );
    assert!(space_fence.is_quiescing());
    drop(pause);
    assert!(!space_fence.is_quiescing());
    drop(original);
    registry.unregister(tid);
}

#[test]
fn failed_crash_participation_vacates_the_slot() {
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().expect("task context");
    let thread = context.thread().clone();
    let _outside = thread
        .enter_crash_safe_point_participation()
        .expect("outside participation");
    let slot = HostExecutionSlot::allocate().unwrap();
    let vcpu = Vcpu::new(41_701);
    assert!(matches!(
        dispatcher.enter_mm_executor_for_thread(
            Some(thread.clone()),
            vcpu.registry.clone(),
            vcpu.tid,
            slot.slot(),
        ),
        Err(MmOccupancyError::CrashParticipationAlreadyActive { thread: rejected })
            if rejected == thread.key()
    ));
    assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
    assert!(
        dispatcher
            .enter_mm_executor_for_thread(None, vcpu.registry.clone(), vcpu.tid, slot.slot())
            .is_ok(),
        "the refused admission left the slot vacant"
    );
}

/// An admitted thread whose task leaves its vCPU (an executor preempted it
/// at a syscall boundary) vacates the slot but stays admitted, so another
/// task can be loaded on that vCPU; it re-occupies whichever vCPU loads it.
#[test]
fn an_unloaded_admission_vacates_its_slot_and_reoccupies_where_it_is_loaded() {
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().expect("task context");
    let (first, second) = (
        HostExecutionSlot::allocate().unwrap(),
        HostExecutionSlot::allocate().unwrap(),
    );
    let vcpu = Vcpu::new(41_750);
    let mut admitted = dispatcher
        .enter_mm_executor_for_thread(
            Some(context.thread().clone()),
            vcpu.registry.clone(),
            vcpu.tid,
            first.slot(),
        )
        .expect("admitted on the first vCPU");
    assert_eq!(admitted.current_slot(), Some(first.slot()));
    admitted.vacate_slot();
    assert_eq!(admitted.current_slot(), None);
    assert!(context.thread().is_crash_safe_point_participant());
    let other = Vcpu::new(41_751);
    let next = dispatcher
        .enter_mm_executor_for_thread(None, other.registry.clone(), other.tid, first.slot())
        .expect("another task loads on the vacated vCPU");
    admitted
        .occupy_slot(second.slot())
        .expect("reloaded elsewhere");
    assert_eq!(admitted.current_slot(), Some(second.slot()));
    assert_eq!(dispatcher.mm_occupancy_probe()(), 2);
    drop(next);
    drop(admitted);
    assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
    assert!(!context.thread().is_crash_safe_point_participant());
}

#[test]
fn vacating_one_occupant_preserves_the_other_and_unwind_vacates() {
    let space = mm(41_800);
    let space_fence = fence();
    let (a, b) = (
        HostExecutionSlot::allocate().unwrap(),
        HostExecutionSlot::allocate().unwrap(),
    );
    let (va, vb) = (Vcpu::new(41_801), Vcpu::new(41_802));
    let first = va.occupy(&a, space, &space_fence).unwrap();
    let second = vb.occupy(&b, space, &space_fence).unwrap();
    assert_eq!(occupant_count_for_probe(space, &space_fence), 2);
    drop(second);
    assert_eq!(residents(space, &space_fence, None).tids(), [va.tid]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _doomed = vb.occupy(&b, space, &space_fence).unwrap();
        assert_eq!(occupant_count_for_probe(space, &space_fence), 2);
        panic!("admitted executor quantum unwound");
    }));
    assert!(result.is_err());
    assert_eq!(
        occupant_count_for_probe(space, &space_fence),
        1,
        "an unwound executor must vacate its slot"
    );
    drop(first);
    assert_eq!(occupant_count_for_probe(space, &space_fence), 0);
}

#[test]
fn a_vcpu_without_a_mailbox_keeps_one_host_slot_per_thread() {
    let first = execution_slot_for_current_thread(None).unwrap();
    assert_eq!(execution_slot_for_current_thread(None).unwrap(), first);
    assert!(first.as_zone().is_none());
    assert_eq!(
        execution_slot_for_current_thread(Some(7)).unwrap(),
        ExecutionSlot::zone(ZoneSlotId::new(7))
    );
    let other = std::thread::spawn(|| execution_slot_for_current_thread(None).unwrap())
        .join()
        .unwrap();
    assert_ne!(other, first);
}

/// Private tables for a publication test (the zone's live in the EL1 region).
fn space_tables() -> (&'static AddressSpaces, &'static Occupancy) {
    (
        Box::leak(Box::new(AddressSpaces::new())),
        Box::leak(Box::new(Occupancy::new())),
    )
}

/// Contract `kernel.el1.address-space-switch`: a published address space's
/// gate follows the MM's fence, so guest EL1 cannot install it while a pause
/// of the MM is in force (raised before the pause scans the occupancy
/// table), and a publication made during a pause starts raised.
#[test]
fn a_published_gate_follows_the_mm_fence() {
    let (spaces, occupancy) = space_tables();
    let mm_fence = fence();
    let publication = publish_for_test(spaces, occupancy, mm(42_001), &mm_fence, 0x1000).unwrap();
    let index = spaces.find(42_001).unwrap();
    assert_eq!(spaces.gate(index), 0, "open once published");
    assert!(spaces.grant(index, 42_001).is_some());

    mm_fence.set_quiescing();
    assert_eq!(spaces.gate(index), 1, "raised with the fence");
    assert!(spaces.grant(index, 42_001).is_none());
    mm_fence.end();
    assert_eq!(spaces.gate(index), 0, "lowered when the pause ends");

    // Published while a pause is in force: raised until that pause ends.
    let other_fence = fence();
    other_fence.set_quiescing();
    let other = publish_for_test(spaces, occupancy, mm(42_002), &other_fence, 0x2000).unwrap();
    let other_index = spaces.find(42_002).unwrap();
    assert_eq!(spaces.gate(other_index), 1);
    other_fence.end();
    assert_eq!(spaces.gate(other_index), 0);

    // One publication per MM.
    assert!(publish_for_test(spaces, occupancy, mm(42_001), &mm_fence, 0x1000).is_none());
    drop(other);
    drop(publication);
}

/// Retirement: closing the gate refuses every later install, and dropping
/// the publication frees the entry and unbinds the fence, after no vCPU in
/// the guest holds the space.
#[test]
fn a_retired_publication_is_closed_unbound_and_freed() {
    let (spaces, occupancy) = space_tables();
    let mm_fence = fence();
    let publication = publish_for_test(spaces, occupancy, mm(42_101), &mm_fence, 0x3000).unwrap();
    let index = spaces.find(42_101).unwrap();
    publication.close();
    assert!(spaces.grant(index, 42_101).is_none(), "closed for good");
    mm_fence.set_quiescing();
    mm_fence.end();
    assert!(
        spaces.grant(index, 42_101).is_none(),
        "a pause does not reopen it"
    );
    drop(publication);
    assert_eq!(spaces.find(42_101), None, "freed");
    assert!(
        mm_fence.unbind_mirror().is_none(),
        "the fence no longer raises it"
    );
    let again = publish_for_test(spaces, occupancy, mm(42_102), &mm_fence, 0x4000).unwrap();
    assert!(
        spaces.find(42_102).is_some(),
        "the MM's fence can be bound again"
    );
    drop(again);
}

/// Contract `kernel.el1.address-space-switch`: a zone vCPU a pause found
/// running the MM is drained once guest EL1 moved it off the MM, even while
/// it stays in the guest. The executor's port names the thread it loaded,
/// whose in-guest flag stays set across what EL1 runs there; with the MM's
/// gate raised EL1 cannot put the MM back, so the word leaving it is final.
/// (A drain that read only the flag hung the first signed two-process run:
/// the vCPU it waited for was idling in WFI on the maintenance root.)
#[test]
fn a_zone_vcpu_moved_off_the_mm_is_drained_while_it_stays_in_guest() {
    let (_, occupancy) = space_tables();
    let space = mm(42_201);
    let slot = ExecutionSlot::zone(ZoneSlotId::new(3));
    let vcpu = Vcpu::new(42_201);
    assert!(occupancy.replace(slot, 0, space.raw()));
    vcpu.flag.enter_guest();
    let residents = MmResidents {
        members: vec![Resident::zone(
            occupancy,
            slot,
            space,
            PauseEndpoint::Registered {
                registry: vcpu.registry.clone(),
                tid: vcpu.tid,
            },
        )],
    };
    assert!(residents.any_in_guest(), "runs the MM in the guest");

    // EL1 switched to the maintenance root; the vCPU stays in the guest.
    assert!(occupancy.replace(slot, space.raw(), 0));
    assert!(!residents.any_in_guest(), "off the MM: drained");

    // Or EL1 moved it to another address space.
    assert!(occupancy.replace(slot, 0, mm(42_202).raw()));
    assert!(!residents.any_in_guest(), "another space is not the MM's");
    assert_eq!(occupancy.vacate_any(slot), mm(42_202).raw());
    vcpu.flag.leave_guest();
}
