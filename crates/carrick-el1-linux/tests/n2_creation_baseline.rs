//! VM-free evidence for the N2 plan, not a signed exit-count measurement.
use carrick_el1::fault::{
    GrantMailboxes, NoopCowResolver, NoopPreparedResolver, PreparedFaultPath,
    dispatch_fault_with_prepared,
};
use carrick_el1::memory::reservations::{Decision, Layout, Placement, SharedReservations};
use carrick_el1_abi::{
    Action, Counters, CurrentTask, FrameGrantMailbox, FrameGrantResidencyTable, InotifyNameCache,
    ReservationBackingReceipt, ReservationCompletion, ReservationMm, ReservationProtection,
    ReservationRange, TrapFrame,
};
use carrick_el1_linux::dispatch::{Zone, dispatch_syscall_with_lifecycle};
use carrick_el1_linux::sched;
use carrick_sched_core::AddressSpaces;
use core::sync::atomic::Ordering;

#[path = "support/policy.rs"]
mod policy;
use carrick_guest_mem::ArmRingFirst;

#[test]
fn creation_host_routes_preserve_arguments_and_count_each_forward_opt_out() {
    creation_host_routes(ArmRingFirst::OptOut);
}
#[test]
fn creation_host_routes_refuse_and_count_nonadmitted_calls_strict() {
    creation_host_routes(ArmRingFirst::Strict);
}
fn creation_host_routes(policy: ArmRingFirst) {
    // This exercises the production dispatcher with explicit tables and policy,
    // not dispatch_syscall's host-only stub.
    // No scheduler/lifecycle/IPC admission is supplied: this does not measure
    // admitted thread clone, futex, or memory service.
    let counters = Counters::default();
    let tasks = [CurrentTask::new()];
    let names = InotifyNameCache::new();
    for nr in [57, 59, 73, 94, 96, 103, 122, 134, 178, 221, 260, 281] {
        for count in 1..=3 {
            let mut frame = TrapFrame::default();
            frame.x[..6].copy_from_slice(&[17, 23, 31, 41, 47, 53]);
            frame.x[8] = nr;
            let mut original = frame.x;
            let refused = policy.is_strict() && matches!(nr, 96 | 103 | 122 | 134 | 178 | 260);
            if refused {
                original[0] =
                    carrick_personality_linux::crossing::LINUX_ENOSYS.guest_retval() as u64;
            }
            assert_eq!(
                dispatch_syscall_with_lifecycle(
                    &mut policy::PolicyFrame {
                        frame: &mut frame,
                        policy
                    },
                    &counters,
                    &tasks,
                    &[],
                    &[],
                    &[],
                    &[],
                    &names,
                    None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
                    None,
                    None,
                    None,
                    |_| core::ptr::null_mut(),
                ),
                if refused {
                    Action::Served
                } else {
                    Action::Forward
                },
                "syscall {nr}"
            );
            assert_eq!(frame.x, original);
            assert_eq!(
                counters.forwarded[nr as usize].load(Ordering::Relaxed),
                if refused { 0 } else { count }
            );
            assert_eq!(counters.served[nr as usize].load(Ordering::Relaxed), 0);
            assert_eq!(
                counters.refused[nr as usize].load(Ordering::Relaxed),
                if refused { count } else { 0 }
            );
        }
    }
}

#[test]
fn first_touch_capacity_forward_is_not_a_linux_syscall_forward() {
    let spaces = AddressSpaces::new();
    let counters = Counters::default();
    // SAFETY: the shared reservation ABI starts in its all-zero unpublished state.
    let roots = unsafe { Box::<SharedReservations>::new_zeroed().assume_init() };
    // Same VA in two live MMs: each request must retain its actual MM.
    for mm in [71, 83] {
        let slot = spaces.publish_closed(mm, mm << 12, mm << 12).unwrap();
        let owner = ReservationMm::new(mm).unwrap();
        roots
            .publish(
                slot.index(),
                owner,
                Layout {
                    heap: ReservationRange::new(0x1000, 0x10_0000).unwrap(),
                    arena: ReservationRange::new(0x4000_0000, 0x8000_0000).unwrap(),
                    brk: 0x1000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        let mut root = roots.lock(slot.index(), owner).unwrap();
        root.finish_import().unwrap();
        let Decision::Work(request) = root
            .mmap(
                Placement::Fixed(0x4000_0000),
                0x2000,
                ReservationProtection::READ_WRITE,
            )
            .unwrap()
        else {
            panic!("fresh reservation must require publication");
        };
        // SAFETY: this VM-free owner has no live descriptor/backing projection.
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(completion).unwrap();
        drop(root);
        spaces.open(slot);
    }
    let tasks = [CurrentTask::new(), CurrentTask::new()];
    for (slot, mm) in [71, 83].into_iter().enumerate() {
        tasks[slot].mm.key.store(mm, Ordering::Release);
        let mailbox = FrameGrantMailbox::new();
        let residency = FrameGrantResidencyTable::new();
        let mut frame = TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x07,
            far: 0x4000_1000,
            slot: slot as u64,
            ..TrapFrame::default()
        };
        frame.x[8] = 220; // stale clone nr must not become syscall attribution
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            ),
            Action::Forward
        );
        assert!(mailbox.has_guest_work());
        let request = mailbox.claim_request().unwrap();
        assert_eq!(request.mm_key, mm);
        assert_ne!(request.reservation_incarnation.raw(), 0);
        assert_eq!(request.fault_va, frame.far);
        assert_eq!(counters.forwarded[220].load(Ordering::Relaxed), 0);
    }
    assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 2);
}

#[test]
fn shared_futex_and_waitv_are_outside_current_private_futex_route() {
    let mut frame = TrapFrame::default();
    frame.x[0] = 0x4000_1000;
    frame.x[8] = 98;
    frame.x[1] = 128; // FUTEX_WAIT_PRIVATE
    assert!(sched::is_served_futex_op(&frame));
    frame.x[1] = 0; // FUTEX_WAIT (shared)
    assert!(!sched::is_served_futex_op(&frame));
    frame.x[8] = 449; // futex_waitv
    assert!(!sched::is_served_futex_op(&frame));
}

// An uninhabited CPU makes accidental hardware use impossible in this fixture.
enum NoCpu {}
impl sched::ThreadCpu for NoCpu {
    fn save(&mut self, _: &TrapFrame, _: &mut carrick_el1_abi::Aarch64ParkedContext) {
        match *self {}
    }
    fn load(&mut self, _: &mut TrapFrame, _: &carrick_el1_abi::Aarch64ParkedContext) {
        match *self {}
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        match *self {}
    }
    fn invalidate_asid(&mut self, _: u64) {
        match *self {}
    }
    fn now(&self) -> u64 {
        match *self {}
    }
    fn freq(&self) -> u64 {
        match *self {}
    }
    fn set_timer(&mut self, _: Option<u64>) {
        match *self {}
    }
    fn send_sgi(&mut self, _: u64) {
        match *self {}
    }
    fn ack_irq(&mut self) -> u32 {
        match *self {}
    }
    fn end_irq(&mut self, _: u32) {
        match *self {}
    }
    fn wait_for_interrupt(&mut self) {
        match *self {}
    }
    fn spin(&mut self) {
        match *self {}
    }
    fn own_sgi_target(&self) -> u64 {
        match *self {}
    }
}
