//! VM-free evidence for the N2 plan, not a signed exit-count measurement.
use carrick_el1::fault::{GrantMailboxes, NoopCowResolver, dispatch_fault_with_regions};
use carrick_el1::{Zone, dispatch_syscall_with_regions, sched};
use carrick_el1_abi::{
    Action, Counters, CurrentTask, FrameGrantMailbox, InotifyNameCache, TrapFrame,
};
use carrick_sched_core::AddressSpaces;
use core::sync::atomic::Ordering;

#[test]
fn creation_host_routes_preserve_arguments_and_count_each_forward() {
    // These calls have no serving arm in the current table. This exercises the
    // real region-based dispatcher, not dispatch_syscall's host-only stub.
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
            let original = frame.x;
            assert_eq!(
                dispatch_syscall_with_regions(
                    &mut frame,
                    &counters,
                    &tasks,
                    &[],
                    &[],
                    &[],
                    &[],
                    &names,
                    None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
                    |_| core::ptr::null_mut(),
                ),
                Action::Forward,
                "syscall {nr}"
            );
            assert_eq!(frame.x, original);
            assert_eq!(
                counters.forwarded[nr as usize].load(Ordering::Relaxed),
                count
            );
            assert_eq!(counters.served[nr as usize].load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn first_touch_capacity_forward_is_not_a_linux_syscall_forward() {
    let spaces = AddressSpaces::new();
    let counters = Counters::default();
    // Same VA in two live MMs: each request must retain its actual MM.
    for mm in [71, 83] {
        let slot = spaces.publish_closed(mm, mm << 12, mm << 12).unwrap();
        spaces.open(slot);
    }
    let tasks = [CurrentTask::new(), CurrentTask::new()];
    for (slot, mm) in [71, 83].into_iter().enumerate() {
        tasks[slot].zone_mm.store(mm, Ordering::Release);
        let mailbox = FrameGrantMailbox::new();
        let mut frame = TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x07,
            far: 0x4000_1000,
            slot: slot as u64,
            ..TrapFrame::default()
        };
        frame.x[8] = 220; // stale clone nr must not become syscall attribution
        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                &mut NoopCowResolver,
            ),
            Action::Forward
        );
        assert!(mailbox.has_guest_work());
        let request = mailbox.claim_request().unwrap();
        assert_eq!(request.mm_key, mm);
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
    fn save(&mut self, _: &TrapFrame, _: &mut carrick_el1_abi::ThreadCtx) {
        match *self {}
    }
    fn load(&mut self, _: &mut TrapFrame, _: &carrick_el1_abi::ThreadCtx) {
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
