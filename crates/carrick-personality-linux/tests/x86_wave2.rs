#![allow(clippy::panic)]
#[path = "x86_wave2/common_entry.rs"]
mod common_entry;
#[path = "x86_wave2/dispatch.rs"]
mod dispatch;
#[test]
fn x4_linux_common_entry() {
    common_entry::x4_linux_common_entry();
}

#[test]
fn unmigrated_family_completes_once_through_linux_owner() {
    use carrick_el1::personality::{dispatch, sched};
    use carrick_el1_abi::{
        Counters, CurrentTask, DELEGATED_FLAG_READABLE, DELEGATED_STATE_GUEST, DelegatedFile,
        DelegatedOpenFile, FdMapSlot, InotifyNameCache, TrapFrame,
    };
    use core::sync::atomic::Ordering;
    for scale in [1, 2, 8] {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(17), 5, 100);
        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42);
        let files = [DelegatedFile::new()];
        files[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        files[0].generation.store(42, Ordering::Relaxed);
        files[0].size.store(100, Ordering::Relaxed);
        let opens = [DelegatedOpenFile::new()];
        opens[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        opens[0].inode_handle.store(1, Ordering::Relaxed);
        opens[0].generation.store(42, Ordering::Relaxed);
        opens[0].inode_generation.store(42, Ordering::Relaxed);
        opens[0]
            .flags
            .store(DELEGATED_FLAG_READABLE, Ordering::Relaxed);
        for _ in 0..scale {
            let mut frame = TrapFrame::default();
            frame.x[0] = 3;
            frame.x[1] = 17;
            frame.x[8] = 62;
            assert_eq!(
                dispatch::dispatch_syscall_with_regions(
                    &mut frame,
                    &counters,
                    &tasks,
                    &fd_map,
                    &files,
                    &opens,
                    &[],
                    &InotifyNameCache::new(),
                    None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
                    |_| core::ptr::null_mut()
                ),
                carrick_el1_abi::Action::Served
            );
            assert_eq!(frame.x[0], 17);
        }
        assert_eq!(counters.served[62].load(Ordering::Relaxed), scale);
        assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 0);
        assert_eq!(opens[0].offset.load(Ordering::Relaxed), 17);
    }
}

// This family fixture has no zone. Reaching a CPU hook would violate the
// absence of a native scheduling venue, rather than model a second scheduler.
struct NoCpu;
impl carrick_el1::personality::sched::ThreadCpu for NoCpu {
    fn save(&mut self, _: &carrick_el1_abi::TrapFrame, _: &mut carrick_el1_abi::ThreadCtx) {
        panic!("no CPU venue");
    }
    fn load(&mut self, _: &mut carrick_el1_abi::TrapFrame, _: &carrick_el1_abi::ThreadCtx) {
        panic!("no CPU venue");
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        panic!("no CPU venue");
    }
    fn invalidate_asid(&mut self, _: u64) {
        panic!("no CPU venue");
    }
    fn now(&self) -> u64 {
        panic!("no CPU venue");
    }
    fn freq(&self) -> u64 {
        panic!("no CPU venue");
    }
    fn set_timer(&mut self, _: Option<u64>) {
        panic!("no CPU venue");
    }
    fn send_sgi(&mut self, _: u64) {
        panic!("no CPU venue");
    }
    fn ack_irq(&mut self) -> u32 {
        panic!("no CPU venue");
    }
    fn end_irq(&mut self, _: u32) {
        panic!("no CPU venue");
    }
    fn wait_for_interrupt(&mut self) {
        panic!("no CPU venue");
    }
    fn spin(&mut self) {
        panic!("no CPU venue");
    }
    fn own_sgi_target(&self) -> u64 {
        panic!("no CPU venue");
    }
}

#[path = "x86_wave2/lifecycle.rs"]
mod lifecycle;
#[test]
fn x5_linux_clone_exit() {
    lifecycle::x5_linux_clone_exit();
}

#[test]
fn registered_clear_tid_is_consumed_by_shared_exit() {
    lifecycle::registered_clear_tid_is_consumed_by_shared_exit();
}
