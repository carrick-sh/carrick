#![allow(clippy::panic)]
#[path = "x86_wave2/common_entry.rs"]
mod common_entry;
#[path = "x86_wave2/dispatch.rs"]
mod dispatch;

#[test]
fn poll_decode_preserves_integer_timeout_and_has_no_sigmask() {
    use carrick_personality_linux::abi::x86_64::PollTimeout;
    for milliseconds in [-1_i32, 0, 1, i32::MAX] {
        let raw = milliseconds as u32 as u64;
        let call = carrick_personality_linux::entry::decode_x86_64(
            7,
            [0x4000, 3, raw, 0xBAD, 0xBAD, 0xBAD],
            0x8000,
        );
        assert_eq!(
            call.canonical.raw(),
            carrick_syscall_abi::CARRICK_PRIVATE_X86_POLL
        );
        assert_eq!(call.native.raw(), 7);
        assert_eq!(call.args, [0x4000, 3, raw, 0, 0, 0]);
        assert_eq!(call.stack.raw(), 0x8000);
        assert_eq!(
            PollTimeout::from_register(call.args[2]).duration(),
            if milliseconds < 0 {
                None
            } else {
                Some(core::time::Duration::from_millis(milliseconds as u64))
            }
        );
    }
}
#[test]
#[cfg(target_arch = "x86_64")]
fn private_x86_counters_have_disjoint_canonical_and_sentinel_slots() {
    use carrick_syscall_abi::*;
    use core::sync::atomic::Ordering;
    let counters = carrick_el1_abi::Counters::new();
    let entry = carrick_personality_linux::dispatch::EntryCounters {
        served: &counters.served,
        forwarded: &counters.forwarded,
    };
    let private = [
        CARRICK_PRIVATE_X86_DUP2,
        CARRICK_PRIVATE_X86_STAT,
        CARRICK_PRIVATE_X86_FSTAT,
        CARRICK_PRIVATE_X86_LSTAT,
        CARRICK_PRIVATE_X86_NEWFSTATAT,
        CARRICK_PRIVATE_X86_UNSUPPORTED,
        CARRICK_PRIVATE_X86_UTIME,
        CARRICK_PRIVATE_X86_UTIMES,
        CARRICK_PRIVATE_X86_POLL,
        CARRICK_PRIVATE_X86_SELECT,
        CARRICK_PRIVATE_X86_EPOLL_CREATE,
        CARRICK_PRIVATE_X86_ALARM,
        CARRICK_PRIVATE_X86_TIME,
        CARRICK_PRIVATE_X86_FORK,
        CARRICK_PRIVATE_X86_ARCH_PRCTL,
    ];
    for number in private {
        entry.served(number);
        entry.forwarded(number);
    }
    for number in private {
        let slot = private_x86_counter_slot(CanonicalNr(number)).unwrap();
        assert!((480..511).contains(&slot));
        assert_eq!(counters.served[slot].load(Ordering::Relaxed), 1);
        assert_eq!(counters.forwarded[slot].load(Ordering::Relaxed), 1);
    }
    for canonical in [0, 158, 467, 511, u64::MAX] {
        assert_eq!(private_x86_counter_slot(CanonicalNr(canonical)), None);
    }
    entry.served(158);
    entry.forwarded(158);
    assert_eq!(counters.served[158].load(Ordering::Relaxed), 1);
    assert_eq!(counters.forwarded[158].load(Ordering::Relaxed), 1);
    assert_eq!(counters.served[511].load(Ordering::Relaxed), 0);
    assert_eq!(counters.forwarded[511].load(Ordering::Relaxed), 0);
}

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
