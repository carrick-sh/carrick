#![allow(clippy::panic)]
use carrick_core::entry::complete;
use carrick_core_abi::ExecutionBinding;
use carrick_personality_linux::entry::{EntryOutcome, LinuxEntryVenue, decode_x86_64, serve};
use core::cell::Cell;

struct Venue {
    binding: ExecutionBinding,
    pending: bool,
    publications: Cell<u64>,
    forwards: Cell<u64>,
    completions_with_work: Cell<u64>,
}

impl LinuxEntryVenue for Venue {
    fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    fn set_robust_list(&self, _: u64, len: u64) -> Option<i64> {
        if len == 24 {
            self.publications.set(self.publications.get() + 1);
            Some(0)
        } else {
            Some(-22)
        }
    }
    fn pending_work(&self) -> bool {
        self.pending
    }
    fn record_forwarded(&self, _: usize) {
        self.forwards.set(self.forwards.get() + 1);
    }
    fn record_served(&self, _: usize) {}
    fn mark_completed_with_work(&self) {
        self.completions_with_work
            .set(self.completions_with_work.get() + 1);
    }
}

#[test]
fn x4_linux_common_entry() {
    let first = ExecutionBinding {
        task: 41,
        generation: 1,
        mm: 5,
        thread_generation: 9,
    };
    let venue = Venue {
        binding: first,
        pending: true,
        publications: Cell::new(0),
        forwards: Cell::new(0),
        completions_with_work: Cell::new(0),
    };
    let call = decode_x86_64(273, [0xa000, 24, 0, 0, 0, 0], 0x7fff_0000);
    let completion = match serve(&call, &venue) {
        EntryOutcome::ServedWithWork { result, completion } => {
            assert_eq!(result.raw(), 0);
            completion
        }
        other => panic!("unexpected entry outcome: {other:?}"),
    };
    assert_eq!(venue.publications.get(), 1);
    assert_eq!(venue.completions_with_work.get(), 1);
    assert!(complete(completion, first).is_ok());

    let reused = ExecutionBinding {
        generation: 2,
        thread_generation: 10,
        ..first
    };
    let stale = carrick_core_abi::EntryCompletion::admit(first).unwrap();
    assert!(complete(stale, reused).is_err());

    let unported = decode_x86_64(39, [0; 6], 0x7fff_0000);
    assert_eq!(serve(&unported, &venue), EntryOutcome::Forward);
    assert_eq!(venue.publications.get(), 1);
    assert_eq!(venue.forwards.get(), 1);
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
