//! The host build of the library uses the same Unavailable file authority as
//! the production CPL0 image. Keep the x86 no-venue routing out of cfg(test).
#![allow(clippy::panic)]

use carrick_el1::personality::{dispatch, sched};
use carrick_el1_abi::{Action, Counters, CurrentTask, El1TaskId, InotifyNameCache, TrapFrame};
use carrick_guest_arch::{CanonicalNr, NativeReturnWord, SlotId, SyscallFrame, UserVa};
use carrick_personality_linux::entry::decode_x86_64;
use core::sync::atomic::{AtomicU64, Ordering};

struct X86Frame<'a> {
    native: carrick_guest_arch::NativeOrdinal,
    canonical: CanonicalNr,
    args: [u64; 6],
    rax: u64,
    isa_unsupported: &'a AtomicU64,
}

impl SyscallFrame for X86Frame<'_> {
    fn canonical_ordinal(&self) -> CanonicalNr {
        self.canonical
    }
    fn argument(&self, index: usize) -> Option<u64> {
        self.args.get(index).copied()
    }
    fn result(&self) -> NativeReturnWord {
        NativeReturnWord(self.rax)
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.rax = result.0;
    }
    fn slot(&self) -> Option<SlotId> {
        Some(SlotId::new(0))
    }
    fn user_sp(&self) -> Option<UserVa> {
        Some(UserVa::new(0x7fff_0000))
    }
}

impl dispatch::GuestDispatchFrame for X86Frame<'_> {
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        self.native
    }

    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        carrick_personality_linux::crossing::HostCrossingSet::X86
    }

    fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
        None
    }
    fn arm_frame_ref(&self) -> Option<&TrapFrame> {
        None
    }
    fn arm_scheduler(&self) -> bool {
        false
    }
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
        None
    }
    fn record_isa_unsupported_forward(&self) {
        self.isa_unsupported.fetch_add(1, Ordering::Relaxed);
    }
}

// No native scheduling venue is supplied. Any CPU hook would be a bug.
struct NoCpu;
impl sched::ThreadCpu for NoCpu {
    fn save(&mut self, _: &TrapFrame, _: &mut carrick_el1_abi::ThreadCtx) {
        panic!("no CPU venue");
    }
    fn load(&mut self, _: &mut TrapFrame, _: &carrick_el1_abi::ThreadCtx) {
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

#[test]
fn production_x86_family_absences_obey_eight_crossings_without_user_memory() {
    let tasks = [CurrentTask::new()];
    tasks[0].set(El1TaskId::from_linux_tid(41), 1, 7);
    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let isa_unsupported = AtomicU64::new(0);
    // The file table is live, but the carrier published no file, IPC or MM
    // venue. Invalid user pointers make an accidental copy observable.
    let args = [3, 0xffff_ffff_ffff_f000, 8, 0, 0, 0];
    for (family, native) in [
        ("anonymous brk", 12),
        ("anonymous mmap", 9),
        ("anonymous mprotect", 10),
        ("anonymous munmap", 11),
        ("IPC read", 0),
        ("IPC write", 1),
        ("IPC epoll_pwait", 281),
        ("futex", 202),
        ("file seek", 8),
        ("file pread", 17),
        ("file pwrite", 18),
        ("inotify add", 254),
        ("inotify remove", 255),
        ("lifecycle sigprocmask", 14),
        ("lifecycle sigaltstack", 131),
        ("signal-return transport", 15),
        ("clone", 56),
        ("fork", 57),
        ("wait4", 61),
        ("getpid decline", 39),
        ("gettid decline", 186),
    ] {
        let call = decode_x86_64(native, args, 0x7fff_0000);
        assert_ne!(call.canonical.raw(), u64::MAX, "{family} must decode");
        let mut frame = X86Frame {
            native: call.native,
            canonical: call.canonical,
            args: call.args,
            rax: 0xfeed,
            isa_unsupported: &isa_unsupported,
        };
        let before_isa = isa_unsupported.load(Ordering::Relaxed);
        let bucket = if native == 57 { 512 } else { native as usize };
        let before_refused = counters.refused[bucket].load(Ordering::Relaxed);
        let action = dispatch::dispatch_syscall_with_lifecycle(
            &mut frame,
            &counters,
            &tasks,
            &[],
            &[],
            &[],
            &[],
            &names,
            None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
            None,
            None,
            None,
            |_| core::ptr::null_mut(),
        );
        let allowed = matches!(native, 0 | 1 | 8 | 17 | 18 | 281);
        assert_eq!(
            action,
            if allowed {
                Action::Forward
            } else {
                Action::Served
            },
            "{family}"
        );
        assert_eq!(
            frame.rax as i64,
            if allowed { 0xfeed } else { -38 },
            "{family}"
        );
        assert_eq!(
            counters.refused[bucket].load(Ordering::Relaxed) - before_refused,
            u64::from(!allowed),
            "{family}"
        );
        assert_eq!(
            isa_unsupported.load(Ordering::Relaxed) - before_isa,
            u64::from(matches!(native, 202)),
            "{family} must distinguish ISA refusal from semantic forwarding"
        );
        assert_eq!(
            counters.served[call.canonical.raw() as usize].load(Ordering::Relaxed),
            0,
            "{family} must not record a guest service"
        );
    }
}

#[test]
fn x86_context_selects_x86_crossings_without_arm_aperture() {
    use dispatch::GuestDispatchFrame;
    let counter = AtomicU64::new(0);
    let frame = X86Frame {
        native: carrick_guest_arch::NativeOrdinal::new(0),
        canonical: CanonicalNr::new(63),
        args: [0; 6],
        rax: 0,
        isa_unsupported: &counter,
    };
    assert_eq!(
        frame.crossing_set(),
        carrick_personality_linux::crossing::HostCrossingSet::X86
    );
    assert!(frame.crossing_strict(|| panic!("x86 must not read ARM aperture")));
}

#[test]
fn x86_unported_refusal_counts_native_ordinal_not_canonical_ordinal() {
    let tasks = [CurrentTask::new()];
    tasks[0].set(El1TaskId::from_linux_tid(41), 1, 7);
    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let isa_unsupported = AtomicU64::new(0);
    let call = decode_x86_64(102, [0; 6], 0x7fff_0000); // getuid -> canonical 174
    let mut frame = X86Frame {
        native: call.native,
        canonical: call.canonical,
        args: call.args,
        rax: 102,
        isa_unsupported: &isa_unsupported,
    };
    let action = dispatch::dispatch_syscall_with_lifecycle(
        &mut frame,
        &counters,
        &tasks,
        &[],
        &[],
        &[],
        &[],
        &names,
        None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
        None,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    assert_eq!(action, Action::Served);
    assert_eq!(frame.rax as i64, -38);
    assert_eq!(counters.refused[102].load(Ordering::Relaxed), 1);
    assert_eq!(counters.refused[174].load(Ordering::Relaxed), 0);
}
