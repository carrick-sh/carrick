//! The host build of the library uses the same Unavailable file authority as
//! the production CPL0 image. Keep the x86 no-venue routing out of cfg(test).
#![allow(clippy::panic)]

use carrick_el1::personality::{dispatch, sched};
use carrick_el1_abi::{Action, Counters, CurrentTask, El1TaskId, InotifyNameCache, TrapFrame};
use carrick_guest_arch::{CanonicalNr, NativeReturnWord, SlotId, SyscallFrame, UserVa};
use carrick_personality_linux::entry::decode_x86_64;
use core::sync::atomic::{AtomicU64, Ordering};

struct X86Frame<'a> {
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
fn production_x86_family_absences_forward_without_touching_user_memory() {
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
    ] {
        let call = decode_x86_64(native, args, 0x7fff_0000);
        assert_ne!(call.canonical.raw(), u64::MAX, "{family} must decode");
        let mut frame = X86Frame {
            canonical: call.canonical,
            args: call.args,
            rax: 0xfeed,
            isa_unsupported: &isa_unsupported,
        };
        let before_isa = isa_unsupported.load(Ordering::Relaxed);
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
            |_| core::ptr::null_mut(),
        );
        assert_eq!(action, Action::Forward, "{family}");
        assert_eq!(frame.rax, 0xfeed, "{family} must not install a result");
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
