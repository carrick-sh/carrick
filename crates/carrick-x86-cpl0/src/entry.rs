//! Thin native entry into Carrick's common in-guest Linux personality.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
extern crate alloc as rust_alloc;

#[cfg(target_os = "none")]
use carrick_el1::isa::x86::context::native as adapter;

#[cfg(target_os = "none")]
use carrick_el1::isa::x86::interrupts;
#[cfg(target_os = "none")]
mod progress;
#[cfg(target_os = "none")]
mod cpl0_scheduler {
    pub(crate) use super::scheduler::*;
}
#[cfg(target_os = "none")]
mod cpl0_entry {
    pub use crate::adapter::*;
}
#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(adapter::CpuBinding, task_address) == 24);
#[cfg(target_os = "none")]
#[path = "../../carrick-x86/src/cpl0_lifecycle.rs"]
mod lifecycle;

#[cfg(target_os = "none")]
use carrick_el1::isa::x86::context::scheduler;

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".section .text.entry, \"ax\"",
    ".global carrick_x86_syscall",
    "carrick_x86_syscall:",
    "swapgs",
    "mov gs:[8], rsp",
    "mov rsp, gs:[0]",
    "push qword ptr gs:[8]",
    "push r11",
    "push rcx",
    "push rax",
    "push rdi",
    "push rsi",
    "push rdx",
    "push r10",
    "push r8",
    "push r9",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",
    "mov rsi, gs:[16]",
    "call carrick_x86_enter",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "pop r9",
    "pop r8",
    "pop r10",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rax",
    "pop rcx",
    "pop r11",
    // The saved user SP is already at the correct place in the IRET frame.
    "push r11",
    "push 0x23",
    "push rcx",
    "mov qword ptr [rsp + 32], 0x1b",
    "swapgs",
    "iretq",
);

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global carrick_x86_page_fault_fixup",
    "carrick_x86_page_fault_fixup:",
    "push rax",
    "push rdx",
    // Error code, RIP and CS follow the two saved scratch registers.
    "cmp qword ptr [rsp + 32], 8",
    "jne 9f",
    "mov rax, qword ptr gs:[24]", // CpuBinding.task_address
    "test rax, rax",
    "jz 9f",
    "mov rdx, qword ptr [rax + 24]", // CurrentTask.linux.fixup_pc
    "test rdx, rdx",
    "jz 9f",
    "mov qword ptr [rsp + 24], rdx",
    "pop rdx",
    "pop rax",
    "add rsp, 8", // discard #PF error code
    "iretq",
    "9:",
    "ud2", // an unguarded kernel/user fault is fatal
);

#[cfg(target_os = "none")]
mod user_fault_gate {
    use crate::interrupts;

    #[repr(C, packed)]
    struct Idtr {
        limit: u16,
        base: u64,
    }

    unsafe extern "C" {
        fn carrick_x86_page_fault_fixup();
    }

    pub struct GateGuard {
        slot: *mut u8,
        previous: [u8; 16],
    }

    impl Drop for GateGuard {
        fn drop(&mut self) {
            // SAFETY: the same CPL0 CPU owns this private IDT. Mask IF while
            // restoring a multi-byte gate, then restore this lane's prior IF.
            unsafe {
                let mask = interrupts::hardware::mask_interrupts();
                for (i, byte) in self.previous.into_iter().enumerate() {
                    core::ptr::write_volatile(self.slot.add(i), byte);
                }
                interrupts::hardware::restore_interrupts(mask);
            }
        }
    }

    /// Install the CPL0 #PF fixup on this CPU's private IDT before any
    /// guarded user access. SYSCALL has masked IF and the IDT is retained by
    /// the image owner until this CPU retires.
    pub fn install() -> GateGuard {
        // SAFETY: CPL0 owns this CPU's IF; a gate update is not atomic.
        let mask = unsafe { interrupts::hardware::mask_interrupts() };
        let mut idtr = Idtr { limit: 0, base: 0 };
        // SAFETY: SIDT is legal at CPL0 and writes exactly the packed record.
        unsafe { core::arch::asm!("sidt [{}]", in(reg) &raw mut idtr, options(nostack)) };
        let base = idtr.base;
        if u64::from(idtr.limit) < 15 * 16 - 1 {
            // SAFETY: an undersized IDT cannot support recoverable #PF.
            unsafe { core::arch::asm!("ud2", options(noreturn)) }
        }
        let entry = carrick_x86_page_fault_fixup as *const () as u64;
        let mut bytes = [0_u8; 16];
        bytes[0..2].copy_from_slice(&(entry as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&8_u16.to_le_bytes());
        bytes[5] = 0x8e;
        bytes[6..8].copy_from_slice(&((entry >> 16) as u16).to_le_bytes());
        bytes[8..12].copy_from_slice(&((entry >> 32) as u32).to_le_bytes());
        let slot = (base + 14 * 16) as *mut u8;
        let mut previous = [0_u8; 16];
        // SAFETY: each CPU owns its private, supervisor-mapped IDT page. IF
        // is masked through SYSCALL and no other CPU can read this gate.
        unsafe {
            for (i, byte) in previous.iter_mut().enumerate() {
                *byte = core::ptr::read_volatile(slot.add(i));
            }
            for (i, byte) in bytes.into_iter().enumerate() {
                core::ptr::write_volatile(slot.add(i), byte);
            }
            interrupts::hardware::restore_interrupts(mask);
        }
        GateGuard { slot, previous }
    }
}

#[cfg(target_os = "none")]
mod kernel {
    use super::adapter::*;
    use carrick_el1::lock::SpinLock;
    use carrick_el1::personality::common_entry::{EntryOutcome, serve_canonical};
    use carrick_el1::personality::thread_setup::GuestLifecycleVenue;
    use carrick_el1_abi::{Counters, CurrentTask};
    use carrick_guest_arch::{EntryArch, InterruptArch};
    use core::sync::atomic::Ordering;

    // Count native exits across CPL0 CPUs for image/link and live diagnostics.
    // A port write exits the VM, so no lock may remain held across it: another
    // CPU can enter and need the same lock before the first CPU resumes.
    #[unsafe(no_mangle)]
    pub static CARRICK_CPL0_DOORBELL_COUNT: SpinLock<u64> = SpinLock::new(0);

    // A port exit may suspend this CPU while another CPU continues. The
    // admission value can only be produced after the lock guard is dropped.
    struct ExitAdmission;

    fn admit_exit() -> ExitAdmission {
        let mut count = CARRICK_CPL0_DOORBELL_COUNT.lock();
        *count = count.wrapping_add(1);
        core::mem::drop(count);
        ExitAdmission
    }

    fn write_port(port: u16, frame: &mut NativeFrame, _admission: ExitAdmission) {
        // SAFETY: CPL0 owns the declared control/forwarding transport.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("rax") frame as *mut _ as u64,
                options(nostack, preserves_flags));
        }
    }

    fn doorbell(port: u16, frame: &mut NativeFrame) {
        write_port(port, frame, admit_exit());
    }

    #[unsafe(no_mangle)]
    extern "C" fn carrick_x86_enter(frame: &mut NativeFrame, binding: &CpuBinding) {
        if !frame.valid_user_return() {
            doorbell(FATAL_PORT, frame);
            halt();
        }
        let mut arch = carrick_el1::isa::x86::kernel_arch();
        if arch.current_cpu().raw() != binding.cpu_slot {
            doorbell(FATAL_PORT, frame);
            halt();
        }
        // Both retained scheduler witness fixtures qualify XCR0 and XSAVE
        // geometry before entry. Exercise the shared native context leaf while
        // preserving the exact current task and MM authority.
        if binding.scheduler_witness.load(Ordering::Acquire) != 0 {
            let Ok(saved) = arch.save_context(frame) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            if arch.load_context(frame, &saved).is_err() {
                doorbell(FATAL_PORT, frame);
                halt();
            }
        }
        if frame.rax == OBSERVE_NATIVE {
            doorbell(CONTROL_PORT, frame);
            frame.rax = 0;
            return;
        }
        if frame.rax == OBSERVE_MMU_ROOT {
            use carrick_guest_arch::MmuBackend;
            let mut arch = carrick_el1::isa::x86::X86Backend;
            frame.rax = arch.live_root().map_or(0, |root| root.address().raw());
            return;
        }
        if frame.rax == OBSERVE_MMU_DRAIN {
            use carrick_guest_arch::{
                AddressContext, ContextGeneration, FrameGpa, GuestLen, MmGeneration, MmuBackend,
                RootGpa, UserRange, UserVa,
            };
            let mut arch = carrick_el1::isa::x86::X86Backend;
            frame.rax = arch
                .live_root()
                .and_then(|_| {
                    let root = RootGpa::page_aligned(FrameGpa::new(frame.rsi))
                        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
                    let context = AddressContext {
                        root,
                        mm: MmGeneration::new(core::num::NonZeroU64::MIN),
                        generation: ContextGeneration::new(core::num::NonZeroU64::MIN),
                    };
                    let range = UserRange::checked(UserVa::new(frame.rdi), GuestLen::new(4096))
                        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
                    arch.request_invalidation(context, range)
                        .and_then(|ticket| arch.ack_drain(ticket))
                })
                .map_or(u64::MAX, |receipt| receipt.root().address().raw());
            return;
        }
        if frame.rax == OBSERVE_DESCRIPTOR_PROTECT {
            use carrick_guest_arch::{
                EditIntent, EditOperation, EditOwner, EditPermissions, FrameGpa, GuestLen,
                MmuEditArch, RootGpa, UserRange, UserVa,
            };
            use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
            let Some(root) = RootGpa::page_aligned(FrameGpa::new(0x60_0000)) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            // SAFETY: this fixture runs one vCPU at a time with a retained
            // root, so the native page-table editor is exclusive here.
            let owner = unsafe {
                EditOwner::issue(root, core::num::NonZeroU64::MIN, core::num::NonZeroU64::MIN)
            };
            let Some(range) = UserRange::checked(UserVa::new(0x3_0000), GuestLen::new(4096)) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            let Some(intent) = EditIntent::checked(
                owner,
                range,
                EditOperation::Protect {
                    permissions: EditPermissions {
                        readable: true,
                        writable: false,
                        executable: false,
                        user: true,
                    },
                },
                &[],
            ) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            // SAFETY: this KVM fixture exclusively owns a retained, identity
            // mapped 448-page PML4 window while its sibling vCPU is stopped.
            let mut arch = carrick_el1::isa::x86::Kernel::new(carrick_el1::isa::x86::X86Backend);
            let receipt = unsafe {
                arch.execute_edit(intent, root.address(), GuestLen::new(FIXTURE_PML4_CAPACITY))
            };
            frame.rax = match receipt {
                Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) => 1,
                Ok(_) => 0,
                Err(_) => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
            };
            return;
        }
        if frame.rax == OBSERVE_ALLOCATOR {
            let layout = match core::alloc::Layout::from_size_align(128, 64) {
                Ok(layout) => layout,
                Err(_) => {
                    frame.rax = 0;
                    return;
                }
            };
            // SAFETY: the global allocator returns a block of this layout;
            // this fixture owns it exclusively until the matching dealloc.
            let ptr = core::hint::black_box(unsafe { crate::rust_alloc::alloc::alloc(layout) });
            if ptr.is_null() {
                frame.rax = 0;
                return;
            }
            // SAFETY: byte 127 is inside this exclusively owned allocation.
            unsafe { core::ptr::write_volatile(ptr.add(127), 0xa5) };
            // SAFETY: the same byte remains allocated until dealloc below.
            let valid = (ptr as usize & 63) == 0
                && (ptr as u64)
                    .checked_sub(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE)
                    .is_some_and(|offset| offset < carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE)
                && unsafe { core::ptr::read_volatile(ptr.add(127)) } == 0xa5;
            // SAFETY: ptr was returned for layout and has not escaped.
            unsafe { crate::rust_alloc::alloc::dealloc(ptr, layout) };
            frame.rax = u64::from(valid);
            return;
        }
        // SAFETY: bootstrap retains these supervisor-only records until the
        // VM/vCPUs retire; each binding names its issued current task.
        let task = unsafe { &*(binding.task_address as *const CurrentTask) };
        let counters = unsafe { &*(binding.counters_address as *const Counters) };
        let _user_fault_gate = super::user_fault_gate::install();
        if frame.rax == carrick_el1::isa::x86::user_access::USER_ACCESS_WITNESS {
            frame.rax = carrick_el1::isa::x86::user_access::witness(task, frame.rdi, frame.rsi);
            return;
        }
        if frame.rax == carrick_el1::isa::x86::transport::TRANSPORT_WITNESS {
            frame.rax = carrick_el1::isa::x86::transport::witness(frame.rdi);
            return;
        }
        binding.entries.fetch_add(1, Ordering::Relaxed);
        let scheduler_witness =
            binding.scheduler_witness.load(Ordering::Acquire) == super::scheduler::PROGRESS_STATE;
        if scheduler_witness {
            super::progress::entry_boundary();
        }
        if binding.entry_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(ENTRY_KICK_PORT, frame);
        }
        let Some(call) = carrick_personality_linux::entry::decode_x86_snapshot(frame.snapshot())
        else {
            doorbell(FORWARD_PORT, frame);
            halt();
        };
        binding
            .captured_stack
            .store(call.stack.raw(), Ordering::Release);
        let lifecycle_address = binding.scheduler_witness.load(Ordering::Acquire);
        if lifecycle_address == super::lifecycle::LIFECYCLE_LANE
            || lifecycle_address
                == super::lifecycle::LIFECYCLE_LANE + super::lifecycle::LIFECYCLE_STRIDE
        {
            // SAFETY: stopped-host bootstrap published and retains the aligned
            // native lane/zone/page custody for this exact CPU binding.
            let Some(mut lane) =
                (unsafe { super::lifecycle::acquire(frame, binding, task, counters, call.args) })
            else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            match carrick_personality_linux::dispatch::dispatch(
                call.canonical.raw(),
                u64::MAX,
                &mut lane,
            ) {
                carrick_personality_linux::dispatch::CompletionRoute::Served => {}
                carrick_personality_linux::dispatch::CompletionRoute::WithWork => {
                    doorbell(WORK_PORT, frame);
                }
                carrick_personality_linux::dispatch::CompletionRoute::Forward => {
                    doorbell(FORWARD_PORT, frame);
                    halt();
                }
                _ => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
            }
        } else {
            match serve_canonical(
                &call,
                counters,
                task,
                &GuestLifecycleVenue,
                Some(&binding.publications),
            ) {
                EntryOutcome::Served { result } | EntryOutcome::ServedWithWork { result } => {
                    frame.rax = result.raw() as u64;
                }
                EntryOutcome::InvalidCompletion => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
                EntryOutcome::Forward => {
                    doorbell(FORWARD_PORT, frame);
                    halt();
                }
            }
        }
        binding.completions.fetch_add(1, Ordering::Relaxed);
        if scheduler_witness {
            super::progress::return_boundary();
        }
        if binding.return_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(RETURN_KICK_PORT, frame);
        }
        if task.linux.has_pending_host_work() {
            task.linux.record_completed_with_work();
            doorbell(WORK_PORT, frame);
        }
    }

    pub fn halt() -> ! {
        loop {
            // SAFETY: terminal CPL0 fatal path, never returns to user.
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    kernel::halt()
}
