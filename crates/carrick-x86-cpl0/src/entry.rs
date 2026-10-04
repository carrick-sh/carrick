//! Thin native entry. The initial red witness forwards every Linux call.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

// The linked common records also link alloc-capable cores. M2 serves no
// allocating operation; fail closed instead of inventing an x86 heap owner.
#[cfg(target_os = "none")]
struct NoAllocation;
#[cfg(target_os = "none")]
unsafe impl core::alloc::GlobalAlloc for NoAllocation {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        kernel::halt()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {
        kernel::halt()
    }
}
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: NoAllocation = NoAllocation;

#[cfg(target_os = "none")]
#[path = "../../carrick-x86/src/cpl0_entry.rs"]
mod adapter;

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
mod kernel {
    use super::adapter::*;
    use carrick_el1_abi::{Counters, CurrentTask};
    use core::sync::atomic::Ordering;

    fn doorbell(port: u16, frame: &mut NativeFrame) {
        // SAFETY: CPL0 owns the declared control/forwarding transport.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("rax") frame as *mut _ as u64,
                options(nostack, preserves_flags));
        }
    }

    #[unsafe(no_mangle)]
    extern "C" fn carrick_x86_enter(frame: &mut NativeFrame, binding: &CpuBinding) {
        if !frame.valid_user_return() {
            doorbell(FATAL_PORT, frame);
            halt();
        }
        if frame.rax == OBSERVE_NATIVE {
            doorbell(CONTROL_PORT, frame);
            frame.rax = 0;
            return;
        }
        // SAFETY: bootstrap retains these supervisor-only records until the
        // VM/vCPUs retire; each binding names its issued current task.
        let task = unsafe { &*(binding.task_address as *const CurrentTask) };
        let counters = unsafe { &*(binding.counters_address as *const Counters) };
        binding.entries.fetch_add(1, Ordering::Relaxed);
        if binding.entry_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(ENTRY_KICK_PORT, frame);
        }
        let call = frame.decode();
        if let Some(counter) = counters.forwarded.get(call.canonical.raw() as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        doorbell(FORWARD_PORT, frame);
        if frame.rax == 0 {
            binding.publications.fetch_add(1, Ordering::Relaxed);
        }
        binding.completions.fetch_add(1, Ordering::Relaxed);
        if binding.return_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(RETURN_KICK_PORT, frame);
        }
        if task.has_pending_host_work() {
            let _ = task.leave_served_with_work();
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
