//! Native CPL0 IRQ entry.
//!
//! The entry saves every user GPR and the qualified XCR0=7 xstate before
//! calling Rust. It retains an IRQ reason in the per-CPU binding for the
//! shared scheduler; no semantic host exit or result publication occurs here.

use crate::personality::Personality;
use carrick_el1::isa::x86::{
    context::scheduler::{InterruptFrame, XsaveArea},
    interrupt, interrupts,
};

// SAFETY: user-origin gates retain their frame on the private TSS stack,
// then move Rust and XSAVE to the CPU syscall stack. Kernel-origin gates
// retain the interrupted kernel stack. The push order is InterruptFrame's
// asserted layout, and the 896-byte scratch leaves space for the 832-byte
// extended-state area plus its 64-byte alignment preamble.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".section .irq_header, \"a\"",
    ".quad {magic}",
    ".quad carrick_x86_timer_irq",
    ".quad carrick_x86_kick_irq",
    ".quad carrick_x86_resched_irq",
    ".quad carrick_x86_shootdown_irq",
    ".quad carrick_x86_user_page_fault",
    ".section .text.irq, \"ax\"",
    ".global carrick_x86_timer_irq",
    "carrick_x86_timer_irq:",
    "push rdi",
    "mov edi, {timer}",
    "jmp carrick_x86_irq_common",
    ".global carrick_x86_kick_irq",
    "carrick_x86_kick_irq:",
    "push rdi",
    "mov edi, {kick}",
    "jmp carrick_x86_irq_common",
    ".global carrick_x86_resched_irq",
    "carrick_x86_resched_irq:",
    "push rdi",
    "mov edi, {resched}",
    "jmp carrick_x86_irq_common",
    ".global carrick_x86_shootdown_irq",
    "carrick_x86_shootdown_irq:",
    "push rdi",
    "mov edi, {shootdown}",
    "carrick_x86_irq_common:",
    "push rsi", "push rdx", "push rcx", "push rax",
    "push r8", "push r9", "push r10", "push r11",
    "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
    "test byte ptr [rsp + 128], 3",
    "jz 2f",
    "swapgs",
    "2:",
    "mov r12, rsp",
    "test byte ptr [r12 + 128], 3",
    "jz 4f",
    "mov rsp, gs:[0]",
    "4:",
    "sub rsp, 896",
    "and rsp, -64",
    "mov r13d, edi",
    "cld", "xor eax, eax", "mov rdi, rsp", "mov ecx, 104", "rep stosq",
    "mov rdi, rsp",
    "call carrick_x86_save_extended_state",
    "mov edi, r13d",
    "mov rsi, r12",
    "mov rdx, rsp",
    "call carrick_x86_receive_irq",
    "mov rdi, rsp",
    "call carrick_x86_restore_extended_state",
    "mov rsp, r12",
    "test byte ptr [rsp + 128], 3",
    "jz 3f",
    "swapgs",
    "3:",
    "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
    "pop r11", "pop r10", "pop r9", "pop r8", "pop rax", "pop rcx",
    "pop rdx", "pop rsi", "pop rdi",
    "iretq",
    ".global carrick_x86_save_extended_state",
    ".type carrick_x86_save_extended_state, @function",
    "carrick_x86_save_extended_state:",
    "xor eax, eax",
    "mov qword ptr [rdi + 512], rax",
    "mov qword ptr [rdi + 520], rax",
    "mov qword ptr [rdi + 528], rax",
    "mov qword ptr [rdi + 536], rax",
    "mov qword ptr [rdi + 544], rax",
    "mov qword ptr [rdi + 552], rax",
    "mov qword ptr [rdi + 560], rax",
    "mov qword ptr [rdi + 568], rax",
    "mov eax, 7",
    "xor edx, edx",
    "xsave64 [rdi]",
    "ret",
    ".global carrick_x86_restore_extended_state",
    ".type carrick_x86_restore_extended_state, @function",
    "carrick_x86_restore_extended_state:",
    "mov eax, 7",
    "xor edx, edx",
    "xrstor64 [rdi]",
    "ret",
    magic = const interrupts::IRQ_HEADER_MAGIC,
    timer = const interrupts::TIMER_VECTOR,
    kick = const interrupts::KICK_VECTOR,
    resched = const interrupts::RESCHED_VECTOR,
    shootdown = const interrupts::SHOOTDOWN_VECTOR,
);

/// Receives and handles an IRQ.
///
/// # Safety
///
/// `frame` and `xsave` must be valid, aligned pointers for the interrupted execution context.
pub unsafe fn carrier_receive_irq<P: Personality>(
    vector: u32,
    frame: *mut InterruptFrame,
    xsave: *mut XsaveArea,
) {
    // SAFETY: the IRQ assembly passes its own complete saved register frame;
    // a user-origin frame includes the five IRET words validated below.
    let frame = unsafe { &mut *frame };
    if (frame.cs & 3 == 3 && !frame.valid_user_return())
        || (frame.cs & 3 == 0 && frame.cs != 8)
        || u8::try_from(vector)
            .ok()
            .and_then(|vector| interrupt::capture_irq(vector).ok())
            .is_none()
    {
        // SAFETY: a refused native IRQ must leave through the declared fatal
        // doorbell; it must not IRET with an unknown or unacknowledged vector.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") carrick_el1::isa::x86::context::native::FATAL_PORT,
                in("al") 0u8,
                options(nostack)
            );
        }
        crate::entry::halt();
    }
    if vector == u32::from(interrupts::TIMER_VECTOR) {
        let binding = carrick_el1::isa::x86::context::current_cpu_binding()
            .unwrap_or_else(|| crate::entry::halt());
        let slot = carrick_sched_core::SlotId::from_index(binding.cpu_slot as usize)
            .unwrap_or_else(|| crate::entry::halt());
        let mut personality = P::default();
        personality.on_timer(slot);
    }
    if frame.cs & 3 == 3 {
        // SAFETY: the IRQ assembly owns this aligned early XSAVE area.
        let mut personality = P::default();
        personality.on_irq_return(frame, unsafe { &mut *xsave });
    }
    if frame.cs & 3 == 3 && interrupt::check_user_return_generation().is_err() {
        // SAFETY: generation mismatch on user return must notify fatal doorbell and halt.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") carrick_el1::isa::x86::context::native::FATAL_PORT,
                in("al") 0u8,
                options(nostack)
            );
        }
        crate::entry::halt();
    }
}
