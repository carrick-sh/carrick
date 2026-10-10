//! Native CPL0 IRQ entry shared by the production and fixture images.
//!
//! The entry saves every user GPR and the qualified XCR0=7 xstate before
//! calling Rust. It retains an IRQ reason in the per-CPU binding for the
//! shared scheduler; no semantic host exit or result publication occurs here.

use carrick_el1::isa::x86::{context::scheduler::InterruptFrame, interrupt, interrupts};

// SAFETY: user-origin gates retain their frame on the private TSS stack,
// then move Rust and XSAVE to the CPU syscall stack. Kernel-origin gates
// retain the interrupted kernel stack. The push order is InterruptFrame's
// asserted layout, and the 896-byte scratch leaves
// at least 832 aligned bytes for the admitted XCR0=7 XSAVE image. IF stays
// masked until IRETQ; SWAPGS is paired only for a user-origin interrupt.
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
    // Signal delivery on a user IRQ return exceeds the 4 KiB TSS entry
    // stack. Retain only its hardware/GPR frame there, like user #PF.
    // A kernel-origin IRQ must preserve the interrupted stack instead;
    // resetting it would overwrite an outer syscall or fault operation.
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

#[unsafe(no_mangle)]
extern "C" fn carrick_x86_receive_irq(vector: u32, frame: *mut InterruptFrame, xsave: *mut carrick_el1::isa::x86::context::scheduler::XsaveArea) {
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
        // doorbell; it must not IRET with an unacknowledged or unknown vector.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") carrick_el1::isa::x86::context::native::FATAL_PORT,
                in("al") 0u8,
                options(nostack)
            );
        }
        crate::kernel::halt();
    }
    if vector == u32::from(interrupts::TIMER_VECTOR) {
        crate::kernel::native_execution::expire_signal_timer(
            carrick_sched_core::SlotId::from_index(
                carrick_el1::isa::x86::context::current_cpu_binding().unwrap_or_else(|| crate::kernel::halt()).cpu_slot as usize
            ).unwrap_or_else(|| crate::kernel::halt())
        );
    }
    if frame.cs & 3 == 3 {
        // SAFETY: the IRQ assembly owns this aligned early XSAVE area.
        crate::signal_irq_return(frame, unsafe { &mut *xsave });
    }
    if frame.cs & 3 == 3 && interrupt::check_user_return_generation().is_err() {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") carrick_el1::isa::x86::context::native::FATAL_PORT,
                in("al") 0u8,
                options(nostack)
            );
        }
        crate::kernel::halt();
    }
}
