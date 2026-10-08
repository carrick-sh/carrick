//! Native CPL0 IRQ entry shared by the production and fixture images.
//!
//! The entry saves every user GPR and the qualified XCR0=7 xstate before
//! calling Rust. It retains an IRQ reason in the per-CPU binding for the
//! shared scheduler; no semantic host exit or result publication occurs here.

use carrick_el1::isa::x86::{context::scheduler::InterruptFrame, interrupt, interrupts};

// SAFETY: these interrupt gates run at CPL0 on private TSS stacks. The push
// order is InterruptFrame's asserted layout, and the 896-byte scratch leaves
// at least 832 aligned bytes for the admitted XCR0=7 XSAVE image. IF stays
// masked until IRETQ; SWAPGS is paired only for a user-origin interrupt.
core::arch::global_asm!(
    ".section .irq_header, \"a\"",
    ".quad {magic}",
    ".quad carrick_x86_timer_irq",
    ".quad carrick_x86_kick_irq",
    ".quad carrick_x86_resched_irq",
    ".quad carrick_x86_shootdown_irq",
    ".quad carrick_x86_page_fault",
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
    "sub rsp, 896",
    "and rsp, -64",
    "mov eax, 7", "xor edx, edx", "xsave64 [rsp]",
    "mov rsi, r12",
    "call carrick_x86_receive_irq",
    "mov eax, 7", "xor edx, edx", "xrstor64 [rsp]",
    "mov rsp, r12",
    "test byte ptr [rsp + 128], 3",
    "jz 3f",
    "swapgs",
    "3:",
    "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
    "pop r11", "pop r10", "pop r9", "pop r8", "pop rax", "pop rcx",
    "pop rdx", "pop rsi", "pop rdi",
    "iretq",
    ".global carrick_x86_page_fault",
    "carrick_x86_page_fault:",
    "test byte ptr [rsp + 16], 3",
    "jz 4f",
    "swapgs",
    "mov rdi, qword ptr [rsp]",
    "mov rsi, qword ptr [rsp + 8]",
    "mov rdx, qword ptr [rsp + 16]",
    "mov rcx, qword ptr [rsp + 32]",
    "mov r8, qword ptr [rsp + 24]",
    "mov r9, rax",
    "call carrick_x86_receive_page_fault",
    "4:",
    "push rax",
    "push rdx",
    "cmp qword ptr [rsp + 32], 8",
    "jne 5f",
    "mov rax, qword ptr gs:[24]",
    "test rax, rax",
    "jz 5f",
    "mov rdx, qword ptr [rax + 24]",
    "test rdx, rdx",
    "jz 5f",
    "mov qword ptr [rsp + 24], rdx",
    "pop rdx",
    "pop rax",
    "add rsp, 8",
    "iretq",
    "5:",
    "ud2",
    magic = const interrupts::IRQ_HEADER_MAGIC,
    timer = const interrupts::TIMER_VECTOR,
    kick = const interrupts::KICK_VECTOR,
    resched = const interrupts::RESCHED_VECTOR,
    shootdown = const interrupts::SHOOTDOWN_VECTOR,
);

#[unsafe(no_mangle)]
extern "C" fn carrick_x86_receive_irq(vector: u32, frame: *const InterruptFrame) {
    // SAFETY: the IRQ assembly passes its own complete saved register frame;
    // a user-origin frame includes the five IRET words validated below.
    let frame = unsafe { &*frame };
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

#[unsafe(no_mangle)]
extern "C" fn carrick_x86_receive_page_fault(
    error_code: u64,
    rip: u64,
    cs: u64,
    rsp: u64,
    rflags: u64,
    saved_rax: u64,
) -> ! {
    if cs & 3 != 3 || interrupt::service_shootdowns().is_err() {
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
    let cr2: u64;
    // SAFETY: reading CR2 captures the page fault linear address for the doorbell record.
    unsafe {
        core::arch::asm!(
            "mov {}, cr2",
            out(reg) cr2,
            options(nomem, nostack, preserves_flags)
        );
    }
    unsafe {
        send_fault_word(u32::from(interrupts::PAGE_FAULT_VECTOR));
        send_fault_qword(error_code);
        send_fault_qword(rip);
        send_fault_qword(cs);
        send_fault_qword(rsp);
        send_fault_qword(rflags);
        send_fault_qword(saved_rax);
        send_fault_qword(cr2);
    }
    fixture_stmt! {
        // The terminal fixture fault can be reentered solely to witness the
        // queued KICK before a bounded completion exit. STI's shadow ends at NOP.
        unsafe {
            core::arch::asm!("sti", "nop", "out dx, al",
                in("dx") carrick_el1::isa::x86::context::native::CONTROL_PORT,
                in("al") 0u8, options(nostack));
        }
    }
    crate::kernel::halt();
}

#[inline(always)]
unsafe fn send_fault_word(word: u32) {
    // SAFETY: the caller ensures the fault doorbell port is ready to accept
    // the next 32-bit word of the fault record.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") carrick_el1::isa::x86::context::native::FAULT_DOORBELL_PORT,
            in("eax") word,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
unsafe fn send_fault_qword(qword: u64) {
    // SAFETY: caller ensures the port is ready for two consecutive 32-bit words.
    unsafe {
        send_fault_word(qword as u32);
        send_fault_word((qword >> 32) as u32);
    }
}
