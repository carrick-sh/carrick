// x86_64 DSR gateway trampoline (SysV ABI). See src/gateway.rs for the
// execution model and the field-offset asserts these `.equ`s mirror.
//
// %r15 is the DsrContext pointer throughout translated execution. Guest %r15
// is virtualized (kept in the snapshot, never loaded live). Enter and exit
// share one host frame: `enter_raw` jumps into the guest and never returns
// itself; an exit stub restores the host stack and `ret`s straight back to
// `enter_raw`'s caller with the exit status in %eax.

.equ SNAP_GPR,        0
.equ SNAP_RIP,        128
.equ SNAP_RFLAGS,     136
.equ SNAP_FXSAVE,     144
.equ HOST_RSP,        656
.equ HOST_CALLEE,     664
.equ CTX_ENTRY,       712
.equ CTX_EXIT_RESUME, 720
.equ CTX_EXIT_STATUS, 728
.equ CTX_GUEST_FSBASE, 776
.equ CTX_HOST_FSBASE,  784
.equ CTX_SAVE_FPU,     816

.text

.globl carrick_dsr_x86_enter_raw
.p2align 4
carrick_dsr_x86_enter_raw:
    // %rdi = ctx. Save host callee-saved + host rsp into the context.
    movq %rsp, HOST_RSP(%rdi)
    movq %rbx, HOST_CALLEE+0(%rdi)
    movq %rbp, HOST_CALLEE+8(%rdi)
    movq %r12, HOST_CALLEE+16(%rdi)
    movq %r13, HOST_CALLEE+24(%rdi)
    movq %r14, HOST_CALLEE+32(%rdi)
    movq %r15, HOST_CALLEE+40(%rdi)

    // Pin r15 = ctx for the duration of translated execution.
    movq %rdi, %r15

    // Install the guest fs base (Linux thread pointer) when the guest has
    // one; fs:-prefixed guest TLS accesses then copy through verbatim.
    // guest_fsbase == 0 means "no guest TLS yet" — skip the swap entirely.
    // (rax/rcx are dead here: guest GPRs load below.)
    movq CTX_GUEST_FSBASE(%r15), %rax
    testq %rax, %rax
    jz 1f
    rdfsbase %rcx
    movq %rcx, CTX_HOST_FSBASE(%r15)
    wrfsbase %rax
1:
    // Restore guest SSE/x87 ONLY when this block touches FPU/vector state
    // (save_fpu != 0). Integer-only blocks skip the 512-byte fxrstor; the
    // snapshot area still holds the last FPU-using block's guest state for the
    // next FPU-using block. Then restore guest rflags (host stack active).
    cmpl $0, CTX_SAVE_FPU(%r15)
    je 3f
    fxrstor SNAP_FXSAVE(%r15)
3:
    pushq SNAP_RFLAGS(%r15)
    popfq

    // Load guest GPRs (all except rsp and r15).
    movq SNAP_GPR+0(%r15),   %rax
    movq SNAP_GPR+8(%r15),   %rcx
    movq SNAP_GPR+16(%r15),  %rdx
    movq SNAP_GPR+24(%r15),  %rbx
    movq SNAP_GPR+40(%r15),  %rbp
    movq SNAP_GPR+48(%r15),  %rsi
    movq SNAP_GPR+56(%r15),  %rdi
    movq SNAP_GPR+64(%r15),  %r8
    movq SNAP_GPR+72(%r15),  %r9
    movq SNAP_GPR+80(%r15),  %r10
    movq SNAP_GPR+88(%r15),  %r11
    movq SNAP_GPR+96(%r15),  %r12
    movq SNAP_GPR+104(%r15), %r13
    movq SNAP_GPR+112(%r15), %r14
    // guest r15 (SNAP_GPR+120) intentionally NOT loaded — r15 == ctx.

    // Load guest rsp last, then jump to the translated block.
    movq SNAP_GPR+32(%r15), %rsp
    jmpq *CTX_ENTRY(%r15)

// ---------------------------------------------------------------------------
// Exit stubs. Translated code branches here with r15 == ctx. Each writes a
// distinct status; all share the save/restore tail. `mov` preserves rflags,
// so guest flags stay intact until captured on the host stack.
// ---------------------------------------------------------------------------

.globl carrick_dsr_x86_exit_syscall
.p2align 4
carrick_dsr_x86_exit_syscall:
    movl $1, CTX_EXIT_STATUS(%r15)   // X86ExitStatus::Syscall
    jmp carrick_dsr_x86_exit_common

.globl carrick_dsr_x86_exit_indirect
.p2align 4
carrick_dsr_x86_exit_indirect:
    movl $3, CTX_EXIT_STATUS(%r15)   // X86ExitStatus::Indirect
    jmp carrick_dsr_x86_exit_common

.globl carrick_dsr_x86_exit_sensitive
.p2align 4
carrick_dsr_x86_exit_sensitive:
    movl $6, CTX_EXIT_STATUS(%r15)   // X86ExitStatus::Sensitive
    jmp carrick_dsr_x86_exit_common

// Guest-fault exit: the host signal shim rewrites the interrupted context's
// RIP to land here, so sigreturn "resumes" at this stub with the guest's
// registers live (r15 still == ctx) and the fault already recorded in the
// context's FaultRecord. The shared tail then captures guest state exactly
// like any other exit. NOTE: snapshot.rip gets the per-block exit_resume —
// the FaultRecord's host_rip is the authoritative fault location.
.globl carrick_dsr_x86_exit_signal
.p2align 4
carrick_dsr_x86_exit_signal:
    movl $4, CTX_EXIT_STATUS(%r15)   // X86ExitStatus::Signal
    jmp carrick_dsr_x86_exit_common

.globl carrick_dsr_x86_exit_common
carrick_dsr_x86_exit_common:
    // Save guest GPRs (movs preserve flags). Skip r15 (== ctx).
    movq %rax, SNAP_GPR+0(%r15)
    movq %rcx, SNAP_GPR+8(%r15)
    movq %rdx, SNAP_GPR+16(%r15)
    movq %rbx, SNAP_GPR+24(%r15)
    movq %rbp, SNAP_GPR+40(%r15)
    movq %rsi, SNAP_GPR+48(%r15)
    movq %rdi, SNAP_GPR+56(%r15)
    movq %r8,  SNAP_GPR+64(%r15)
    movq %r9,  SNAP_GPR+72(%r15)
    movq %r10, SNAP_GPR+80(%r15)
    movq %r11, SNAP_GPR+88(%r15)
    movq %r12, SNAP_GPR+96(%r15)
    movq %r13, SNAP_GPR+104(%r15)
    movq %r14, SNAP_GPR+112(%r15)
    movq %rsp, SNAP_GPR+32(%r15)     // guest rsp

    // Switch to the host stack, then capture guest rflags FIRST — only `mov`s
    // ran since the guest, so flags are still intact. This MUST precede the
    // FPU conditional below, whose `cmpl` clobbers flags.
    movq HOST_RSP(%r15), %rsp
    pushfq
    popq %rax
    movq %rax, SNAP_RFLAGS(%r15)

    // Capture guest SSE/x87 only when this block used FPU/vector state; an
    // integer-only block left the snapshot's fxsave area untouched, so its
    // stored guest state stays valid. Guest xmm/x87 are still live here (only
    // mov/pushfq/popq ran since the guest — none touch them); rflags are
    // already saved, so the flag-clobbering `cmpl` is safe.
    cmpl $0, CTX_SAVE_FPU(%r15)
    je 4f
    fxsave SNAP_FXSAVE(%r15)
4:

    // Resume RIP = pre-filled per-block resume target.
    movq CTX_EXIT_RESUME(%r15), %rax
    movq %rax, SNAP_RIP(%r15)

    // Restore the host fs base if the guest's was installed at entry. The
    // guest cannot have CHANGED fsbase inside a block (wrfsbase/arch_prctl
    // classify Sensitive and exit), so guest_fsbase needs no re-read. Guest
    // rflags are already captured — test/jz are safe here.
    movq CTX_GUEST_FSBASE(%r15), %rax
    testq %rax, %rax
    jz 2f
    movq CTX_HOST_FSBASE(%r15), %rax
    wrfsbase %rax
2:

    // Restore host callee-saved; return status in %eax. Restore host r15 last.
    movl CTX_EXIT_STATUS(%r15), %eax
    movq HOST_CALLEE+0(%r15),  %rbx
    movq HOST_CALLEE+8(%r15),  %rbp
    movq HOST_CALLEE+16(%r15), %r12
    movq HOST_CALLEE+24(%r15), %r13
    movq HOST_CALLEE+32(%r15), %r14
    movq HOST_CALLEE+40(%r15), %r15
    ret

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
