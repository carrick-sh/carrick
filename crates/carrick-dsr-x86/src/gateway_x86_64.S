// x86_64 DSR gateway trampoline (SysV ABI). See src/gateway.rs for the
// execution model and the field-offset asserts these `.equ`s mirror.
//
// %r15 is the DsrContext pointer throughout translated execution. Guest %r15
// is virtualized (kept in the snapshot, never loaded live). Enter and exit
// share one host frame: `enter_raw` jumps into the guest and never returns
// itself; an exit stub restores the host stack and `ret`s straight back to
// `enter_raw`'s caller with the exit status in %eax.

.equ SNAP_GPR,         0
.equ SNAP_RIP,         128
.equ SNAP_RFLAGS,      136
.equ SNAP_XSAVE,       192
.equ CTX_HOST_XSAVE,   16576
.equ HOST_RSP,         32960
.equ HOST_CALLEE,      32968
.equ CTX_ENTRY,        33016
.equ CTX_EXIT_RESUME,  33024
.equ CTX_EXIT_STATUS,  33032
.equ CTX_GUEST_FSBASE, 33080
.equ CTX_HOST_FSBASE,  33088
.equ CTX_SAVE_FPU,     33120
.equ CTX_XSAVEOPT,     33124
.equ CTX_DIAGNOSTIC,   33160
.equ CTX_HOST_XSAVE_INIT, 33164
.equ CTX_INDIRECT_CACHE_TABLE, 33168
.equ CTX_INDIRECT_CACHE_LEN, 33176
.equ CTX_INDIRECT_CACHE_SITE, 33180
.equ CTX_INDIRECT_ACTUAL, 33184
.equ CTX_KICK_RESTORE_RCX, 33192
.equ CTX_EXIT_KICKED_ADDR, 33200
.equ CTX_EXECUTABLE_STOP_WORD, 33208
// Host-injected `extern "C" fn(base: u64)` that installs a hardware FS base via
// the host's mechanism. Only referenced on the `#if defined(__NetBSD__)` path,
// where the kernel does not enable ring-3 CR4.FSGSBASE. See gateway.rs
// (`CTX_SET_FSBASE_FN` / `X86DsrContext::set_fsbase_fn`).
.equ CTX_SET_FSBASE_FN, 33240

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

    // Save the host fs base and install the guest's Linux thread pointer for
    // every full entry. Zero is a real guest FS base, not a sentinel: skipping
    // that write would expose host TLS to a guest after ARCH_SET_FS(0).
    // (rax/rcx are dead here: guest GPRs load below.)
#if defined(__NetBSD__)
    // NetBSD 10.x does NOT enable ring-3 CR4.FSGSBASE, so rdfsbase/wrfsbase #UD
    // in userland. Site 1 (the rdfsbase host-base capture) is ELIMINATED: the
    // host base is invariant per host thread and was captured once via
    // sysarch(X86_64_GET_FSBASE) at run-loop setup (CTX_HOST_FSBASE already
    // holds it). Site 2 installs the guest base through the host-injected
    // sysarch(X86_64_SET_FSBASE) leaf. %r15 (ctx) is SysV callee-saved and
    // survives the call; rdi carries the base; rax/rcx are dead here.
    movq CTX_GUEST_FSBASE(%r15), %rdi
    subq $8, %rsp                        // 16-byte SysV alignment for the call
    call *CTX_SET_FSBASE_FN(%r15)
    addq $8, %rsp
#else
    movq CTX_GUEST_FSBASE(%r15), %rax
    rdfsbase %rcx
    movq %rcx, CTX_HOST_FSBASE(%r15)
    wrfsbase %rax
#endif
    // Preserve the complete host extended state, then install the guest's
    // hardware-safe state. Host PKRU is included; guest PKRU is virtualized
    // outside this XSAVE payload so it cannot revoke gateway/context access.
    // Integer-only blocks skip this pair entirely.
    cmpl $0, CTX_SAVE_FPU(%r15)
    je 7f
    xorl %ecx, %ecx
    xgetbv
    // XSAVEOPT's modified-state optimization is valid only after this stable
    // destination contains one complete baseline image. Keep the first host
    // save full; later entries use the same buffer and full XCR0 mask.
    cmpl $0, CTX_XSAVEOPT(%r15)
    je .Lhost_xsave_full
    cmpl $0, CTX_HOST_XSAVE_INIT(%r15)
    je .Lhost_xsave_first
    xsaveopt64 CTX_HOST_XSAVE(%r15)
    jmp .Lhost_xsave_done
.Lhost_xsave_first:
    xsave64 CTX_HOST_XSAVE(%r15)
    movl $1, CTX_HOST_XSAVE_INIT(%r15)
    jmp .Lhost_xsave_done
.Lhost_xsave_full:
    xsave64 CTX_HOST_XSAVE(%r15)
.Lhost_xsave_done:
    xrstor64 SNAP_XSAVE(%r15)
    jmp 3f
7:
    // Diagnostic-only deterministic negative control: model arbitrary host
    // vector use at a skipped transfer boundary. PCMPEQD changes no flags; the
    // guest RFLAGS image is restored below regardless.
    testl $1, CTX_DIAGNOSTIC(%r15)
    jz 3f
    pcmpeqd %xmm0, %xmm0
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

// Asynchronous runtime kick: the FreeBSD exit-group signal shim redirects a
// translated thread here. No fault record is written; the runtime only needs
// a safe gateway boundary so it can observe the process-exit rendezvous.
.globl carrick_dsr_x86_exit_kicked
.p2align 4
carrick_dsr_x86_exit_kicked:
    movl $7, CTX_EXIT_STATUS(%r15)   // X86ExitStatus::Kicked
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

    // Guest AC and DF are both legal state, but neither may leak into gateway
    // comparisons or the SysV/Rust host. Preserve the exact guest image above,
    // then clear both bits through a user-legal RFLAGS restore immediately.
    // -263169 == ~((1 << 18) | (1 << 10)) as a sign-extended imm32.
    andq $-263169, %rax
    pushq %rax
    popfq

    // A translated return may publish a one-based monomorphic cache site and
    // its live stack target without changing guest flags or registers. Resolve
    // a hit here, after the full GPR/RFLAGS snapshot but BEFORE transferring
    // xstate back to the host. This keeps G resident across the return while a
    // cold/mismatched/host-resident site follows the ordinary Rust path.
    cmpl $3, CTX_EXIT_STATUS(%r15)
    jne .Lfull_exit
    movl CTX_INDIRECT_CACHE_SITE(%r15), %eax
    testl %eax, %eax
    jz .Lfull_exit
    // The ret is still unapplied here: guest RSP and RIP remain at the exact
    // return-instruction boundary. Poll the per-run stop word before any cache
    // validation or architectural stack/RIP mutation. Ordinary x86 loads have
    // acquire semantics; all guest GPRs/RFLAGS are already in the snapshot.
    movq CTX_EXECUTABLE_STOP_WORD(%r15), %rcx
    testq %rcx, %rcx
    jz .Lreturn_cache_validate
    movl 0(%rcx), %ecx
    testl %ecx, %ecx
    jz .Lreturn_cache_validate
    movl $7, CTX_EXIT_STATUS(%r15)   // X86ExitStatus::Kicked
    jmp .Lfull_exit
.Lreturn_cache_validate:
    cmpl CTX_INDIRECT_CACHE_LEN(%r15), %eax
    ja .Lfull_exit
    movq CTX_INDIRECT_CACHE_TABLE(%r15), %rcx
    testq %rcx, %rcx
    jz .Lfull_exit
    decl %eax
    shlq $5, %rax                 // sizeof(X86IndirectCacheEntry) == 32
    addq %rcx, %rax
    movq 0(%rax), %rdx            // expected guest target (zero = cold)
    testq %rdx, %rdx
    jz .Lfull_exit
    cmpq CTX_INDIRECT_ACTUAL(%r15), %rdx
    jne .Lfull_exit
    cmpl $0, CTX_SAVE_FPU(%r15)   // only G-resident intervals may stay in JIT
    je .Lfull_exit
    movq 8(%rax), %rcx            // translated target
    testq %rcx, %rcx
    jz .Lfull_exit
    movq %rcx, CTX_ENTRY(%r15)
    movq 16(%rax), %rcx           // ret's 8 + optional imm16 stack advance
    addq %rcx, SNAP_GPR+32(%r15)
    movq %rdx, SNAP_RIP(%r15)
    movl $0, CTX_INDIRECT_CACHE_SITE(%r15)
    jmp .Lresume_guest

.Lfull_exit:
    // Save every enabled guest xstate component and restore the complete host
    // extended state before returning to Rust. GPRs and guest RFLAGS are safe in
    // the snapshot, so XGETBV's clobbers are harmless here.
    cmpl $0, CTX_SAVE_FPU(%r15)
    je 4f
    xorl %ecx, %ecx
    xgetbv
    // Guest state must be a complete authoritative snapshot at every native
    // boundary. In particular, FreeBSD XSAVEOPT can omit x87 legacy bytes
    // after a copied FLD, leaving an unusable FIP/TOP payload for FXSAVE and
    // the legacy environment codecs. Keep the host-side persistent save
    // optimized, but use full XSAVE for guest publication.
    xsave64 SNAP_XSAVE(%r15)
    xrstor64 CTX_HOST_XSAVE(%r15)
4:
    // SysV requires DF clear on every host function boundary. Guest `std` is
    // legal state and was captured above, but must never leak into Rust/libc.
    cld

    // Resume RIP = pre-filled per-block resume target.
    movq CTX_EXIT_RESUME(%r15), %rax
    movq %rax, SNAP_RIP(%r15)

    // Every full entry installed the guest fs base, including zero. Restore
    // the saved host base on every full exit before any Rust/libc code runs.
    // Return-cache hits bypass this full-exit path and remain guest-resident.
#if defined(__NetBSD__)
    // NetBSD: restore the host base through the injected sysarch leaf (site 3).
    // The host stack is already active (HOST_RSP restored above). The call may
    // clobber caller-saved regs, but that is harmless here: %eax is reloaded
    // with the exit status below, and every host callee-saved register is
    // restored from the context immediately after (the movq HOST_CALLEE...
    // block). %r15 (ctx) survives the call by SysV. The set leaf is TLS-free,
    // so it does not itself deref the (currently guest) FS base.
    movq CTX_HOST_FSBASE(%r15), %rdi
    subq $8, %rsp                        // 16-byte SysV alignment for the call
    call *CTX_SET_FSBASE_FN(%r15)
    addq $8, %rsp
#else
    movq CTX_HOST_FSBASE(%r15), %rax
    wrfsbase %rax
#endif

    // Restore host callee-saved; return status in %eax. Restore host r15 last.
    movl CTX_EXIT_STATUS(%r15), %eax
    movq HOST_CALLEE+0(%r15),  %rbx
    movq HOST_CALLEE+8(%r15),  %rbp
    movq HOST_CALLEE+16(%r15), %r12
    movq HOST_CALLEE+24(%r15), %r13
    movq HOST_CALLEE+32(%r15), %r14
    movq HOST_CALLEE+40(%r15), %r15
    ret

// Resume a monomorphic indirect-cache hit without touching either xstate
// image or the FS bases: the same guest-resident interval is continuing.
// GPRs/RFLAGS were captured before cache lookup, so host-side comparisons and
// stack arithmetic cannot leak into guest architectural state.
.Lresume_guest:
    pushq SNAP_RFLAGS(%r15)
    popfq
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
    movq SNAP_GPR+32(%r15),  %rsp
    jmpq *CTX_ENTRY(%r15)

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
