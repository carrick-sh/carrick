/* #2900: a context whose PC sits on its SYSCALL instruction must re-enter
 * that SYSCALL exactly once, with every argument register intact, however
 * many times a signal checkpoint persists and resumes it.
 *
 * The SIGUSR1 handler rewrites its interrupted context to stand on a
 * Go-shaped `Syscall6` site (`mov %rsi,%r10; mov %rdi,%rdx; mov %rcx,%rsi;
 * mov %rbx,%rdi; syscall`) with getpid's number and marker arguments, as a
 * thread parked at the SYSCALL boundary is. Before returning it raises
 * SIGUSR2, blocked in the handler, and arms one contended copy of the next
 * signal frame. rt_sigreturn then lands on the boundary with SIGUSR2
 * deliverable: its frame copy is "not now", so the boundary context is
 * persisted and resumed before the SIGUSR2 handler runs. The SIGUSR2 handler
 * repeats the cycle (raise, arm, return) ROUNDS times.
 *
 * Every rewind past the SYSCALL lands on one of the prologue's moves: at
 * S-2 RDI becomes RBX, at S-6 RSI becomes the return RCX (#2900's
 * epoll_pwait values), at S-9 RDX becomes RDI.
 * Exit status names the first step that differs from Linux:
 *   2 rt_sigaction failed      3 the injected contention was refused
 *     (Linux answers the injection's number with ENOSYS)
 *   4 the boundary syscall's answer was not getpid's
 *   5 rdi, 6 rsi, 7 rdx, 8 r10, 9 r8, 10 r9 was not its marker
 *   11 the SIGUSR1 handler did not run once
 *   12 the SIGUSR2 handler did not run ROUNDS times
 *   13 the boundary SYSCALL did not complete exactly once
 *   14 a resumed boundary context was labelled after its SYSCALL
 *   0 every step matched Linux */
#define INJECT_OWNED_COPY_BUSY_ONCE -485 /* 0x...fe1b */
#define INJECT_EDITOR_BUSY_ONCE -495     /* 0x...fe11 */
#define INJECT_MISLABELLED_RESUME_CENSUS -437 /* 0x...fe4b */
#ifndef ROUNDS
#define ROUNDS 4
#endif
#define SIGUSR1 10
#define SIGUSR2 12
#define MARK_RDI 0x1111
#define MARK_RSI 0x2222
#define MARK_RDX 0x3333
#define MARK_R10 0x4444
#define MARK_R8 0x5555
#define MARK_R9 0x6666
.global _start
.text
_start:
    lea usr1(%rip), %rax
    mov %rax, action(%rip)
    movq $0x14000000, action+8(%rip)   /* SA_RESTART | SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $(1 << (SIGUSR2 - 1)), action+24(%rip)
    mov $SIGUSR1, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax                       /* rt_sigaction */
    syscall
    mov $2, %edi
    test %rax, %rax
    jnz exit
    lea usr2(%rip), %rax
    mov %rax, action(%rip)
    movq $(1 << (SIGUSR2 - 1)), action+24(%rip)
    mov $SIGUSR2, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    mov $2, %edi
    test %rax, %rax
    jnz exit
    mov $39, %eax                       /* getpid */
    syscall
    mov %eax, pid(%rip)
    mov $SIGUSR1, %edi
    call raise
    /* Not reached: the SIGUSR1 handler resumes at `boundary`. */
    mov $11, %edi
    jmp exit

    /* Go's internal/runtime/syscall.Syscall6 argument shuffle. */
    mov %rsi, %r10
    mov %rdi, %rdx
    mov %rcx, %rsi
    mov %rbx, %rdi
boundary:
    syscall
    incl boundary_done(%rip)
    mov %rdi, seen(%rip)
    mov %rsi, seen+8(%rip)
    mov %rdx, seen+16(%rip)
    mov %r10, seen+24(%rip)
    mov %r8, seen+32(%rip)
    mov %r9, seen+40(%rip)
    mov $4, %edi
    cmp pid(%rip), %eax
    jne exit
    mov $5, %edi
    cmpq $MARK_RDI, seen(%rip)
    jne exit
    mov $6, %edi
    cmpq $MARK_RSI, seen+8(%rip)
    jne exit
    mov $7, %edi
    cmpq $MARK_RDX, seen+16(%rip)
    jne exit
    mov $8, %edi
    cmpq $MARK_R10, seen+24(%rip)
    jne exit
    mov $9, %edi
    cmpq $MARK_R8, seen+32(%rip)
    jne exit
    mov $10, %edi
    cmpq $MARK_R9, seen+40(%rip)
    jne exit
    mov $11, %edi
    cmpl $1, usr1_runs(%rip)
    jne exit
    mov $12, %edi
    cmpl $ROUNDS, usr2_runs(%rip)
    jne exit
    mov $13, %edi
    cmpl $1, boundary_done(%rip)
    jne exit
    /* Every resumed boundary context named its PC at the SYSCALL. Linux
     * (the oracle) answers the census's number with ENOSYS. */
    mov $INJECT_MISLABELLED_RESUME_CENSUS, %rax
    syscall
    mov $14, %edi
    cmp $-38, %rax
    je passed
    test %rax, %rax
    jnz exit
passed:
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2

/* raise(%edi) through tgkill(pid, pid, sig): the root's tid is its pid. */
raise:
    mov %edi, %edx
    mov pid(%rip), %edi
    mov %edi, %esi
    mov $234, %eax                      /* tgkill */
    syscall
    ret

/* Raise SIGUSR2 (blocked here) and make the next signal-frame copy
 * contended once, so the context this handler returns to is persisted. */
rearm:
    mov $SIGUSR2, %edi
    call raise
#if defined(EDITOR_BUSY)
    mov $INJECT_EDITOR_BUSY_ONCE, %rax
#else
    mov $INJECT_OWNED_COPY_BUSY_ONCE, %rax
#endif
    syscall
    test %rax, %rax
    jz armed
    cmp $-38, %rax                      /* Linux (the oracle): ENOSYS */
    jne refused
armed:
    ret
refused:
    mov $3, %edi
    jmp exit

/* uc_mcontext: r8 40, r9 48, r10 56, rdi 104, rsi 112, rbx 128, rdx 136,
 * rax 144, rcx 152, rip 168 bytes into the ucontext. */
usr1:
    incl usr1_runs(%rip)
    lea boundary(%rip), %rax
    mov %rax, 168(%rdx)
    lea 2+boundary(%rip), %rax
    mov %rax, 152(%rdx)                 /* RCX: the return PC SYSCALL saved */
    movq $39, 144(%rdx)
    movq $MARK_RDI, 104(%rdx)
    movq $MARK_RDI, 128(%rdx)           /* RBX feeds RDI at S-2 */
    movq $MARK_RSI, 112(%rdx)
    movq $MARK_RDX, 136(%rdx)
    movq $MARK_R10, 56(%rdx)
    movq $MARK_R8, 40(%rdx)
    movq $MARK_R9, 48(%rdx)
    jmp rearm

usr2:
    incl usr2_runs(%rip)
    cmpl $ROUNDS, usr2_runs(%rip)
    jb rearm
    ret

restorer:
    mov $15, %eax                       /* rt_sigreturn */
    syscall
    ud2

.data
.balign 4096
action: .space 32
pid: .long 0
usr1_runs: .long 0
usr2_runs: .long 0
boundary_done: .long 0
.balign 8
seen: .space 48
.section .note.GNU-stack,"",@progbits
