/* #2141: a signal arrives for a thread parked on its contended user fault.
 * The worker's first touch of fresh anonymous memory meets a held MM editor
 * after its Prepare supply and parks (a FaultRetry wait). The main thread
 * sees that park, sends the worker SIGUSR1, then releases the holder. The
 * resumed fault returns to user mode with the signal pending: the handler
 * runs exactly once before the store reruns, and the rerun completes with
 * RAX (a canary) and the stored byte intact. The main thread exits 7 once
 * the worker raw-exited, 91 on a failed check, 92 on a clobbered canary,
 * 93 when the park never came, 94 when the handler had not run exactly
 * once by the time the store completed. */
#define INJECT_WAIT_PARK_CENSUS -493         /* 0x...fe13 */
#define INJECT_POST_SUPPLY_BUSY_HELD -462    /* 0x...fe32 */
#define INJECT_RELEASE_POST_SUPPLY_HOLD -461 /* 0x...fe33 */
#define CANARY 0x1122334455667788
#define SIGUSR1 10
#define SA_RESTORER 0x04000000
.global _start
.text
_start:
    /* Commit every page the handler, its frame and the sync words touch, so
     * only the worker's one store meets the held editor. */
    lea thread_stack(%rip), %rdi
    mov $4, %ecx
1:
    movb $0, (%rdi)
    add $4096, %rdi
    dec %ecx
    jnz 1b
    movl $0, handled(%rip)
    /* Nonzero until the worker's exit clears it (CLONE_CHILD_CLEARTID). */
    movl $1, child_tid(%rip)
    /* rt_sigaction(SIGUSR1, &act, NULL, 8) */
    lea handler(%rip), %rax
    mov %rax, act(%rip)
    movq $SA_RESTORER, act+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, act+16(%rip)
    movq $0, act+24(%rip)
    mov $SIGUSR1, %edi
    lea act(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    jnz failure
    /* mmap(NULL, 1 MiB, RW, PRIVATE|ANONYMOUS, -1, 0), untouched. */
    xor %edi, %edi
    mov $0x100000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    lea 0x80000(%rax), %rbx
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    mov %rax, %r14
    /* glibc's thread flags: VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID. */
    mov $0x3d0f00, %edi
    lea thread_stack_top(%rip), %rsi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    lea tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
    /* The worker's store parked. */
    lea 1(%r14), %r15
    call await_parks
    /* tgkill(getpid(), worker, SIGUSR1) */
    mov $39, %eax
    syscall
    mov %eax, %edi
    mov parent_tid(%rip), %esi
    mov $SIGUSR1, %edx
    mov $234, %eax
    syscall
    test %rax, %rax
    jnz failure
    mov $INJECT_RELEASE_POST_SUPPLY_HOLD, %rax
    syscall
    cmp $1, %rax
    jne failure
    /* The worker's raw exit clears child_tid. */
    mov $100000, %r13d
4:
    cmpl $0, child_tid(%rip)
    je 5f
    dec %r13d
    jz failure
    mov $24, %eax
    syscall
    jmp 4b
5:
    cmpl $1, worker_done(%rip)
    jne failure
    mov $7, %edi
    jmp exit

worker:
    mov $INJECT_POST_SUPPLY_BUSY_HELD, %rax
    syscall
    test %rax, %rax
    jnz failure
    movabs $CANARY, %rax
    mov %al, (%rbx)
    movabs $CANARY, %rcx
    cmp %rcx, %rax
    jne canary_failure
    cmpb $0x88, (%rbx)
    jne failure
    cmpl $1, handled(%rip)
    jne handler_failure
    movl $1, worker_done(%rip)
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

handler:
    lock incl handled(%rip)
    ret
restorer:
    mov $15, %eax
    syscall
    ud2

/* sched_yield until the park census reaches %r15 (bounded). */
await_parks:
    mov $100000, %r13d
1:
    dec %r13d
    jz census_failure
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    cmp %r15, %rax
    jae 2f
    mov $24, %eax
    syscall
    jmp 1b
2:
    ret

canary_failure:
    mov $92, %edi
    jmp exit
census_failure:
    mov $93, %edi
    jmp exit
handler_failure:
    mov $94, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.bss
.balign 4096
handled: .space 4
worker_done: .space 4
parent_tid: .space 8
child_tid: .space 8
act: .space 32
tls: .space 256
.balign 4096
thread_stack: .space 16384
thread_stack_top:
