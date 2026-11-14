/* #2226 cause B: a second thread's first touch of its fresh stack and TLS,
 * on the other vCPU, meets a held MM editor. The main thread spins without
 * yielding or touching memory it has not committed, so the worker runs on
 * the idle peer; the main thread arms one editor hold only after the clone,
 * and the worker touches nothing new until it is armed. The worker's first
 * stack push parks on the editor's release and reruns; then its first TLS
 * store faults in. The main thread exits 7 once the worker raw-exited, 91 on
 * a failed check, 93 when the worker's fault never parked, 95 when the
 * worker never ran while the main thread held its own vCPU. */
#define INJECT_EDITOR_BUSY_ONCE -495 /* 0x...fe11 */
#define INJECT_WAIT_PARK_CENSUS -493 /* 0x...fe13 */
.global _start
.text
_start:
    movl $0, armed(%rip)
    /* Nonzero until the worker's exit clears it (CLONE_CHILD_CLEARTID). */
    movl $1, child_tid(%rip)
    /* mmap(NULL, 64 KiB, RW, PRIVATE|ANONYMOUS, -1, 0): the worker's stack,
     * untouched. */
    xor %edi, %edi
    mov $0x10000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    lea 0x10000(%rax), %r12
    /* One untouched page for the worker's TLS block. */
    xor %edi, %edi
    mov $0x1000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    mov %rax, %r8
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    mov %rax, %r14
    /* glibc's thread flags: VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID; TLS in r8. */
    mov $0x3d0f00, %edi
    mov %r12, %rsi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
    mov $INJECT_EDITOR_BUSY_ONCE, %rax
    syscall
    test %rax, %rax
    jnz failure
    movl $1, armed(%rip)
    /* Hold this vCPU without a syscall until the worker finished. */
    mov $0x40000000, %r13
1:
    cmpl $1, worker_done(%rip)
    je 2f
    pause
    dec %r13
    jnz 1b
    mov $95, %edi
    jmp exit
2:
    /* The worker's raw exit clears child_tid. */
    mov $100000, %r13d
3:
    cmpl $0, child_tid(%rip)
    je 4f
    dec %r13d
    jz failure
    mov $24, %eax
    syscall
    jmp 3b
4:
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    sub %r14, %rax
    jz census_failure
    mov $7, %edi
    jmp exit

worker:
    /* Touch nothing new until the hold is armed. */
    mov $100000000, %r13d
1:
    cmpl $1, armed(%rip)
    je 2f
    pause
    dec %r13d
    jnz 1b
    jmp failure
2:
    /* First stack touch: parks on the held editor, then reruns. */
    mov $0x5a, %eax
    push %rax
    pop %rcx
    cmp $0x5a, %rcx
    jne failure
    /* First TLS touch. */
    movq $0x6b, %fs:0
    cmpq $0x6b, %fs:0
    jne failure
    movl $1, worker_done(%rip)
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

census_failure:
    mov $93, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.bss
.balign 4096
armed: .space 4
worker_done: .space 4
parent_tid: .space 8
child_tid: .space 8
