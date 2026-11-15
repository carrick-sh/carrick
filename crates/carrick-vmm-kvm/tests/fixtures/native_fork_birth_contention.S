/* #2242: a sibling's fork while this process's fork holds its birth
 * reservation (Go forks from several goroutines at once). The fixture
 * image holds the leader's fork inside `reserve_birth`
 * (INJECT_HOLD_NEXT_BIRTH) until the worker's fork parks or returns, so
 * the contention is deterministic: no sleeps.
 *
 * Leader: arm the hold; clone a worker; fork (held).
 * Worker: poll INJECT_BIRTH_HELD; fork must wait for the release and then
 * fork; its child exits 0.
 *
 * Exit 7: the worker forked. 100 + n: the worker's fork failed with errno
 * n (111 = EAGAIN); 200 + n: the held fork failed with errno n. Other
 * codes name a failed setup step.
 */
#define INJECT_HOLD_NEXT_BIRTH    0xfffffffffffffe1f
#define INJECT_BIRTH_HELD         0xfffffffffffffe20
#define INJECT_RELEASE_HELD_BIRTH 0xfffffffffffffe21
#define POLL_LIMIT                0x10000000

.global _start
.text
_start:
    /* mmap(NULL, 0x3000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    xor %edi, %edi
    mov $0x3000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_mmap
    mov %rax, %r12

    /* Shared layout in %r12:
     * +0x00: u32 worker tid / CLEARTID word
     * +0x18: i32 worker ready
     * +0x30: i32 worker result
     * +0x40: timespec join timeout = { 5, 0 }
     */
    movq $5, 0x40(%r12)
    movq $0, 0x48(%r12)

    mov $INJECT_HOLD_NEXT_BIRTH, %rax
    syscall
    test %rax, %rax
    jnz fail_arm

    /* Worker thread (CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID). */
    mov $0x003d0f00, %edi
    lea 0x2ff0(%r12), %rsi
    mov %r12, %rdx
    mov %r12, %r10
    lea 0x100(%r12), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker

    /* Let the worker start: once it runs, the idle CPU holds one of the
     * two members, so the held fork never starves it of a CPU. */
    mov $POLL_LIMIT, %r13
ready_loop:
    cmpl $0, 0x18(%r12)
    jne ready
    dec %r13
    jz fail_ready
    mov $24, %eax
    syscall
    jmp ready_loop
ready:

    /* The held fork; its child exits 0 at once. Its result is reported
     * after the worker's, which is this witness's claim. */
    xor %r15d, %r15d
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child_exit
    jns join_loop
    mov %eax, %r15d

    /* Join the worker through its CLONE_CHILD_CLEARTID word. */
join_loop:
    mov (%r12), %edx
    test %edx, %edx
    jz joined
    mov %r12, %rdi
    xor %esi, %esi
    lea 0x40(%r12), %r10
    mov $202, %eax
    syscall
    cmp $-110, %rax
    je fail_join
    jmp join_loop
joined:
    mov 0x30(%r12), %edi
    cmp $22, %edi
    jne die
    test %r15d, %r15d
    jnz fail_held_fork
    mov $7, %edi
    jmp die

worker:
    movl $1, 0x18(%r12)

    mov $POLL_LIMIT, %r13
held_loop:
    mov $INJECT_BIRTH_HELD, %rax
    syscall
    cmp $1, %rax
    je held
    dec %r13
    jz worker_never_held
    pause
    jmp held_loop
held:

    /* fork() while the leader's fork holds the reservation. */
    mov $57, %eax
    syscall
    test %rax, %rax
    jz child_exit
    mov %rax, %r14
    mov $INJECT_RELEASE_HELD_BIRTH, %rax
    syscall
    test %r14, %r14
    js worker_errno
    movl $22, 0x30(%r12)
    jmp worker_exit
worker_errno:
    neg %r14d
    add $100, %r14d
    mov %r14d, 0x30(%r12)
    jmp worker_exit
worker_never_held:
    movl $99, 0x30(%r12)
    mov $INJECT_RELEASE_HELD_BIRTH, %rax
    syscall
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

child_exit:
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2

fail_mmap:
    mov $81, %edi
    jmp die
fail_held_fork:
    mov %r15d, %edi
    neg %edi
    add $200, %edi
    jmp die
fail_arm:
    mov $85, %edi
    jmp die
fail_clone:
    mov $86, %edi
    jmp die
fail_ready:
    mov $87, %edi
    jmp die
fail_join:
    mov $88, %edi
die:
    mov $231, %eax
    syscall
    ud2
