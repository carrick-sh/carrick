/* #2441: a multi-threaded parent (a Go program) forks on one thread while
 * another thread maps memory. The fork takes its census under the
 * parent's space editor, drops the editor for its stock loan crossing and
 * scratch, then its prepare re-checks the parent snapshot the census took.
 * The fixture image holds the leader's fork just before that prepare
 * (INJECT_HOLD_NEXT_FORK_PREPARE) while the worker thread runs a real
 * mmap, which moves the parent's generation, and then releases it: real
 * contention, deterministic, no sleeps and no injected refusal. The fork
 * must be "not now" (Busy) exactly once and then fork, never end the run
 * as a broken invariant or answer an errno.
 *
 * Leader: arm the hold; clone a worker; fork (held); reap the child; join
 * the worker; read the superseded-fork census.
 * Worker: poll INJECT_FORK_PREPARE_HELD; mmap; release the hold.
 *
 * Exit 7: the fork reran once and forked. 100 + n: the worker's mmap
 * failed with errno n; 200 + n: the held fork failed with errno n.
 * 91: no fork was superseded; 92: more than one was; 93: the worker never
 * saw the hold; 94: the child was not reaped with status 0. Other codes
 * name a failed setup step.
 */
#define INJECT_HOLD_NEXT_FORK_PREPARE    0xfffffffffffffe2f
#define INJECT_FORK_PREPARE_HELD         0xfffffffffffffe30
#define INJECT_RELEASE_HELD_FORK_PREPARE 0xfffffffffffffe31
#define INJECT_FORK_SUPERSEDED_CENSUS    0xfffffffffffffe32
#define INJECT_HOLD_EDITOR_AND_RESUME_FORK 0xfffffffffffffe35
#define INJECT_FORK_EDITOR_WAITERS      0xfffffffffffffe36
#define INJECT_FORK_EDITOR_PROGRESS     0xfffffffffffffe37
#define POLL_LIMIT                       0x10000000

.global _start
.text
_start:
    /* mmap(NULL, 0x5000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    xor %edi, %edi
    mov $0x5000, %esi
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
     * +0x60: i32 child wait status
     */
    movq $5, 0x40(%r12)
    movq $0, 0x48(%r12)

    mov $INJECT_HOLD_NEXT_FORK_PREPARE, %rax
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
#ifdef HOLD_EDITOR
    /* Two additional members share the fork's CPU when the editor's
     * sibling occupies the other CPL0 CPU. */
    mov $0x003d0f00, %edi
    lea 0x3ff0(%r12), %rsi
    lea 0x04(%r12), %rdx
    mov %rdx, %r10
    lea 0x180(%r12), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz pool_waiter

    mov $0x003d0f00, %edi
    lea 0x4ff0(%r12), %rsi
    lea 0x08(%r12), %rdx
    mov %rdx, %r10
    lea 0x200(%r12), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz pool_progress
#endif

    /* The held fork; its child exits 0 at once. */
    mov $57, %eax
    syscall
    test %rax, %rax
    jz child_exit
    js fail_held_fork
    mov %rax, %r14

    /* wait4(pid, &status, 0, NULL) */
    mov %r14, %rdi
    lea 0x60(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14, %rax
    jne fail_reap
    cmpl $0, 0x60(%r12)
    jne fail_reap

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
#ifdef HOLD_EDITOR
    /* Wait for the second forking member to report its successful reap. */
    mov $POLL_LIMIT, %r13
pool_join:
    cmpl $1, 0x70(%r12)
    je pool_joined
    dec %r13
    jz fail_join
    mov $24, %eax
    syscall
    jmp pool_join
pool_joined:
#endif
    mov 0x30(%r12), %edi
    cmp $22, %edi
    jne die

    mov $INJECT_FORK_SUPERSEDED_CENSUS, %rax
    syscall
    test %rax, %rax
    jz fail_not_superseded
    cmp $1, %rax
    jne fail_superseded_twice
    mov $7, %edi
    jmp die

worker:
    movl $1, 0x18(%r12)

    mov $POLL_LIMIT, %r13
held_loop:
    mov $INJECT_FORK_PREPARE_HELD, %rax
    syscall
    cmp $1, %rax
    je held
    dec %r13
    jz worker_never_held
    pause
    jmp held_loop
held:

    /* mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
     * -1, 0) while the leader's fork is held after its census. */
    xor %edi, %edi
    mov $0x1000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov %rax, %r14
#ifdef HOLD_EDITOR
    mov $INJECT_HOLD_EDITOR_AND_RESUME_FORK, %rax
    syscall
    test %rax, %rax
    jnz worker_never_held

#else
    mov $INJECT_RELEASE_HELD_FORK_PREPARE, %rax
    syscall
#endif
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
    movl $93, 0x30(%r12)
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

#ifdef HOLD_EDITOR
pool_waiter:
    mov $1, %r15d
    call wait_for_editor_queue
    mov $57, %eax
    syscall
    test %rax, %rax
    jz child_exit
    js fail_held_fork
    mov %rax, %r14
    mov %rax, %rdi
    lea 0x68(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14, %rax
    jne fail_reap
    cmpl $0, 0x68(%r12)
    jne fail_reap
    movl $1, 0x70(%r12)
    jmp worker_exit

pool_progress:
    mov $2, %r15d
    call wait_for_editor_queue
    /* This member runs with both fork continuations still parked. */
    mov $39, %eax
    syscall
    test %rax, %rax
    jle fail_ready
    mov $INJECT_FORK_EDITOR_PROGRESS, %rax
    syscall
    test %rax, %rax
    jnz fail_ready
    jmp worker_exit

wait_for_editor_queue:
    mov $POLL_LIMIT, %r13
1:
    mov $INJECT_FORK_EDITOR_WAITERS, %rax
    syscall
    cmp %r15, %rax
    je 2f
    dec %r13
    jz fail_ready
    mov $24, %eax
    syscall
    jmp 1b
2:
    ret
#endif

child_exit:
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2

fail_mmap:
    mov $81, %edi
    jmp die
fail_held_fork:
    mov %eax, %edi
    neg %edi
    add $200, %edi
    jmp die
fail_not_superseded:
    mov $91, %edi
    jmp die
fail_superseded_twice:
    mov $92, %edi
    jmp die
fail_reap:
    mov $94, %edi
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
