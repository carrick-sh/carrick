/* #2749 fatal 3: threads of the container root spin on sched_yield while
 * a sibling is parked. The root (pinned to CPU 0 by the test) clones four
 * workers, so five threads share two CPUs:
 *
 *   workers 1 and 2  make no call but sched_yield until `stop` is set;
 *   worker 3         yields ROUNDS times, then sets `gate` and wakes it;
 *   worker 4         FUTEX_WAITs on `gate`, then sets `stop`;
 *   the root         makes no call but sched_yield until `stop` is set.
 *
 * So the woken waiter comes back to a run queue whose CPU a yielder holds.
 * Every yield must return 0 and the park must end: a yield that reports a
 * switch it did not make kills the carrier, and one that never gives the
 * CPU up starves the woken thread.
 *
 * The workers exit one at a time (4 after 3, 2 after 4, 1 after 2), each a
 * non-last thread's raw exit beside running yielders. With LIVE_YIELDER,
 * worker 1 never exits: the root's exit_group ends it while it yields.
 *
 * Every wait is bounded by BOUND_TICKS of the TSC (RDTSC, not a syscall).
 * Exit 0: the park ended and every yield returned 0. 91: the root waited
 * out the bound for `stop`; 93: it waited out the bound for the workers'
 * exits; 94: a sched_yield returned nonzero; 96: the
 * futex wait failed with something other than EAGAIN or EINTR; 81: mmap
 * failed; 100 + n: clone failed with errno n.
 */
#define ROUNDS 512
#ifndef BOUND_TICKS
#define BOUND_TICKS 3000000000
#endif

/* Shared pages: +0x08 u32 stop, +0x0c u32 gate, +0x10 u32 fault (a worker's
 * failure code); worker k's stack below +0x1000 * (k + 1); worker k's
 * CLEARTID word at +0x5000 + 4 * k. */
#define STOP 0x08
#define GATE 0x0c
#define FAULT 0x10
#define TIDS 0x5000

.global _start
.text
_start:
    xor %edi, %edi
    mov $0x6000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4096, %rax
    jae fail_setup
    mov %rax, %r12
    /* Make every shared page resident before the clones: the witness is
     * the yield, not a first touch. */
    movl $0, 0x0000(%r12)
    movl $0, 0x1000(%r12)
    movl $0, 0x2000(%r12)
    movl $0, 0x3000(%r12)
    movl $0, 0x4000(%r12)
    movl $0, 0x5000(%r12)

    mov $1, %ebx
spawn_next:
    mov %ebx, %esi
    inc %esi
    shl $12, %esi
    lea -0x10(%r12,%rsi), %rsi
    call spawn
    inc %ebx
    cmp $4, %ebx
    jbe spawn_next

    /* The root yields until every park has ended. */
    call stamp_start
root_spin:
    cmpl $0, STOP(%r12)
    jne root_join
    mov $24, %eax               /* sched_yield */
    syscall
    test %eax, %eax
    jnz root_bad_yield
    call elapsed_over
    test %eax, %eax
    jz root_spin
    mov $91, %edi
    jmp die
root_join:
    call stamp_start
join_loop:
    mov (TIDS + 8)(%r12), %eax
    or (TIDS + 12)(%r12), %eax
    or (TIDS + 16)(%r12), %eax
#ifndef LIVE_YIELDER
    or (TIDS + 4)(%r12), %eax
#endif
    jz joined
    mov $24, %eax               /* sched_yield */
    syscall
    test %eax, %eax
    jnz root_bad_yield
    call elapsed_over
    test %eax, %eax
    jz join_loop
    mov $93, %edi
    jmp die
joined:
    mov FAULT(%r12), %edi
    jmp die
root_bad_yield:
    mov $94, %edi
    jmp die

/* Clone worker %ebx on the stack at %rsi:
 * clone(CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|
 * CHILD_CLEARTID, stack, &tid, &tid, 0). The worker keeps %ebx and %r12. */
spawn:
    mov $0x00350f00, %edi
    lea TIDS(%r12,%rbx,4), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker
    ret

worker:
    cmp $3, %ebx
    je opener
    cmp $4, %ebx
    je waiter

/* Workers 1 and 2: yield until `stop`, then exit after the next worker
 * (2 after 4, 1 after 2). */
spinner:
    cmpl $0, STOP(%r12)
    jne spinner_stopped
    mov $24, %eax               /* sched_yield */
    syscall
    test %eax, %eax
    jz spinner
    movl $94, FAULT(%r12)
spinner_stopped:
#ifdef LIVE_YIELDER
    cmp $1, %ebx
    je yield_forever
#endif
    mov $2, %r13d
    cmp $1, %ebx
    je await_exit
    mov $4, %r13d
    jmp await_exit

#ifdef LIVE_YIELDER
/* The root's exit_group ends this thread while it yields. */
yield_forever:
    mov $24, %eax               /* sched_yield */
    syscall
    jmp yield_forever
#endif

/* Worker 3: ROUNDS yields beside the parked waiter, then open the gate. */
opener:
    mov $ROUNDS, %r13d
open_round:
    mov $24, %eax               /* sched_yield */
    syscall
    test %eax, %eax
    jz open_ok
    movl $94, FAULT(%r12)
open_ok:
    dec %r13d
    jnz open_round
    movl $1, GATE(%r12)
    lea GATE(%r12), %rdi
    mov $129, %esi              /* FUTEX_WAKE_PRIVATE */
    mov $1, %edx
    mov $202, %eax
    syscall
    jmp worker_exit

/* Worker 4: park on the gate, then stop the yielders. */
waiter:
    cmpl $0, GATE(%r12)
    jne waiter_woken
    lea GATE(%r12), %rdi
    mov $128, %esi              /* FUTEX_WAIT_PRIVATE on gate == 0 */
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    test %rax, %rax
    jz waiter
    cmp $-11, %rax              /* EAGAIN: the gate opened first */
    je waiter
    cmp $-4, %rax               /* EINTR */
    je waiter
    movl $96, FAULT(%r12)
waiter_woken:
    movl $1, STOP(%r12)
    mov $3, %r13d

/* Exit once worker %r13d has: one raw exit at a time. */
await_exit:
    cmpl $0, TIDS(%r12,%r13,4)
    je worker_exit
    mov $24, %eax               /* sched_yield */
    syscall
    jmp await_exit
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

/* r14 = the TSC now. */
stamp_start:
    rdtsc
    shl $32, %rdx
    or %rdx, %rax
    mov %rax, %r14
    ret

/* eax = 1 once more than BOUND_TICKS passed since the stamp. */
elapsed_over:
    rdtsc
    shl $32, %rdx
    or %rdx, %rax
    sub %r14, %rax
    movabs $BOUND_TICKS, %rcx
    cmp %rcx, %rax
    seta %al
    movzbl %al, %eax
    ret

fail_setup:
    mov $81, %edi
    jmp die
fail_clone:
    neg %eax
    lea 100(%rax), %edi
die:
    mov $231, %eax
    syscall
    ud2
