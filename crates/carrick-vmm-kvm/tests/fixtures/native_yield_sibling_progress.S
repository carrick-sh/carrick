/* #2354: sched_yield lets a runnable sibling on the same CPU run. The root
 * (pinned to CPU 0 by the test) clones two workers, so three threads share
 * two CPUs and at least two of them share one. The three take turns through
 * a shared turn word: thread k (the root is 0) owns every turn t with
 * t % 3 == k, and makes no call but sched_yield until the turn is its own,
 * then passes it on. Whenever the owner of the turn is queued behind a
 * yielder on its CPU, only that yield can hand it the CPU, as Linux does.
 * Every wait for a turn is bounded by BOUND_TICKS of the TSC (the test
 * passes one second's worth; the clock read is RDTSC, not a syscall, so a
 * waiting thread's only call is sched_yield).
 *
 * Exit 0: every turn was taken. 91: the root waited out the bound for its
 * turn; 92: a worker waited out the bound for its turn (it exits 0 with the
 * result in its shared word); 93: a worker's exit was not observed within
 * the bound; 81: mmap failed; 100 + n: clone failed with errno n.
 */
#define THREADS 3
#define HOPS 64
#ifndef BOUND_TICKS
#define BOUND_TICKS 3000000000
#endif

.global _start
.text
_start:
    /* Shared pages: +0x00 and +0x04 the workers' CLEARTID words, +0x08 u32
     * turn, +0x0c and +0x10 the workers' results; worker 1's stack below
     * +0x2000, worker 2's below +0x3000. */
    xor %edi, %edi
    mov $0x3000, %esi
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
    movl $0, 0x08(%r12)
    movl $0, 0x1000(%r12)
    movl $0, 0x2000(%r12)

    mov $1, %ebx
    lea 0x1ff0(%r12), %rsi
    call spawn
    mov $2, %ebx
    lea 0x2ff0(%r12), %rsi
    call spawn

    xor %ebx, %ebx
    call take_turns
    test %eax, %eax
    jz root_done
    mov $91, %edi
    jmp die
root_done:
    /* Join both workers by their CLEARTID words. */
    call stamp_start
join_loop:
    mov (%r12), %eax
    or 0x04(%r12), %eax
    jz joined
    mov $24, %eax               /* sched_yield */
    syscall
    call elapsed_over
    test %eax, %eax
    jz join_loop
    mov $93, %edi
    jmp die
joined:
    mov 0x0c(%r12), %edi
    or 0x10(%r12), %edi
    jmp die

/* Clone worker %ebx on the stack at %rsi:
 * clone(CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|
 * CHILD_CLEARTID, stack, &tid[k-1], &tid[k-1], 0). The worker keeps %ebx
 * and %r12. */
spawn:
    mov $0x00350f00, %edi
    lea -4(%r12,%rbx,4), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker
    ret

worker:
    call take_turns
    test %eax, %eax
    jz worker_exit
    movl $92, 0x08(%r12,%rbx,4)
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

/* Thread %ebx takes each turn t < THREADS * HOPS with t % THREADS == %ebx.
 * eax = 0 when it took every one, 1 when it waited out the bound. */
take_turns:
    mov %ebx, %r15d
turn_wait:
    call stamp_start
turn_poll:
    cmpl %r15d, 0x08(%r12)
    je turn_take
    mov $24, %eax               /* sched_yield */
    syscall
    call elapsed_over
    test %eax, %eax
    jz turn_poll
    ret
turn_take:
    lea 1(%r15), %eax
    movl %eax, 0x08(%r12)
    add $THREADS, %r15d
    cmp $(THREADS * HOPS), %r15d
    jb turn_wait
    xor %eax, %eax
    ret

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
