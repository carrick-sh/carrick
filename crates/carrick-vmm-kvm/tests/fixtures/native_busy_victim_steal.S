/* #3083 item 2 (#3117) on x86 CPL0, on the production idle scan: an idle
 * scan that meets a busy run-queue lock must be woken by that lock's
 * release, even when the release comes after the scan's final pre-HLT
 * recheck, and its next scan must take the thread it gave up on.
 *
 * The other CPU's next idle pass is stopped at its top, before it looks
 * for work (INJECT_STOP_PEER_SCAN). This CPU clones a worker, which waits
 * in this CPU's run queue: the stopped peer cannot take it, and a worker
 * that runs here first only yields back. Then one syscall
 * (INJECT_HOLD_RUN_QUEUE_ACROSS_PEER_HLT) holds this CPU's run-queue lock,
 * lets the peer go on, and waits, with interrupts masked, until the peer
 * is IdleWfi past its final recheck of the durable wake words, right
 * before `sti; hlt`. Every scan the peer ran meanwhile found the lock
 * busy. The syscall then releases the lock through its production guard,
 * checks that the release owes the peer its pass, sends that pass through
 * the CPU's production venue, lets the peer HLT, and returns only once an
 * idle scan has stolen from this CPU, resending meanwhile an IPI the busy
 * ICR left owed. Past its recheck the peer reads no durable word again, so
 * only the release's vector can wake it. This CPU stays in that syscall,
 * so no slice, rotation or yield here can hand the worker over. A release
 * that owes the scan nothing, or sends it no vector, leaves the peer
 * asleep past the worker, and the bounded child reaches its bound.
 *
 * The witness runs in a forked child (threads live in a native child
 * process); the leader reaps it and exits with its status.
 *
 * Exit 7: the worker ran on the other CPU after the steal. 80: the fork
 * or its reap failed. 81: arming the
 * stop failed; 150 + n: clone failed with errno n; 83: the hold failed; 92: the worker ran
 * on this CPU; 95: the peer's scans never enrolled on the busy lock, so
 * nothing was proven; 96: the release owed the peer no pass.
 */
#define INJECT_CURRENT_CPU                    0xfffffffffffffe26
#define INJECT_PEER_SCAN_HELD                 0xfffffffffffffe2b
#define INJECT_STOP_PEER_SCAN                 0xfffffffffffffe66
#define INJECT_HOLD_RUN_QUEUE_ACROSS_PEER_HLT 0xfffffffffffffe67

.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js fail_fork
    jz witness
    /* wait4(child, &status, 0, NULL), then exit with its exit status. */
    mov %eax, %edi
    sub $16, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %rax, %rax
    js fail_fork
    mov (%rsp), %edi
    test $0x7f, %edi
    jnz fail_fork
    shr $8, %edi
    and $0xff, %edi
    jmp die

witness:
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
    js fail_arm
    mov %rax, %r12
    /* Populate the page holding the worker's tid word before the clone:
     * the ring refuses a clone whose tid word is on an untouched page
     * (#2997), which is not this witness's claim. */
    movl $0, (%r12)

    /* Shared layout in %r12:
     * +0x00: u32 worker tid / CLEARTID word
     * +0x18: i32 worker ran on the other CPU
     * +0x1c: i32 the CPU it ran on
     */
    mov $INJECT_CURRENT_CPU, %rax
    syscall
    mov %eax, %r14d

    mov $INJECT_STOP_PEER_SCAN, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
stop_loop:
    /* The event itself, never a count of polls (#3136): the test's bounded
     * child bounds a peer that never stops. */
    mov $INJECT_PEER_SCAN_HELD, %rax
    syscall
    cmp $1, %rax
    je stopped
    pause
    jmp stop_loop
stopped:

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

    mov $INJECT_HOLD_RUN_QUEUE_ACROSS_PEER_HLT, %rax
    syscall
    cmp $1, %rax
    je fail_not_enrolled
    cmp $2, %rax
    je fail_not_owed
    test %rax, %rax
    jnz fail_hold

ran_loop:
    cmpl $0, 0x18(%r12)
    jne ran
    pause
    jmp ran_loop
ran:
    cmp 0x1c(%r12), %r14d
    je fail_same_cpu
    mov $7, %edi
    jmp die

worker:
    /* Run only on the other CPU: here, yield back to the leader. */
    mov $INJECT_CURRENT_CPU, %rax
    syscall
    cmp %eax, %r14d
    jne worker_peer
    mov $24, %eax
    syscall
    jmp worker
worker_peer:
    mov %eax, 0x1c(%r12)
    movl $1, 0x18(%r12)
    /* A non-last thread's raw exit. */
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fail_fork:
    mov $80, %edi
    jmp die
fail_arm:
    mov $81, %edi
    jmp die
fail_clone:
    neg %eax
    lea 150(%rax), %edi
    jmp die
fail_hold:
    mov $83, %edi
    jmp die
fail_same_cpu:
    mov $92, %edi
    jmp die
fail_not_enrolled:
    mov $95, %edi
    jmp die
fail_not_owed:
    mov $96, %edi
die:
    mov $231, %eax
    syscall
    ud2
