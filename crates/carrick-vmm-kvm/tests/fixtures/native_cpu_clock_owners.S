/* #2028: clock_gettime(2) clocks keep one epoch across a fork, and a CPU
 * clock reads the task it names (clock_getcpuclockid(3),
 * pthread_getcpuclockid(3)), sampled as it asks. Native Linux 6.12 answers
 * every check here; the test runs this binary natively first as the oracle.
 *
 * 1. Two live threads. A worker burns >= 100 ms of its own thread CPU and
 *    parks. The root thread, parked meanwhile, reads the live sibling's
 *    thread clock (SCHED and VIRT), its own thread clock (static, and by its
 *    own tid), and the process clock (which includes the sibling); the
 *    sibling's tid names no process (EINVAL). The worker then leaves by raw
 *    exit. (Its cleared tid word does not prove its clock is gone: Linux
 *    clears it before the thread is released.)
 * 2. Two live processes. The root samples MONOTONIC and BOOTTIME (T0), then
 *    forks. The child samples them (T1 >= T0), burns >= 400 ms of its own
 *    process CPU, reads its parent's process clock (under half its own: the
 *    root was parked but for its worker's 100 ms), is refused the parent's
 *    thread clock (EINVAL: not its thread group), reads its own VIRT clock by
 *    pid 0, reports T1 and its CPU time through a pipe, and blocks. The root,
 *    idle until then, samples again (T2 >= T1), reads the live child's
 *    process clock (at least what it reported, while its own stays under
 *    half), its VIRT clock, and is refused its thread clock. It releases the
 *    child, observes the zombie with waitid(WNOWAIT) and still reads its
 *    final CPU time, reaps it, and then its pid, like a pid that never
 *    existed, is EINVAL (even with a null output).
 *
 * Exit 8: every check passed. 38 (root) or 138 (child): a counted ENOSYS.
 * Otherwise the failing check: 40..89 in the root, 150..156 in the child.
 * 91: setup failed.
 */
.global _start
.text
_start:
    xor %r15d, %r15d
    mov $40, %r14d
    /* 0x4000 bytes of private scratch; the worker stack tops at 0x2000. */
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_failed
    mov %rax, %r12
    /* Fault the scratch in first: an x86 root clone whose PARENT_SETTID
     * word sits on an untouched anonymous page is a counted ENOSYS today
     * (#2997), which is not this witness's subject. */
    movl $0, 0x000(%r12)
    movl $0, 0x1000(%r12)
    movl $0, 0x2000(%r12)
    movl $0, 0x3000(%r12)
    /* 1. A worker thread (CLONE_VM | FS | FILES | SIGHAND | THREAD | SYSVSEM
     * | PARENT_SETTID | CHILD_CLEARTID); its tid lands at 0x3000. */
    mov $80, %r14d
    mov $0x00350f00, %edi
    lea 0x2000(%r12), %rsi
    lea 0x3000(%r12), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    cmp $-38, %rax
    je refused
    test %rax, %rax
    js wrong
    jz worker
1:
    cmpl $0, 0x3008(%r12)
    jne 2f
    lea 0x3008(%r12), %rdi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp 1b
2:
    mov 0x3000(%r12), %ebx
    /* The live sibling's thread clock. */
    mov $81, %r14d
    mov %ebx, %edi
    mov $6, %esi
    call dynamic_id
    call clock_ns
    cmp $100000000, %rax
    jb wrong
    mov %rax, %r13
    mov $82, %r14d
    mov %ebx, %edi
    mov $5, %esi
    call dynamic_id
    call clock_ns
    call user_share
    /* The root thread was parked: its own clock is under half. */
    mov $83, %r14d
    mov $3, %edi
    call clock_ns
    shl $1, %rax
    cmp %r13, %rax
    jae wrong
    /* So is its thread clock by its own tid (the leader's, its pid). */
    mov $84, %r14d
    mov $39, %eax
    syscall
    mov %eax, %edi
    mov $6, %esi
    call dynamic_id
    call clock_ns
    shl $1, %rax
    cmp %r13, %rax
    jae wrong
    /* The process clock includes the sibling. */
    mov $85, %r14d
    mov $2, %edi
    call clock_ns
    cmp %r13, %rax
    jb wrong
    /* A non-leader tid names no process. */
    mov $86, %r14d
    mov %ebx, %edi
    mov $2, %esi
    call dynamic_id
    lea 0x300(%r12), %rsi
    mov $-22, %rdx
    call expect_errno
    /* Release the worker; it exits with raw exit, clearing its tid. */
    movl $1, 0x3010(%r12)
    lea 0x3010(%r12), %rdi
    mov $1, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
8:
    mov 0x3000(%r12), %edx
    test %edx, %edx
    jz 9f
    lea 0x3000(%r12), %rdi
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp 8b
9:
    /* 2. Two live processes. */
    /* Pipe A (child to root) at 0x100, pipe B (root to child) at 0x108. */
    lea 0x100(%r12), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz setup_failed
    lea 0x108(%r12), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz setup_failed
    /* T0, before the fork. */
    mov $1, %edi
    call clock_ns
    mov %rax, 0x200(%r12)
    mov $7, %edi
    call clock_ns
    mov %rax, 0x208(%r12)
    mov $57, %eax
    syscall
    test %rax, %rax
    js setup_failed
    jz child
    mov %eax, %ebx
    mov 0x104(%r12), %edi
    mov $3, %eax
    syscall
    mov 0x108(%r12), %edi
    mov $3, %eax
    syscall

    /* The child's report: T1 (MONOTONIC, BOOTTIME) and its CPU time. */
    mov $60, %r14d
    mov 0x100(%r12), %edi
    lea 0x220(%r12), %rsi
    mov $24, %edx
    xor %eax, %eax
    syscall
    cmp $-38, %rax
    je refused
    cmp $24, %rax
    jne child_failed
    /* T2 >= T1 >= T0: one epoch across the fork. */
    mov $61, %r14d
    mov $1, %edi
    call clock_ns
    cmp 0x220(%r12), %rax
    jb wrong
    mov $7, %edi
    call clock_ns
    cmp 0x228(%r12), %rax
    jb wrong
    /* The live child's process clock: at least what it reported. */
    mov $62, %r14d
    mov %ebx, %edi
    mov $2, %esi
    call dynamic_id
    call clock_ns
    cmp 0x230(%r12), %rax
    jb wrong
    mov %rax, %r13
    /* The root was idle: its own process clock is under half the child's. */
    mov $63, %r14d
    mov $2, %edi
    call clock_ns
    shl $1, %rax
    cmp %r13, %rax
    jae wrong
    /* The child's VIRT (user) clock: a busy loop is mostly user time. */
    mov $64, %r14d
    mov %ebx, %edi
    mov $1, %esi
    call dynamic_id
    call clock_ns
    call user_share
    /* The child is not a thread of the root's thread group. */
    mov $65, %r14d
    mov %ebx, %edi
    mov $6, %esi
    call dynamic_id
    lea 0x300(%r12), %rsi
    mov $-22, %rdx
    call expect_errno
    /* Release the child; it exits. */
    mov $66, %r14d
    mov 0x10c(%r12), %edi
    lea 0x240(%r12), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne wrong
    /* waitid(P_PID, child, &info, WEXITED | WNOWAIT): an unreaped zombie. */
    mov $67, %r14d
    mov $1, %edi
    mov %ebx, %esi
    lea 0x400(%r12), %rdx
    mov $0x01000004, %r10d
    xor %r8d, %r8d
    mov $247, %eax
    syscall
    cmp $-38, %rax
    je refused
    test %rax, %rax
    jnz wrong
    /* A zombie's process clock reads its final CPU time. */
    mov $68, %r14d
    mov %ebx, %edi
    mov $2, %esi
    call dynamic_id
    call clock_ns
    cmp %r13, %rax
    jb wrong
    /* Reap it. */
    mov $69, %r14d
    call reap_child
    test %edi, %edi
    jnz exit
    /* The reaped pid names no process. */
    mov $70, %r14d
    mov %ebx, %edi
    mov $2, %esi
    call dynamic_id
    lea 0x300(%r12), %rsi
    mov $-22, %rdx
    call expect_errno
    /* Nor does a pid that never existed, checked before a null output. */
    mov $71, %r14d
    mov $0x0fffffff, %edi
    mov $2, %esi
    call dynamic_id
    xor %esi, %esi
    mov $-22, %rdx
    call expect_errno
    mov $8, %edi
    jmp exit

worker:
    mov $87, %r14d
3:
    mov $0x10000, %ecx
4:
    pause
    dec %ecx
    jnz 4b
    mov $3, %edi
    call clock_ns
    cmp $100000000, %rax
    jb 3b
    movl $1, 0x3008(%r12)
    lea 0x3008(%r12), %rdi
    mov $1, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
5:
    cmpl $0, 0x3010(%r12)
    jne 6f
    lea 0x3010(%r12), %rdi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp 5b
6:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

child:
    mov $100, %r15d
    mov 0x100(%r12), %edi
    mov $3, %eax
    syscall
    mov 0x10c(%r12), %edi
    mov $3, %eax
    syscall
    /* T1 after the root's pre-fork T0. */
    mov $50, %r14d
    mov $1, %edi
    call clock_ns
    mov %rax, 0x220(%r12)
    cmp 0x200(%r12), %rax
    jb wrong
    mov $51, %r14d
    mov $7, %edi
    call clock_ns
    mov %rax, 0x228(%r12)
    cmp 0x208(%r12), %rax
    jb wrong
    /* Burn >= 400 ms of the child's own process CPU: well over twice the
     * root's, which includes its exited worker's 100 ms. */
    mov $52, %r14d
6:
    mov $0x10000, %ecx
7:
    pause
    dec %ecx
    jnz 7b
    mov $2, %edi
    call clock_ns
    cmp $400000000, %rax
    jb 6b
    mov %rax, %r13
    /* The idle parent's process clock is the parent's, not the child's. */
    mov $53, %r14d
    mov $110, %eax
    syscall
    mov %eax, %ebx
    mov %eax, %edi
    mov $2, %esi
    call dynamic_id
    call clock_ns
    shl $1, %rax
    cmp %r13, %rax
    jae wrong
    /* The parent is not a thread of the child's thread group. */
    mov $54, %r14d
    mov %ebx, %edi
    mov $6, %esi
    call dynamic_id
    lea 0x300(%r12), %rsi
    mov $-22, %rdx
    call expect_errno
    /* The child's own VIRT clock, by pid 0. */
    mov $55, %r14d
    xor %edi, %edi
    mov $1, %esi
    call dynamic_id
    call clock_ns
    call user_share
    mov $2, %edi
    call clock_ns
    mov %rax, 0x230(%r12)
    /* Report, then wait for the root's reads. */
    mov $56, %r14d
    mov 0x104(%r12), %edi
    lea 0x220(%r12), %rsi
    mov $24, %edx
    mov $1, %eax
    syscall
    cmp $24, %rax
    jne wrong
    mov 0x108(%r12), %edi
    lea 0x240(%r12), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne wrong
    xor %edi, %edi
    jmp exit

/* The child failed before its report: exit with its code. */
child_failed:
    call reap_child
    test %edi, %edi
    jnz exit
    jmp wrong

/* wait4(child %ebx): %edi is its exit code; a signal or a lost child is
 * check %r14. */
reap_child:
    mov %ebx, %edi
    lea 0x000(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %ebx, %eax
    jne wrong
    mov 0x000(%r12), %edi
    test $127, %edi
    jnz wrong
    shr $8, %edi
    ret

/* A user-time-only (VIRT) reading %rax against its total %r13: a busy loop
 * is mostly user time. Allow a tick of sampling skew above, and a quarter
 * below. */
user_share:
    lea 20000000(%r13), %rcx
    cmp %rcx, %rax
    ja wrong
    shl $2, %rax
    cmp %r13, %rax
    jb wrong
    ret

/* ~pid << 3 | bits, as clock_getcpuclockid(3) builds it: %edi pid, %esi bits. */
dynamic_id:
    not %edi
    shl $3, %edi
    or %esi, %edi
    ret

/* clock_gettime(%edi) in nanoseconds; it must succeed with a valid timespec. */
clock_ns:
    sub $24, %rsp
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je refused
    test %rax, %rax
    jnz wrong
    mov 8(%rsp), %rax
    cmp $999999999, %rax
    ja wrong
    imul $1000000000, (%rsp), %rcx
    add %rcx, %rax
    add $24, %rsp
    ret

/* clock_gettime(%edi, %rsi) must return %rdx. */
expect_errno:
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je refused
    cmp %rdx, %rax
    jne wrong
    ret

setup_failed:
    mov $91, %edi
    jmp exit
refused:
    mov $38, %edi
    add %r15d, %edi
    jmp exit
wrong:
    mov %r14d, %edi
    add %r15d, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
