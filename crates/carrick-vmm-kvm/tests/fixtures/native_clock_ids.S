/* #2028: a root and its native fork child, both live, read every Linux clock
 * id through the raw clock_gettime syscall (228), as a libc does for a clock
 * the vDSO does not serve (libuv's CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME).
 * Each answer must be the one native Linux gives (a native 6.12 probe):
 * - COARSE monotonic, BOOTTIME and BOOTTIME_ALARM lie between two raw
 *   CLOCK_MONOTONIC samples (COARSE may trail its base by a tick);
 * - TAI and REALTIME_ALARM lie between two raw CLOCK_REALTIME samples;
 * - the caller's CPU clocks read, by static id and by dynamic id (its own
 *   pid, its own tid, and pid 0);
 * - an unknown id and a posix-clock fd are EINVAL, even with a null output;
 *   a valid clock with a null output is EFAULT.
 * Exit 8: both processes match. Otherwise the failing process (root +0,
 * child +100) exits 38 for a counted ENOSYS, or the number of its check.
 */
.global _start
.text
_start:
    xor %r15d, %r15d
    mov $57, %eax
    syscall
    test %eax, %eax
    js fork_failed
    jz child
    mov %eax, %r12d
    call check_clocks
    sub $16, %rsp
    mov %r12d, %edi
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fork_failed
    mov (%rsp), %edi
    test $127, %edi
    jnz fork_failed
    shr $8, %edi
    jmp exit
child:
    mov $100, %r15d
    call check_clocks
    mov $8, %edi
    jmp exit
fork_failed:
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

/* Every check; %r14 names the one running. */
check_clocks:
    /* Base clock %ebx, tested clock %ebp, slack %r13 nanoseconds. */
    xor %r13d, %r13d
    mov $41, %r14d
    mov $1, %ebx
    mov $7, %ebp
    call sandwich
    mov $42, %r14d
    mov $9, %ebp
    call sandwich
    mov $43, %r14d
    mov $6, %ebp
    /* A COARSE clock may trail its base by up to one tick. */
    mov $10000000, %r13d
    call sandwich
    xor %r13d, %r13d
    mov $44, %r14d
    xor %ebx, %ebx
    mov $11, %ebp
    call sandwich
    mov $45, %r14d
    mov $8, %ebp
    call sandwich

    sub $24, %rsp
    /* The caller's process CPU clock by its own pid: ~pid << 3 | SCHED. */
    mov $46, %r14d
    mov $39, %eax
    syscall
    not %eax
    shl $3, %eax
    or $2, %eax
    mov %eax, %edi
    mov %rsp, %rsi
    call read_valid
    /* Its thread CPU clock by its own tid: ~tid << 3 | PERTHREAD | SCHED. */
    mov $47, %r14d
    mov $186, %eax
    syscall
    not %eax
    shl $3, %eax
    or $6, %eax
    mov %eax, %edi
    mov %rsp, %rsi
    call read_valid
    /* pid 0 names the caller. */
    mov $48, %r14d
    mov $0xfffffffa, %edi
    mov %rsp, %rsi
    call read_valid
    mov $49, %r14d
    mov $2, %edi
    mov %rsp, %rsi
    call read_valid
    mov $50, %r14d
    mov $3, %edi
    mov %rsp, %rsi
    call read_valid

    /* EINVAL before the output: an unknown id, with and without one. */
    mov $51, %r14d
    mov $12, %edi
    mov %rsp, %rsi
    mov $-22, %rdx
    call expect_errno
    mov $52, %r14d
    mov $12, %edi
    xor %esi, %esi
    call expect_errno
    /* A posix-clock fd (~3 << 3 | CLOCKFD): carrick has no clock device. */
    mov $53, %r14d
    mov $0xffffffe3, %edi
    mov %rsp, %rsi
    call expect_errno
    /* EFAULT for a valid clock's null output. */
    mov $54, %r14d
    mov $7, %edi
    xor %esi, %esi
    mov $-14, %rdx
    call expect_errno
    add $24, %rsp
    ret

/* Raw samples base, tested, base: the tested value must lie between them,
 * the lower bound less %r13. */
sandwich:
    sub $56, %rsp
    mov %ebx, %edi
    mov %rsp, %rsi
    call read_valid
    mov %ebp, %edi
    lea 16(%rsp), %rsi
    call read_valid
    mov %ebx, %edi
    lea 32(%rsp), %rsi
    call read_valid
    mov %rsp, %rsi
    call timespec_ns
    mov %rax, %r8
    lea 16(%rsp), %rsi
    call timespec_ns
    mov %rax, %r9
    lea 32(%rsp), %rsi
    call timespec_ns
    cmp %rax, %r9
    ja wrong
    add %r13, %r9
    cmp %r8, %r9
    jb wrong
    add $56, %rsp
    ret

/* clock_gettime(%edi, %rsi) must return 0 with a valid timespec. */
read_valid:
    push %rsi
    mov $228, %eax
    syscall
    pop %rsi
    cmp $-38, %rax
    je refused
    test %rax, %rax
    jne wrong
    call timespec_ns
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

/* The nanoseconds of the timespec at %rsi; its tv_nsec must be in range. */
timespec_ns:
    mov 8(%rsi), %rax
    cmp $999999999, %rax
    ja wrong
    imul $1000000000, (%rsi), %rcx
    add %rcx, %rax
    ret
.section .note.GNU-stack,"",@progbits
