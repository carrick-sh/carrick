/*
 * The x86 root's CPU-time accounting survives a host crossing. The root
 * never parks (no futex, sleep or getrandom), so the scheduler never switches
 * it in; it polls its standard descriptors (a host crossing, as Rust's std
 * startup does) and then burns CPU in user mode. Raw
 * clock_gettime(CLOCK_PROCESS_CPUTIME_ID) must advance by at least 30 ms
 * before raw CLOCK_MONOTONIC has advanced by 2 s, and times() user + system
 * must advance by at least two 10 ms ticks.
 * Exit values: 8 success, 38 ENOSYS, 91 malformed, 93 CPU time stopped,
 * 94 times() stopped.
 */
.global _start
.text
_start:
    /* poll({0, 1, 2}, 3, 0): the root's standard descriptors cross. */
    lea pollfds(%rip), %rdi
    mov $3, %esi
    xor %edx, %edx
    mov $7, %eax
    syscall
    test %rax, %rax
    js failure
    mov $2, %edi
    call raw_clock
    mov %rax, %r12
    mov $1, %edi
    call raw_clock
    mov %rax, %r13
    call times_cpu
    mov %rax, %r14
burn:
    mov $100000, %ecx
spin:
    dec %ecx
    jnz spin
    mov $2, %edi
    call raw_clock
    sub %r12, %rax
    cmp $30000000, %rax
    jae burned
    mov $1, %edi
    call raw_clock
    sub %r13, %rax
    cmp $2000000000, %rax
    jb burn
    mov $93, %edi
    jmp exit
burned:
    call times_cpu
    sub %r14, %rax
    cmp $2, %rax
    jl times_stopped
    mov $8, %edi
    jmp exit
times_stopped:
    mov $94, %edi
    jmp exit

/* Raw clock_gettime(%edi) in nanoseconds. */
raw_clock:
    lea sample(%rip), %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jne failure
    imul $1000000000, sample(%rip), %rax
    add sample+8(%rip), %rax
    ret

/* Raw times(): tms_utime + tms_stime. */
times_cpu:
    lea tms(%rip), %rdi
    mov $100, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp $-4095, %rax
    jae failure
    mov tms(%rip), %rax
    add tms+8(%rip), %rax
    ret

clock_unserved:
    mov $38, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.data
.balign 8
pollfds:
    .long 0
    .short 0, 0
    .long 1
    .short 0, 0
    .long 2
    .short 0, 0
.bss
.balign 16
sample:
    .skip 16
tms:
    .skip 32
.section .note.GNU-stack,"",@progbits
