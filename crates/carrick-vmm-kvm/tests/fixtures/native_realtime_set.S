/*
 * The container clock is set to TARGET seconds after the carrier published
 * its load-time realtime word. Every ring realtime read must follow the
 * container clock: raw clock_gettime(REALTIME and REALTIME_COARSE),
 * gettimeofday and time, in the x86 root and in a native fork child.
 * Each process then tries clock_settime(CLOCK_REALTIME) one year ahead: an
 * x86 guest is refused with ENOSYS today (#1981) and keeps reading TARGET;
 * a served set must move every later read, including the root's after the
 * child's step. Exit values: 8 success, 38 ENOSYS, 91 malformed, 93 a read
 * returned another wall clock, 100+errno settime refused otherwise.
 */
#define TARGET 4102444800
#define YEAR 31536000
.global _start
.text
_start:
    movabs $TARGET, %r13
    call check_shifted
    call set_realtime
    call check_shifted
    mov $57, %eax
    syscall
    test %rax, %rax
    js failure
    jz child
    mov %eax, %r12d
    sub $16, %rsp
    mov %r12d, %edi
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    cmp $8, %edi
    jne exit
    /* The child's step is the container's clock, not a per-process one. */
    mov %r14, %r13
    call check_shifted
    mov $8, %edi
    jmp exit
child:
    call check_shifted
    call set_realtime
    call check_shifted
    mov $8, %edi
    jmp exit

/* clock_settime(CLOCK_REALTIME, {r13 + YEAR, 0}); r13 and r14 follow a set. */
set_realtime:
    lea YEAR(%r13), %rax
    mov %rax, %r14
    mov %rax, sample(%rip)
    movq $0, sample+8(%rip)
    xor %edi, %edi
    lea sample(%rip), %rsi
    mov $227, %eax
    syscall
    cmp $-38, %rax
    je settime_unserved
    test %rax, %rax
    jnz settime_refused
    mov %r14, %r13
    ret
settime_unserved:
    mov %r13, %r14
    ret

/* Every realtime read must land in [r13, r13 + 60] seconds. */
check_shifted:
    xor %edi, %edi
    lea sample(%rip), %rsi
    call raw_realtime
    mov sample(%rip), %rax
    call check_seconds
    mov $5, %edi
    lea sample(%rip), %rsi
    call raw_realtime
    mov sample(%rip), %rax
    call check_seconds
    lea sample(%rip), %rdi
    xor %esi, %esi
    mov $96, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jne failure
    cmpq $999999, sample+8(%rip)
    ja failure
    mov sample(%rip), %rax
    call check_seconds
    xor %edi, %edi
    mov $201, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    call check_seconds
    ret

check_seconds:
    cmp %r13, %rax
    jb stale
    sub %r13, %rax
    cmp $60, %rax
    ja stale
    ret

raw_realtime:
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jne failure
    cmpq $999999999, sample+8(%rip)
    ja failure
    ret

settime_refused:
    neg %eax
    lea 100(%rax), %edi
    jmp exit
stale:
    mov $93, %edi
    jmp exit
clock_unserved:
    mov $38, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.bss
.balign 16
sample:
    .skip 16
.section .note.GNU-stack,"",@progbits
