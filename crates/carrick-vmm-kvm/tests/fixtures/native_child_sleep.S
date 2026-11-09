/* Production fork, child nanosleep or clock_nanosleep, and parent wait. The
 * exit status reports 8 for a zero return, 218 for -ENOSYS, 91 for any other
 * answer. Parent and child remain live during the call (#1808).
 *   default            nanosleep({0, 1 ms}, &rem): parks, expires, returns 0
 *   SLEEP_ZERO         nanosleep({0, 0}, &rem): 0 without parking
 *   SLEEP_ABSOLUTE     clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
 *                      {0, 1}, NULL): the deadline has passed, 0 at once
 */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
    mov %eax, %edi
    sub $16, %rsp
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
    jmp exit
child:
    sub $32, %rsp
    movq $0, (%rsp)
#if defined(SLEEP_ZERO)
    movq $0, 8(%rsp)
#elif defined(SLEEP_ABSOLUTE)
    movq $1, 8(%rsp)
#else
    movq $1000000, 8(%rsp)
#endif
#ifdef SLEEP_ABSOLUTE
    mov $1, %edi
    mov $1, %esi
    mov %rsp, %rdx
    xor %r10d, %r10d
    mov $230, %eax
#else
    mov %rsp, %rdi
    lea 16(%rsp), %rsi
    mov $35, %eax
#endif
    syscall
    test %rax, %rax
    je success
    cmp $-38, %rax
    jne failure
    mov $218, %edi
    jmp exit
success:
    mov $8, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
