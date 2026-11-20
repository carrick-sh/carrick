/* Production fork, child nanosleep or clock_nanosleep, and parent wait. The
 * exit status reports 8 for a zero return, 218 for -ENOSYS, 91 for any other
 * answer. Parent and child remain live during the call (#1808).
 *   CLOCK_GETRES      root and child clock_getres with a writable result
 *   default            nanosleep({0, 1 ms}, &rem): parks, expires, returns 0
 *   SLEEP_ZERO         nanosleep({0, 0}, &rem): 0 without parking
 *   SLEEP_ABSOLUTE     clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
 *                      {0, 1}, NULL): the deadline has passed, 0 at once
 */
.global _start
.text
_start:
#ifdef CLOCK_GETRES
    call clock_getres
#endif
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
#ifdef CLOCK_GETRES
    call clock_getres
    jmp success
#else
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
#endif
success:
    mov $8, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
#ifdef CLOCK_GETRES
clock_getres:
    sub $16, %rsp
    movq $-1, (%rsp)
    movq $-1, 8(%rsp)
    mov $1, %edi
    mov %rsp, %rsi
    mov $229, %eax
    syscall
    cmp $-38, %rax
    je clock_refused
    test %rax, %rax
    jne failure
    cmpq $0, (%rsp)
    jne failure
    mov 8(%rsp), %rax
    dec %rax
    cmp $999999998, %rax
    ja failure
    add $16, %rsp
    ret
clock_refused:
    mov $218, %edi
    jmp exit
#endif
.section .note.GNU-stack,"",@progbits
