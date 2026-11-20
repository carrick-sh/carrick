/* Production fork, child nanosleep or clock_nanosleep, and parent wait. The
 * exit status reports 8 for a zero return, 218 for -ENOSYS, 91 for any other
 * answer. Parent and child remain live during the call (#1808).
 *   CLOCK_GETRES      root and child clock_getres with a writable result
 *   MONOTONIC_GETTIME   root and child monotonic samples, with nibble results
 *   default            nanosleep({0, 1 ms}, &rem): parks, expires, returns 0
 *   SLEEP_ZERO         nanosleep({0, 0}, &rem): 0 without parking
 *   SLEEP_FUTURE_ABSOLUTE: sleep until a deadline sampled by the child
 *                         and check that return does not precede it.
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
#ifdef MONOTONIC_GETTIME
    call clock_gettime
    mov %edi, %r13d
#endif
    mov %r12d, %edi
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
#ifdef MONOTONIC_GETTIME
    // Two independent results, root in the high nibble and child in the low.
    // 0 = valid sample, 1 = ENOSYS, 2 = other syscall error or malformed sample.
    shl $4, %r13d
    or %r13d, %edi
#endif
    jmp exit
child:
#ifdef CLOCK_GETRES
    call clock_getres
    jmp success
#elif defined(MONOTONIC_GETTIME)
    call clock_gettime
    jmp exit
#elif defined(SLEEP_FUTURE_ABSOLUTE)
    sub $32, %rsp
    mov %rsp, %rsi
    call read_monotonic
    cmpq $999999999, 8(%rsp)
    ja failure
    addq $30000000, 8(%rsp)
    cmpq $1000000000, 8(%rsp)
    jb 1f
    subq $1000000000, 8(%rsp)
    incq (%rsp)
1:
    mov $1, %edi
    mov $1, %esi
    mov %rsp, %rdx
    xor %r10d, %r10d
    mov $230, %eax
    syscall
    cmp $-38, %rax
    je sleep_refused
    test %rax, %rax
    jne failure
    lea 16(%rsp), %rsi
    call read_monotonic
    mov 16(%rsp), %rax
    cmp (%rsp), %rax
    ja success
    jb failure
    mov 24(%rsp), %rax
    cmp 8(%rsp), %rax
    jae success
    jmp failure
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
#endif
#ifdef MONOTONIC_GETTIME
clock_gettime:
    sub $16, %rsp
    mov $1, %edi
    movq $-1, (%rsp)
    movq $-1, 8(%rsp)
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je monotonic_refused
    mov $2, %edi
    test %rax, %rax
    jne monotonic_return
    cmpq $0, (%rsp)
    jl monotonic_return
    cmpq $999999999, 8(%rsp)
    ja monotonic_return
    xor %edi, %edi
    jmp monotonic_return
monotonic_refused:
    mov $1, %edi
monotonic_return:
    add $16, %rsp
    ret
#endif
#ifdef CLOCK_GETRES
clock_refused:
    mov $218, %edi
    jmp exit
#endif
#ifdef SLEEP_FUTURE_ABSOLUTE
read_monotonic:
    mov $1, %edi
    mov $228, %eax
    syscall
    test %rax, %rax
    jne failure
    ret
sleep_refused:
    mov $218, %edi
    jmp exit
#endif
.section .note.GNU-stack,"",@progbits
