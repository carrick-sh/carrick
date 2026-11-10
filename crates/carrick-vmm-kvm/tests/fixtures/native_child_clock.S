/* Production fork, child clock reads, parent wait (#2028). Parent and child
 * stay live during every call. The child exits 8 when each row answers as
 * Linux does, and 40 + n for the first row n that does not (218 is reserved
 * for -ENOSYS, the counted refusal this witness exists to retire):
 *   1  clock_gettime(CLOCK_REALTIME, &ts)    0, tv_sec past 2023
 *   2  clock_gettime(CLOCK_MONOTONIC, &ts)   0, tv_nsec below one second
 *   3  clock_gettime(12, &ts)                -EINVAL
 *   4  clock_gettime(CLOCK_MONOTONIC, NULL)  -EFAULT
 *   5  clock_getres(CLOCK_MONOTONIC, &ts)    0, {0, 1 ms}
 *   6  gettimeofday(&tv, &tz)                0, tv_sec past 2023, tz zeroed
 *   7  gettimeofday(NULL, NULL)              0
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
    sub $64, %rsp
    /* 1 */
    xor %edi, %edi
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je enosys
    test %rax, %rax
    jnz row1
    cmpq $1700000000, (%rsp)
    jl row1
    /* 2 */
    mov $1, %edi
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    test %rax, %rax
    jnz row2
    cmpq $1000000000, 8(%rsp)
    jae row2
    /* 3 */
    mov $12, %edi
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    cmp $-22, %rax
    jne row3
    /* 4 */
    mov $1, %edi
    xor %esi, %esi
    mov $228, %eax
    syscall
    cmp $-14, %rax
    jne row4
    /* 5 */
    movq $-1, (%rsp)
    movq $-1, 8(%rsp)
    mov $1, %edi
    mov %rsp, %rsi
    mov $229, %eax
    syscall
    test %rax, %rax
    jnz row5
    cmpq $0, (%rsp)
    jne row5
    cmpq $1000000, 8(%rsp)
    jne row5
    /* 6 */
    movq $-1, 32(%rsp)
    mov %rsp, %rdi
    lea 32(%rsp), %rsi
    mov $96, %eax
    syscall
    test %rax, %rax
    jnz row6
    cmpq $1700000000, (%rsp)
    jl row6
    cmpq $1000000, 8(%rsp)
    jae row6
    cmpq $0, 32(%rsp)
    jne row6
    /* 7 */
    xor %edi, %edi
    xor %esi, %esi
    mov $96, %eax
    syscall
    test %rax, %rax
    jnz row7
    mov $8, %edi
    jmp exit
row1:
    mov $41, %edi
    jmp exit
row2:
    mov $42, %edi
    jmp exit
row3:
    mov $43, %edi
    jmp exit
row4:
    mov $44, %edi
    jmp exit
row5:
    mov $45, %edi
    jmp exit
row6:
    mov $46, %edi
    jmp exit
row7:
    mov $47, %edi
    jmp exit
enosys:
    mov $218, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
