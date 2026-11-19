/* Both live processes independently reserve the same advisory ranges.
 * The child exits with the mmap errno on failure (38 on the original ring).
 */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r13d
    mov $0x10000000, %edi
    call reserve
    mov %rax, %r14
    call writable
    movb $37, (%r14)
    sub $16, %rsp
    mov %rsp, %rsi
    mov %r13d, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne failure
    cmpb $37, (%r14)
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit

child:
    mov $0x10000000, %edi
    call reserve
    mov %rax, %r14
    call writable
    cmpb $0, (%r14)
    jne failure
    movb $51, (%r14)
    cmpb $51, (%r14)
    jne failure
    mov %r14, %rdi
    call release

    /* The next advisory hint collides with the still-live anonymous range. */
    movabs $0x6100000000, %rdi
    call reserve
    mov %rax, %r15
    mov %rax, %rdi
    call reserve
    cmp %rax, %r15
    je failure
    mov %rax, %rdi
    call release
    mov %r15, %rdi
    call release

    movabs $0x1000000000000000, %rdi
    call reserve
    mov %rax, %rdi
    call release
    xor %edi, %edi
    call reserve
    mov %rax, %rdi
    call release
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
failure:
    mov $91, %edi
    jmp exit

reserve:
    mov $0x10000000, %esi
    xor %edx, %edx
    mov $0x4022, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js mmap_errno
    test $4095, %eax
    jnz failure
    ret
mmap_errno:
    neg %eax
    mov %eax, %edi
    jmp exit
writable:
    mov %r14, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $10, %eax
    syscall
    test %eax, %eax
    jnz failure
    ret
release:
    mov $0x10000000, %esi
    mov $11, %eax
    syscall
    test %eax, %eax
    jnz failure
    ret
.section .note.GNU-stack,"",@progbits
