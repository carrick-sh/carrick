/* Linux man-page ABI only. Untouched anonymous outputs on production CPL0. */
.global _start
.section .text
_start:
    mov $9, %eax
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r12
#ifdef STATX_OUTPUT
    mov $332, %eax
    mov $-100, %rdi
    lea path(%rip), %rsi
    xor %edx, %edx
    mov $0x7ff, %r10d
    mov %r12, %r8
    syscall
    test %rax, %rax
    jne fail
    movzwl 28(%r12), %eax
    and $0xf000, %eax
    cmp $0x4000, %eax
    jne fail
#else
    /* eventfd2(1, EFD_NONBLOCK), then epoll_create1(0). */
    mov $290, %eax
    mov $1, %edi
    mov $0x800, %esi
    syscall
    test %rax, %rax
    js fail
    mov %eax, %r13d
    mov $291, %eax
    xor %edi, %edi
    syscall
    test %rax, %rax
    js fail
    mov %eax, %r14d
    mov $233, %eax
    mov %r14d, %edi
    mov $1, %esi
    mov %r13d, %edx
    lea event(%rip), %r10
    syscall
    test %rax, %rax
    jne fail
    mov $281, %eax
    mov %r14d, %edi
    mov %r12, %rsi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    syscall
    cmp $1, %rax
    jne fail
    cmpl $1, (%r12)
    jne fail
    movabs $0x123456789abcdef, %rax
    cmp %rax, 4(%r12)
    jne fail
#endif
    xor %edi, %edi
    jmp done
fail:
    mov $31, %edi
done:
    mov $231, %eax
    syscall
    ud2
.section .rodata
path: .asciz "/"
event:
    .long 1
    .quad 0x123456789abcdef
.section .note.GNU-stack,"",@progbits
