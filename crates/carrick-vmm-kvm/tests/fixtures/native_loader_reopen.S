/* A loader closes its cache before opening a library. Both opens must use
 * the same ring namespace; a stale host projection must not return EBUSY. */
.global _start
.text
_start:
    mov $3, %r12d
    mov $-1, %r13d
again:
    mov $-100, %edi
    lea name(%rip), %rsi
    mov $0x80000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js open_failed
    cmp $-1, %r13d
    je first_open
    cmp %r13d, %eax
    jne wrong_fd
first_open:
    mov %eax, %r13d
    mov %eax, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne close_failed
    dec %r12d
    jnz again
    xor %edi, %edi
    jmp exit
open_failed:
    neg %eax
    mov %eax, %edi
    jmp exit
wrong_fd:
    mov $43, %edi
    jmp exit
close_failed:
    mov $42, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
name: .asciz FILE_PATH
.section .note.GNU-stack,"",@progbits
