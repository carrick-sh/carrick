/* Private file first-touch through the production CPL0 runtime. Stage-specific
 * exit statuses distinguish setup failures from mapping and fault failures. */
.global _start
.text
_start:
#ifndef PREOPENED_FD
    mov $-100, %edi
    lea name(%rip), %rsi
#ifdef EXPECT_ACCESS_FAILURE
    mov $1, %edx
#elif defined(EXPECT_PATH_FAILURE)
    mov $0x200000, %edx
#else
    xor %edx, %edx
#endif
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js setup_failed
    mov %eax, %r12d
#else
    mov $PREOPENED_FD, %r12d
#endif
#ifdef EXPECT_SOURCE_LIMIT
    mov $1024, %r14d
map_again:
#endif
    xor %edi, %edi
#ifdef EXPECT_BUS
    mov $8192, %esi
#else
    mov $4096, %esi
#endif
#ifdef COW_WRITE
    mov $3, %edx
#else
    mov $1, %edx
#endif
    mov $2, %r10d
    mov %r12d, %r8d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
#ifdef EXPECT_ACCESS_FAILURE
    cmp $-13, %rax
    jne bytes_failed
    xor %edi, %edi
    jmp exit
#endif
#ifdef EXPECT_PATH_FAILURE
    cmp $-9, %rax
    jne bytes_failed
    xor %edi, %edi
    jmp exit
#endif
#ifdef EXPECT_SOURCE_LIMIT
    cmp $-1, %r14d
    je source_recovered
    test %r14d, %r14d
    jz source_limit
    test %rax, %rax
    js map_failed
    mov %rax, %r15
    dec %r14d
    jmp map_again
source_limit:
#ifdef NATIVE_SOURCE_LIMIT_CONTROL
    test %rax, %rax
    js bytes_failed
#else
    cmp $-12, %rax
    jne bytes_failed
#endif
    mov %r15, %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    jnz unmap_failed
    mov $-1, %r14d
    jmp map_again
source_recovered:
#endif
    test %rax, %rax
    js map_failed
    mov %rax, %r13
#ifdef CHILD_FIRST_TOUCH
    xor %edi, %edi
    lea signal_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    jnz signal_failed
    mov $57, %eax
    syscall
    test %rax, %rax
    js fork_failed
    jz child
    mov %eax, %r14d
    mov %r13, %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    jnz unmap_failed
    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz parent_close_failed
    mov %r14d, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jnz signal_failed
    mov %r14d, %edi
    lea child_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14, %rax
    jne bytes_failed
    cmpl $0, child_status(%rip)
    jne child_status_failed
    xor %edi, %edi
    jmp exit
child:
    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz child_close_failed
    lea signal_mask(%rip), %rdi
    xor %esi, %esi
    lea signal_timeout(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $10, %rax
    jne signal_failed
    mov %r13, %rax
#endif
    cmpb $0x41, (%rax)
    jne bytes_failed
    cmpb $0x5a, 4095(%rax)
    jne bytes_failed
#ifdef EXPECT_BUS
    movb 4096(%rax), %al
    jmp bytes_failed
#endif
#ifdef COW_WRITE
    movb $0x42, (%rax)
    cmpb $0x42, (%rax)
    jne bytes_failed
#ifndef CHILD_FIRST_TOUCH
    mov %r12d, %edi
    lea original(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    mov $17, %eax
    syscall
    cmp $1, %rax
    jne bytes_failed
    cmpb $0x41, original(%rip)
    jne bytes_failed
#endif
#endif
    xor %edi, %edi
    jmp exit
setup_failed:
    mov $31, %ebx
    jmp report_error
signal_failed:
    mov $34, %ebx
    jmp report_error
fork_failed:
    mov $35, %ebx
    jmp report_error
unmap_failed:
    mov $36, %ebx
    jmp report_error
child_close_failed:
    mov $37, %ebx
    jmp report_error
parent_close_failed:
    mov $38, %ebx
    jmp report_error
child_status_failed:
    mov child_status(%rip), %eax
    mov $39, %ebx
    jmp report_error
map_failed:
    mov $32, %ebx
    jmp report_error
bytes_failed:
    mov $33, %edi
    jmp exit
report_error:
    mov %rax, original(%rip)
    mov $1, %edi
    lea original(%rip), %rsi
    mov $8, %edx
    mov $1, %eax
    syscall
    mov %ebx, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
name: .asciz FILE_PATH
.balign 8
signal_mask: .quad 512
signal_timeout: .quad 5, 0
.bss
.balign 4096
original: .skip 4096
child_status: .skip 4
.section .note.GNU-stack,"",@progbits
