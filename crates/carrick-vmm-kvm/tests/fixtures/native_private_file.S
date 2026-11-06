/* Private file first-touch through the production CPL0 runtime. Stage-specific
 * exit statuses distinguish setup failures from mapping and fault failures. */
.global _start
.text
_start:
#ifndef PREOPENED_FD
    mov $-100, %edi
    lea name(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js setup_failed
    mov %eax, %r12d
#else
    mov $PREOPENED_FD, %r12d
#endif
    xor %edi, %edi
    mov $4096, %esi
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
    test %rax, %rax
    js map_failed
    mov %rax, %r13
    cmpb $0x41, (%rax)
    jne bytes_failed
    cmpb $0x5a, 4095(%rax)
    jne bytes_failed
#ifdef COW_WRITE
    movb $0x42, (%rax)
    cmpb $0x42, (%rax)
    jne bytes_failed
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
    xor %edi, %edi
    jmp exit
setup_failed:
    mov $31, %ebx
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
.bss
.balign 4096
original: .skip 4096
.section .note.GNU-stack,"",@progbits
