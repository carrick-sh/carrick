/* Child: one RW page touched, made R; a grandchild writes it (SIGSEGV);
 * then the child first-touches a second page. Exit 7 if it survives. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    mov status(%rip), %edi
    shr $8, %edi
    jmp exit
child:
    xor %edi, %edi
    mov $0x2000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov %rax, %r15
    movb $1, (%r15)
    mov %r15, %rdi
    mov $0x1000, %esi
    mov $1, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    jnz bad
    mov $57, %eax
    syscall
    test %eax, %eax
    jnz 1f
    movb $1, (%r15)
    xor %edi, %edi
    mov $231, %eax
    syscall
1:  mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    mov status(%rip), %eax
    and $127, %eax
    cmp $11, %eax
    jne bad
#ifdef TOUCH_AFTER
    movb $1, 0x1000(%r15)
#endif
    mov $7, %edi
    jmp exit
bad:
    mov $92, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .bss
.balign 4
status: .space 4
.section .note.GNU-stack,"",@progbits
