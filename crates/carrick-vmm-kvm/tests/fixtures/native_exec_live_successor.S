/* Signal masks survive exec. Announce replacement to the still-live parent,
 * then require its acknowledgement before exiting. No handler or IPC binding
 * is needed; both signal waits consume blocked signals through the owner. */
.global _start
.text
_start:
    /* Inspect and write the actual replacement stack, not just sealed RSP. */
    test $15, %rsp
    jnz failure
    cmpq $1, (%rsp)
    jne failure
    mov 8(%rsp), %rax
    test %rax, %rax
    jz failure
    cmpb $'/', (%rax)
    jne failure
    cmpq $0, 16(%rsp)
    jne failure
    cmpq $0, 24(%rsp)
    jne failure
    sub $16, %rsp
    movabs $0x657865632d73746b, %rax
    mov %rax, (%rsp)
    cmp %rax, (%rsp)
    jne failure
    add $16, %rsp
    mov $110, %eax
    syscall
    test %eax, %eax
    jle failure
    mov %eax, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
    lea acknowledgement(%rip), %rdi
    xor %esi, %esi
    lea bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $12, %eax
    jne failure
    xor %edi, %edi
    jmp exit
failure:
    mov $92, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
.balign 8
acknowledgement: .quad (1 << 11)
bound: .quad 5, 0
