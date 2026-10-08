# Native x86 Linux oracle for anonymous memory followed by fork and wait4.
# Expected stdout: F\n; expected exit: 7.
.global _start
.text
_start:
    mov $12, %rax
    xor %rdi, %rdi
    syscall
    mov %rax, %r12
    lea 4096(%r12), %rdi
    mov $12, %rax
    syscall
    cmp %rdi, %rax
    jne fail
    mov %r12, %rdi
    mov $12, %rax
    syscall
    cmp %r12, %rax
    jne fail
    xor %rdi, %rdi
    mov $4096, %rsi
    mov $3, %rdx
    mov $0x22, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $-4095, %rax
    jae fail
    mov %rax, %r13
    movb $0x5a, (%r13)
    cmpb $0x5a, (%r13)
    jne fail
    mov %r13, %rdi
    mov $4096, %rsi
    mov $11, %rax
    syscall
    test %rax, %rax
    jne fail
    mov $57, %rax
    syscall
    test %rax, %rax
    js fail
    jz child
    mov %rax, %r14
    sub $16, %rsp
    mov %r14, %rdi
    mov %rsp, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    cmp %r14, %rax
    jne fail
    cmpl $0x300, (%rsp)
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
child:
    mov $3, %rdi
    mov $60, %rax
    syscall
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "F\n"
