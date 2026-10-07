# Native x86 Linux oracle for forwarded arch_prctl TLS segment bases.
# Expected stdout: T\n; expected exit: 7.
.global _start
.text
_start:
    mov $158, %rax
    mov $0x1002, %rdi
    mov $0x12345000, %rsi
    syscall
    test %rax, %rax
    jne fail
    mov $158, %rax
    mov $0x1003, %rdi
    mov %rsp, %rsi
    syscall
    test %rax, %rax
    jne fail
    cmpq $0x12345000, (%rsp)
    jne fail
    mov $158, %rax
    mov $0x1001, %rdi
    mov $0x56789000, %rsi
    syscall
    test %rax, %rax
    jne fail
    mov $158, %rax
    mov $0x1004, %rdi
    mov %rsp, %rsi
    syscall
    test %rax, %rax
    jne fail
    cmpq $0x56789000, (%rsp)
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "T\n"
