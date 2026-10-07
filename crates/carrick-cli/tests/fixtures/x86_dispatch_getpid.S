# Native x86 Linux oracle for one task identity across shared guest calls.
# Expected stdout: D\n; expected exit: 7.
.global _start
.text
_start:
    mov $39, %rax
    syscall
    test %rax, %rax
    jle fail
    mov %rax, %r12
    mov $186, %rax
    syscall
    cmp %r12, %rax
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
ok: .ascii "D\n"
