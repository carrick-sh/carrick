# Native x86 Linux oracle for a syscall forwarded from the shared guest.
# Expected stdout: D\n; expected exit: 7.
.global _start
.text
_start:
    mov $39, %rax
    syscall
    test %rax, %rax
    jle fail
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
