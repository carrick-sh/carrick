# Native x86 Linux oracle: a bad user pointer must return EFAULT, then
# the same task must still write and exit normally.
.global _start
.text
_start:
    mov $1, %rax
    mov $1, %rdi
    mov $-1, %rsi
    mov $1, %rdx
    syscall
    cmp $-14, %rax
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
ok: .ascii "E\n"
