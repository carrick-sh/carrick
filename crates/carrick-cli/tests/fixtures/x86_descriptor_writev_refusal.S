.equ SYS_dup2, 33
.equ SYS_writev, 20
.equ SYS_exit_group, 231
.global _start
.text
_start:
    mov $SYS_dup2, %rax
    mov $2, %rdi
    mov $1, %rsi
    syscall
    cmp $1, %rax
    jne fail
    mov $SYS_writev, %rax
    mov $1, %rdi
    lea vec(%rip), %rsi
    mov $1, %rdx
    syscall
    # Native writes two bytes; Carrick must refuse this unsupported forward.
    cmp $2, %rax
    je native_done
    cmp $-38, %rax
    jne fail
    mov $8, %rdi
    jmp exit
native_done:
    mov $7, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
err: .ascii "V\n"
.align 8
vec: .quad err, 2
