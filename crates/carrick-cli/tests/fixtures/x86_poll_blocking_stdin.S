# A blocking poll must park until stdin receives one byte, then report it once.
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.equ POLLIN, 1
.global _start
.text
_start:
    mov $SYS_write, %rax
    mov $1, %rdi
    lea ready(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail

    sub $8, %rsp
    movl $0, 0(%rsp)
    movw $POLLIN, 4(%rsp)
    movw $0, 6(%rsp)
    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $1, %rsi
    mov $-1, %rdx
    syscall
    cmp $1, %rax
    jne fail
    testw $POLLIN, 6(%rsp)
    jz fail
    mov $SYS_write, %rax
    mov $1, %rdi
    lea success(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail
    mov $7, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
ready: .ascii "R\n"
success: .ascii "P\n"
