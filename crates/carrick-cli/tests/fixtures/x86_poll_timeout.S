# A finite poll on open empty stdin returns zero with clear revents.
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.equ POLLIN, 1
.global _start
.text
_start:
    sub $8, %rsp
    movl $0, 0(%rsp)
    movw $POLLIN, 4(%rsp)
    movw $0, 6(%rsp)
    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $1, %rsi
    mov $50, %rdx
    syscall
    test %rax, %rax
    jne fail
    cmpw $0, 6(%rsp)
    jne fail
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
success: .ascii "T\n"
