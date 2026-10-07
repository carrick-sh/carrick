# Polling the CLI's host-backed stdout must agree with native Linux.
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.equ POLLOUT, 4
.global _start
.text
_start:
    sub $16, %rsp
    movl $1, (%rsp)
    movw $POLLOUT, 4(%rsp)
    movw $0, 6(%rsp)
    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $1, %rsi
    xor %rdx, %rdx
    syscall
    cmp $1, %rax
    jne fail
    testw $POLLOUT, 6(%rsp)
    jz fail
    mov $SYS_write, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "P\n"
