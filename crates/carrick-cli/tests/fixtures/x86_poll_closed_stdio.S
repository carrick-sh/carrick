# The guest fd table owns dup2 and close; the host-bound stdout object survives.
.equ SYS_dup2, 33
.equ SYS_close, 3
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.equ POLLOUT, 4
.equ POLLNVAL, 32
.global _start
.text
_start:
    mov $SYS_dup2, %rax
    mov $1, %rdi
    mov $5, %rsi
    syscall
    cmp $5, %rax
    jne fail_dup

    mov $SYS_close, %rax
    mov $1, %rdi
    syscall
    test %rax, %rax
    jne fail_close

    sub $16, %rsp
    movl $5, 0(%rsp)
    movw $POLLOUT, 4(%rsp)
    movw $0, 6(%rsp)
    movl $1, 8(%rsp)
    movw $POLLOUT, 12(%rsp)
    movw $0, 14(%rsp)
    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $2, %rsi
    xor %rdx, %rdx
    syscall
    cmp $2, %rax
    jne fail_poll_count
    testw $POLLOUT, 6(%rsp)
    jz fail_poll_write
    cmpw $POLLNVAL, 14(%rsp)
    jne fail_poll_closed

    mov $SYS_write, %rax
    mov $5, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail_write
    mov $SYS_close, %rax
    mov $5, %rdi
    syscall
    test %rax, %rax
    jne fail_release
    mov $7, %rdi
    jmp exit
fail_dup:
    mov $91, %rdi
    jmp exit
fail_close:
    mov $92, %rdi
    jmp exit
fail_poll_count:
    mov $93, %rdi
    jmp exit
fail_poll_write:
    mov $94, %rdi
    jmp exit
fail_poll_closed:
    mov $95, %rdi
    jmp exit
fail_write:
    mov $96, %rdi
    jmp exit
fail_release:
    mov $97, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "C\n"
