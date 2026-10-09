# Poll on an open, empty stdin pipe must not report POLLIN.
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.equ POLLIN, 1
.equ POLLOUT, 4
.global _start
.text
_start:
    sub $16, %rsp
    movl $0, 0(%rsp)
    movw $POLLIN, 4(%rsp)
    movw $0, 6(%rsp)
    movl $1, 8(%rsp)
    movw $POLLOUT, 12(%rsp)
    movw $0, 14(%rsp)
    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $2, %rsi
    xor %rdx, %rdx
    syscall
    cmpw $0, 6(%rsp)
    jne bad_stdin
    cmp $1, %rax
    jne bad_count
    testw $POLLOUT, 14(%rsp)
    jz bad_stdout
    mov $SYS_write, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne bad_write
    mov $7, %rdi
    jmp exit
bad_count:
    mov $91, %rdi
    jmp exit
bad_stdin:
    mov $92, %rdi
    jmp exit
bad_stdout:
    mov $93, %rdi
    jmp exit
bad_write:
    mov $99, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "E\n"
