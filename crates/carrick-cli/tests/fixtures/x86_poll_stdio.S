# Polling the CLI's host-backed stdout and standard descriptors must agree with native Linux.
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.equ POLLIN, 1
.equ POLLOUT, 4
.equ POLLNVAL, 32
.global _start
.text
_start:
    sub $32, %rsp

    # entry 0: stdout (fd 1)
    movl $1, 0(%rsp)
    movw $POLLOUT, 4(%rsp)
    movw $0, 6(%rsp)

    # entry 1: negative fd (-1)
    movl $-1, 8(%rsp)
    movw $5, 12(%rsp)
    movw $0, 14(%rsp)

    # entry 2: absent fd (42)
    movl $42, 16(%rsp)
    movw $POLLIN, 20(%rsp)
    movw $0, 22(%rsp)

    # entry 3: duplicate stdout (fd 1)
    movl $1, 24(%rsp)
    movw $POLLOUT, 28(%rsp)
    movw $0, 30(%rsp)

    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $4, %rsi
    xor %rdx, %rdx
    syscall

    # Ready count must be 3 (entry 0, entry 2 POLLNVAL, entry 3)
    cmp $3, %rax
    jne fail

    # entry 0: POLLOUT
    testw $POLLOUT, 6(%rsp)
    jz fail

    # entry 1: ignored (revents == 0)
    cmpw $0, 14(%rsp)
    jne fail

    # entry 2: POLLNVAL
    testw $POLLNVAL, 22(%rsp)
    jz fail

    # entry 3: POLLOUT
    testw $POLLOUT, 30(%rsp)
    jz fail

    # Passed! Write "P\n" to stdout and exit with code 7
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

