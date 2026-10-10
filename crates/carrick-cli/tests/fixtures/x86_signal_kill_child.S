# Native x86 Linux oracle for killing a child process with SIGTERM and wait4 reporting status.
# Expected stdout: W\n; expected exit: 7.
.global _start
.text
_start:
    mov $57, %rax         # SYS_fork
    syscall
    test %rax, %rax
    js fail
    jz child

    mov %rax, %r14        # child pid
    # kill(child_pid, 15)
    mov $62, %rax         # SYS_kill
    mov %r14, %rdi
    mov $15, %rsi         # SIGTERM
    syscall
    test %rax, %rax
    jnz fail

    # wait4(child_pid, &status, 0, NULL)
    mov %r14, %rdi
    sub $16, %rsp
    mov %rsp, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax         # SYS_wait4
    syscall
    cmp %r14, %rax
    jne fail

    # Check that child was terminated by SIGTERM (status & 0x7f == 15)
    mov (%rsp), %eax
    and $0x7f, %eax
    cmp $15, %eax
    jne fail

    # Write 'W\n'
    mov $1, %rax
    mov $1, %rdi
    lea msg_w(%rip), %rsi
    mov $2, %rdx
    syscall

    mov $7, %rdi
    jmp exit

child:
    mov $130, %rax        # SYS_rt_sigsuspend on x86_64
    lea zero_mask(%rip), %rdi
    mov $8, %rsi
    syscall
    pause
    jmp child

fail:
    mov $99, %rdi
exit:
    mov $231, %rax        # SYS_exit_group
    syscall
    ud2

.section .rodata
msg_w:
    .ascii "W\n"
zero_mask:
    .quad 0
