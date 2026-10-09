# Native x86 Linux oracle for SIGSEGV signal handler on deliberate fault.
# Expected stdout: SC\n; expected exit: 7.
.global _start
.text
_start:
    # 1. Set up struct sigaction for SIGSEGV (11):
    # SA_RESTORER (0x04000000) | SA_SIGINFO (0x00000004) = 0x04000004
    lea handler(%rip), %rax
    mov %rax, sa_act(%rip)
    movq $0x04000004, sa_act+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, sa_act+16(%rip)
    movq $0, sa_act+24(%rip)

    # rt_sigaction(SIGSEGV=11, &sa_act, NULL, 8)
    mov $13, %rax         # SYS_rt_sigaction
    mov $11, %rdi         # SIGSEGV
    lea sa_act(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    syscall
    test %rax, %rax
    jnz fail

    # 2. Deliberate fault: dereference NULL pointer
    xor %rax, %rax
fault_insn:
    movb (%rax), %bl
resume_point:
    # 3. Write 'C\n'
    mov $1, %rax
    mov $1, %rdi
    lea msg_c(%rip), %rsi
    mov $2, %rdx
    syscall

    mov $7, %rdi
    jmp exit

handler:
    # %rdi = signum (11), %rsi = &siginfo, %rdx = &ucontext
    # Write 'S'
    push %rdx
    mov $1, %rax
    mov $1, %rdi
    lea msg_s(%rip), %rsi
    mov $1, %rdx
    syscall
    pop %rdx

    # In ucontext (%rdx), rip is at offset 168 (40 + 128)
    lea resume_point(%rip), %rax
    mov %rax, 168(%rdx)
    ret

restorer:
    mov $15, %rax         # SYS_rt_sigreturn
    syscall
    ud2

fail:
    mov $99, %rdi
exit:
    mov $231, %rax        # SYS_exit_group
    syscall
    ud2

.section .data
.align 8
sa_act:
    .space 32

.section .rodata
msg_s:
    .ascii "S"
msg_c:
    .ascii "C\n"
