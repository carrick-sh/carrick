# Native x86 Linux oracle for signal handler installation, self-raise, and rt_sigreturn.
# Expected stdout: HK\n; expected exit: 7.
.global _start
.text
_start:
    # Set up struct sigaction (32 bytes):
    # handler (8 bytes) = handler
    # flags (8 bytes) = SA_RESTORER (0x04000000)
    # restorer (8 bytes) = restorer
    # mask (8 bytes) = 0
    lea handler(%rip), %rax
    mov %rax, sa_act(%rip)
    movl $0x84000004, sa_act+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, sa_act+16(%rip)
    movq $0, sa_act+24(%rip)

    # rt_sigaction(SIGUSR1=10, &sa_act, NULL, 8)
    mov $13, %rax         # SYS_rt_sigaction on x86_64
    mov $10, %rdi         # SIGUSR1
    lea sa_act(%rip), %rsi
    xor %rdx, %rdx        # oldact = NULL
    mov $8, %r10          # sigsetsize = 8
    syscall
    test %rax, %rax
    jnz fail

    # getpid() -> %rdi
    mov $39, %rax         # SYS_getpid
    syscall
    mov %rax, %rdi

    # kill(pid, SIGUSR1=10)
    mov $62, %rax         # SYS_kill on x86_64
    mov $10, %rsi         # SIGUSR1
    syscall
    cmp $0x12345678, %rax
    jne fail

    # After handler returns and rt_sigreturn resumes here: write 'K\n'
    mov $1, %rax          # SYS_write
    mov $1, %rdi          # stdout
    lea msg_k(%rip), %rsi
    mov $2, %rdx
    syscall

    mov $7, %rdi
    jmp exit

handler:
    # Saved RAX is Linux ucontext offset 40 + 13 * 8.
    movq $0x12345678, 144(%rdx)
    mov $13, %rax
    mov $10, %rdi
    xor %rsi, %rsi
    lea old_action(%rip), %rdx
    mov $8, %r10
    syscall
    test %rax, %rax
    jnz fail
    cmpq $0, old_action(%rip)
    jne fail
    # Handler writes 'H' to stdout
    mov $1, %rax          # SYS_write
    mov $1, %rdi          # stdout
    lea msg_h(%rip), %rsi
    mov $1, %rdx
    syscall
    ret                   # Returns to pretcode (restorer)

restorer:
    mov $15, %rax         # SYS_rt_sigreturn on x86_64
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
old_action:
    .space 32

.section .rodata
msg_h:
    .ascii "H"
msg_k:
    .ascii "K\n"
