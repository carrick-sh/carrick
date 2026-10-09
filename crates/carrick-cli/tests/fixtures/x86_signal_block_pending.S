# Native x86 Linux oracle for signal blocking, pending set, and unblock delivery.
# Expected stdout: BHU\n; expected exit: 7.
.global _start
.text
_start:
    # 1. Set up struct sigaction for SIGUSR1 (10):
    lea handler(%rip), %rax
    mov %rax, sa_act(%rip)
    movq $0x04000000, sa_act+8(%rip)     # SA_RESTORER
    lea restorer(%rip), %rax
    mov %rax, sa_act+16(%rip)
    movq $0, sa_act+24(%rip)

    # rt_sigaction(SIGUSR1=10, &sa_act, NULL, 8)
    mov $13, %rax         # SYS_rt_sigaction
    mov $10, %rdi         # SIGUSR1
    lea sa_act(%rip), %rsi
    xor %rdx, %rdx        # oldact = NULL
    mov $8, %r10          # sigsetsize = 8
    syscall
    test %rax, %rax
    jnz fail

    # 2. Block SIGUSR1 (bit 9 in sigset_t: 1 << 9 = 0x200):
    movq $0x200, block_mask(%rip)
    # rt_sigprocmask(SIG_BLOCK=0, &block_mask, NULL, 8)
    mov $14, %rax         # SYS_rt_sigprocmask
    xor %rdi, %rdi        # SIG_BLOCK = 0
    lea block_mask(%rip), %rsi
    xor %rdx, %rdx        # oldset = NULL
    mov $8, %r10          # sigsetsize = 8
    syscall
    test %rax, %rax
    jnz fail

    # 3. Raise SIGUSR1 to self: kill(getpid(), SIGUSR1)
    mov $39, %rax         # SYS_getpid
    syscall
    mov %rax, %rdi
    mov $62, %rax         # SYS_kill
    mov $10, %rsi         # SIGUSR1
    syscall
    test %rax, %rax
    jnz fail

    # 4. Check that SIGUSR1 is pending: rt_sigpending(&pending, 8)
    mov $127, %rax        # SYS_rt_sigpending
    lea pending_set(%rip), %rdi
    mov $8, %rsi          # sigsetsize = 8
    syscall
    test %rax, %rax
    jnz fail

    mov pending_set(%rip), %rax
    test $0x200, %rax     # bit 9 must be set
    jz fail

    # 5. Write 'B'
    mov $1, %rax          # SYS_write
    mov $1, %rdi          # stdout
    lea msg_b(%rip), %rsi
    mov $1, %rdx
    syscall

    # 6. Unblock SIGUSR1: rt_sigprocmask(SIG_UNBLOCK=1, &block_mask, NULL, 8)
    # The pending signal will be delivered before rt_sigprocmask returns!
    mov $14, %rax         # SYS_rt_sigprocmask
    mov $1, %rdi          # SIG_UNBLOCK = 1
    lea block_mask(%rip), %rsi
    xor %rdx, %rdx        # oldset = NULL
    mov $8, %r10          # sigsetsize = 8
    syscall
    test %rax, %rax
    jnz fail

    # 7. Write 'U\n'
    mov $1, %rax          # SYS_write
    mov $1, %rdi          # stdout
    lea msg_u(%rip), %rsi
    mov $2, %rdx
    syscall

    mov $7, %rdi
    jmp exit

handler:
    # Handler writes 'H'
    mov $1, %rax          # SYS_write
    mov $1, %rdi          # stdout
    lea msg_h(%rip), %rsi
    mov $1, %rdx
    syscall
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
block_mask:
    .quad 0
pending_set:
    .quad 0

.section .rodata
msg_b:
    .ascii "B"
msg_h:
    .ascii "H"
msg_u:
    .ascii "U\n"
