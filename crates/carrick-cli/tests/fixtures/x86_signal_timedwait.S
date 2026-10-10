# Native x86 Linux oracle for rt_sigtimedwait with pending signal and with timeout.
# Expected stdout: PT\n; expected exit: 7.
.global _start
.text
_start:
    # 1. Block SIGUSR1 (10) and SIGUSR2 (12):
    # bit 9: 1 << 9 = 0x200 (SIGUSR1)
    # bit 11: 1 << 11 = 0x800 (SIGUSR2)
    # mask = 0xa00
    movq $0xa00, mask(%rip)
    mov $14, %rax         # SYS_rt_sigprocmask
    xor %rdi, %rdi        # SIG_BLOCK = 0
    lea mask(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    syscall
    test %rax, %rax
    jnz fail

    # 2. Raise SIGUSR1 to self
    mov $39, %rax         # SYS_getpid
    syscall
    mov %rax, %rdi
    mov $62, %rax         # SYS_kill
    mov $10, %rsi         # SIGUSR1
    syscall
    test %rax, %rax
    jnz fail

    # 3. rt_sigtimedwait with pending SIGUSR1:
    # set = 0x200 (SIGUSR1)
    movq $0x200, wait_set(%rip)
    mov $128, %rax        # SYS_rt_sigtimedwait on x86_64
    lea wait_set(%rip), %rdi
    xor %rsi, %rsi        # info = NULL
    xor %rdx, %rdx        # timeout = NULL
    mov $8, %r10          # sigsetsize = 8
    syscall
    cmp $10, %rax         # must return 10 (SIGUSR1)
    jne fail

    # Write 'P'
    mov $1, %rax
    mov $1, %rdi
    lea msg_p(%rip), %rsi
    mov $1, %rdx
    syscall

    # 4. rt_sigtimedwait with timeout (10ms) on SIGUSR2 (not pending)
    # set = 0x800 (SIGUSR2)
    movq $0x800, wait_set(%rip)
    # timeout: 0 sec, 10_000_000 ns (10ms)
    movq $0, timeout(%rip)
    movq $10000000, timeout+8(%rip)
    mov $128, %rax        # SYS_rt_sigtimedwait on x86_64
    lea wait_set(%rip), %rdi
    xor %rsi, %rsi        # info = NULL
    lea timeout(%rip), %rdx
    mov $8, %r10          # sigsetsize = 8
    syscall
    cmp $-11, %rax        # -EAGAIN = -11
    jne fail

    # Write 'T\n'
    mov $1, %rax
    mov $1, %rdi
    lea msg_t(%rip), %rsi
    mov $2, %rdx
    syscall

    mov $7, %rdi
    jmp exit

fail:
    mov $99, %rdi
exit:
    mov $231, %rax        # SYS_exit_group
    syscall
    ud2

.section .data
.align 8
mask:
    .quad 0
wait_set:
    .quad 0
timeout:
    .quad 0, 0

.section .rodata
msg_p:
    .ascii "P"
msg_t:
    .ascii "T\n"
