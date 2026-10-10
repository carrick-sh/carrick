# Native x86 Linux witness showing shmget returns ENOSYS (unrouted, known refusal).
# Expected stdout: U\n; expected exit: 7.
.global _start
.text
_start:
    xor %rdi, %rdi              # key = IPC_PRIVATE (0)
    mov $4096, %rsi             # size = 4096
    mov $0666, %rdx             # shmflg = 0666
    mov $29, %rax               # SYS_shmget
    syscall
    cmp $-38, %rax              # -ENOSYS = -38
    jne fail_enosys

    # Success: write "U\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    mov $231, %rax              # SYS_exit_group
    syscall
    ud2

fail_enosys:
    mov $99, %rdi
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "U\n"
