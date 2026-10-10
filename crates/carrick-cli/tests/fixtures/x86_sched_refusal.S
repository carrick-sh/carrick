# Check explicit ENOSYS return for unported sched_setaffinity syscall.
# Expected stdout: R\n; expected exit: 7.
.global _start
.text
_start:
    xor %rdi, %rdi              # pid = 0 (calling thread)
    mov $8, %rsi                # cpusetsize = 8
    lea mask(%rip), %rdx        # mask ptr
    mov $203, %rax              # sched_setaffinity
    syscall
    cmp $-38, %rax              # ENOSYS
    jne fail

    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2

.data
.balign 8
mask:
    .quad 1                     # CPU 0

.section .rodata
ok: .ascii "R\n"
