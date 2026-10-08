# Real own-thread SIGABRT: native dies by signal; CLI command reports 134.
.global _start
.text
_start:
    mov $186, %rax
    syscall
    mov %rax, %rdi
    mov $6, %rsi
    mov $200, %rax
    syscall
    # A returned syscall is a failure, including unsupported delivery.
    sub $16, %rsp
    mov %rax, (%rsp)
    mov $1, %rax
    mov $1, %rdi
    mov %rsp, %rsi
    mov $8, %rdx
    syscall
    mov $96, %rdi
    mov $231, %rax
    syscall
    ud2
