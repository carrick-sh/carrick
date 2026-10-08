# musl raise shape: queue SIGABRT while blocked, then restore the mask.
.global _start
.text
_start:
    mov $14, %rax
    mov $0, %rdi
    lea mask(%rip), %rsi
    lea old(%rip), %rdx
    mov $8, %r10
    syscall
    test %rax, %rax
    jne refusal
    mov $186, %rax
    syscall
    mov %rax, %rdi
    mov $6, %rsi
    mov $200, %rax
    syscall
    test %rax, %rax
    jne refusal
    mov $14, %rax
    mov $2, %rdi
    lea old(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    syscall
refusal:
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
.data
.balign 8
mask: .quad 32
old: .quad 0
