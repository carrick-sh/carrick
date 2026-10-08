# Rust signal-stack shape: MAP_STACK, guard page, first touch, sigaltstack.
.global _start
.text
_start:
    xor %rdi, %rdi
    mov $12288, %rsi
    mov $3, %rdx
    mov $0x20022, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    test %rax, %rax
    js refusal
    mov %rax, %r12
    mov %rax, %rdi
    mov $4096, %rsi
    xor %rdx, %rdx
    mov $10, %rax
    syscall
    test %rax, %rax
    jne refusal
    lea 4096(%r12), %rax
    movb $0x51, (%rax)
    movb $0xa2, 8191(%rax)
    mov %rax, stack(%rip)
    lea stack(%rip), %rdi
    lea old(%rip), %rsi
    mov $131, %rax
    syscall
    test %rax, %rax
    jne refusal
    xor %rdi, %rdi
    mov $131, %rax
    syscall
    test %rax, %rax
    jne refusal
    mov stack(%rip), %rax
    cmp %rax, old(%rip)
    jne refusal
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
refusal:
    sub $16, %rsp
    mov %rax, (%rsp)
    mov $1, %rax
    mov $1, %rdi
    mov %rsp, %rsi
    mov $8, %rdx
    syscall
    mov $96, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "S\n"
.data
.balign 8
stack: .quad 0,0,8192
old: .zero 24
