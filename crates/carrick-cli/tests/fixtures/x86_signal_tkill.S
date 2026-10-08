
.macro CHECK value=0
    cmp $\value, %rax
    jne refusal
.endm
.global _start
.text
_start:

    mov $39, %rax
    syscall
    mov %rax, %r12
    mov $186, %rax
    syscall
    mov %rax, %r13
    mov %r13, %rdi
    mov $0, %rsi
    mov $200, %rax
    syscall
    CHECK
    mov %r13, %rdi
    mov $65, %rsi
    mov $200, %rax
    syscall
    CHECK -22
    mov %r13, %rdi
    mov $0, %rsi
    mov $2147483647, %rdi
    mov $200, %rax
    syscall
    CHECK -3
    mov $13, %rax
    mov $13, %rdi
    lea ignore(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    syscall
    CHECK
    mov %r13, %rdi
    mov $13, %rsi
    mov $200, %rax
    syscall
    CHECK

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
ignore: .quad 1,0,0,0
