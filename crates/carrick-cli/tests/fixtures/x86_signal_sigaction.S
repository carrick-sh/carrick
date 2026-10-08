# Native startup signal dependency; exact field/errno checks.

.macro CHECK value=0
    cmp $\value, %rax
    jne refusal
.endm
.global _start
.text
_start:

    mov $13, %rax
    mov $13, %rdi
    lea ignore(%rip), %rsi
    lea old(%rip), %rdx
    mov $8, %r10
    syscall
    CHECK
    mov $13, %rdi
    xor %rsi, %rsi
    mov $13, %rax
    syscall
    CHECK
    cmpq $1, old(%rip)
    jne refusal
    mov $11, %rdi
    lea caught(%rip), %rsi
    mov $13, %rax
    syscall
    CHECK
    xor %rsi, %rsi
    mov $13, %rax
    syscall
    CHECK
    lea handler(%rip), %rax
    cmp %rax, old(%rip)
    jne refusal
    cmpq $0x0c000004, old+8(%rip)
    jne refusal
    lea restorer(%rip), %rax
    cmp %rax, old+16(%rip)
    jne refusal
    mov $7, %rdi
    lea caught(%rip), %rsi
    mov $13, %rax
    syscall
    CHECK
    mov $9, %rdi
    mov $13, %rax
    syscall
    CHECK -22

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
old: .zero 32
ignore: .quad 1, 0, 0, 0
caught: .quad handler, 0x0c000004, restorer, 0x1000
mask: .quad 0x4010100
stack: .quad stackmem, 0, 8192
.bss
.balign 16
stackmem: .skip 8192
.text
handler: ret
restorer: mov $15, %rax; syscall; ud2
