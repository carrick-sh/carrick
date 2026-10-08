# Native startup signal dependency; exact field/errno checks.

.macro CHECK value=0
    cmp $\value, %rax
    jne refusal
.endm
.global _start
.text
_start:

    mov $14, %rax
    mov $2, %rdi
    lea mask(%rip), %rsi
    lea old(%rip), %rdx
    mov $8, %r10
    syscall
    CHECK
    xor %rsi, %rsi
    mov $14, %rax
    syscall
    CHECK
    mov $0x1000, %rax
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
old: .zero 32
ignore: .quad 1, 0, 0, 0
caught: .quad handler, 0x0c000004, restorer, 0x1000
mask: .quad 0x41100
stack: .quad stackmem, 0, 8192
.bss
.balign 16
stackmem: .skip 8192
.text
handler: ret
restorer: mov $15, %rax; syscall; ud2
