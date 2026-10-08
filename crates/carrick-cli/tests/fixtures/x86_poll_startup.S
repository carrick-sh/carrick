# Musl startup dependency: poll an inherited standard descriptor with timeout zero.
.global _start
.text
_start:
    lea pfd(%rip), %rdi
    mov $1, %rsi
    xor %rdx, %rdx
    mov $7, %rax
    syscall
    test %rax, %rax
    js refusal
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
broken:
    mov $96, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "P\n"
.data
.balign 8
pfd: .long 1
     .short 0
     .short 0
