# Musl's startup dependency: arch_prctl(ARCH_SET_FS, self pointer).
.global _start
.text
_start:
    lea tls(%rip), %rsi
    mov %rsi, (%rsi)
    mov $0x1002, %rdi
    mov $158, %rax
    syscall
    test %rax, %rax
    jne refusal
    mov %fs:0, %rax
    lea tls(%rip), %rsi
    cmp %rax, %rsi
    jne broken
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
ok: .ascii "T\n"
.bss
.balign 16
tls: .skip 16
