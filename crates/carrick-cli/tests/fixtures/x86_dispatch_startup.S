# Native x86 Linux oracle for host-served static-libc startup calls.
# Expected stdout: S\n; expected exit: 7.
.global _start
.text
_start:
    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    mov $7, %rax
    syscall
    test %rax, %rax
    jne fail_poll
    mov $10, %rdi
    xor %rsi, %rsi
    lea -128(%rsp), %rdx
    mov $8, %r10
    mov $13, %rax
    syscall
    test %rax, %rax
    jne fail_sigaction
    xor %rdi, %rdi
    lea -96(%rsp), %rsi
    mov $131, %rax
    syscall
    test %rax, %rax
    jne fail_sigaltstack
    lea -64(%rsp), %rdi
    mov $218, %rax
    syscall
    test %rax, %rax
    jle fail_set_tid
    mov %rsp, %rdi
    and $-4096, %rdi
    mov $4096, %rsi
    mov $3, %rdx
    mov $10, %rax
    syscall
    test %rax, %rax
    jne fail_mprotect
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
fail_poll:
    mov $91, %rdi
    jmp exit
fail_sigaction:
    mov $92, %rdi
    jmp exit
fail_sigaltstack:
    mov $93, %rdi
    jmp exit
fail_set_tid:
    mov $94, %rdi
    jmp exit
fail_mprotect:
    mov $95, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "S\n"
