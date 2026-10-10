# libc raise shape: use set_tid_address's return value as tkill's tid.
.global _start
.text
_start:
    lea word(%rip), %rdi
    mov $218, %rax
    syscall
    test %rax, %rax
    jle fail
    mov %rax, %r12
    mov $10, %rdi
    lea action(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    mov $13, %rax
    syscall
    test %rax, %rax
    jne fail
    mov %r12, %rdi
    mov $10, %rsi
    mov $200, %rax
    syscall
    test %rax, %rax
    jne fail
    cmpl $1, delivered(%rip)
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp finish
handler:
    movl $1, delivered(%rip)
    ret
restorer:
    mov $15, %rax
    syscall
    ud2
fail:
    mov $91, %rdi
finish:
    mov $231, %rax
    syscall
    ud2
.data
.balign 8
action: .quad handler, 0x4000000, restorer, 0
word: .long 1234
delivered: .long 0
.section .rodata
ok: .ascii "S\n"
.section .note.GNU-stack,"",@progbits
