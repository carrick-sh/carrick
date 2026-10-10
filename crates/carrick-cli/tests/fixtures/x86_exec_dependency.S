# Native completes self-exec; CPL0 must refuse before installing any image.
.global _start
.text
_start:
    cmpq $2, (%rsp)
    je after
    mov 8(%rsp), %rdi
    mov %rdi, arguments(%rip)
    lea arguments(%rip), %rsi
    xor %rdx, %rdx
    mov $59, %rax
    syscall
    cmp $-38, %rax
    jne fail
    lea refused(%rip), %rsi
    jmp output
after:
    lea completed(%rip), %rsi
output:
    mov $1, %rax
    mov $1, %rdi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp finish
fail:
    mov $91, %rdi
finish:
    mov $231, %rax
    syscall
    ud2
.data
.balign 8
arguments: .quad 0, marker, 0
.section .rodata
marker: .asciz "after"
completed: .ascii "E\n"
refused: .ascii "F\n"
.section .note.GNU-stack,"",@progbits
