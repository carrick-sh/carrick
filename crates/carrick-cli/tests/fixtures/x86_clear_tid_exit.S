# cpl0 exit custody: this requires production thread exit and futex wake.
.global _start
.text
_start:
    mov $56, %rax
    mov $0x10f00, %rdi
    lea child_stack_end(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    syscall
    test %rax, %rax
    js fail
    jz child
    lea word(%rip), %rdi
    xor %rsi, %rsi
    mov $1, %rdx
    lea deadline(%rip), %r10
    mov $202, %rax
    syscall
    cmpl $0, word(%rip)
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp finish
child:
    lea word(%rip), %rdi
    mov $218, %rax
    syscall
    test %rax, %rax
    jle fail
    xor %rdi, %rdi
    mov $60, %rax
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
deadline: .quad 5, 0
word: .long 1
.section .bss
.balign 16
child_stack: .skip 16384
child_stack_end:
.section .rodata
ok: .ascii "J\n"
.section .note.GNU-stack,"",@progbits
