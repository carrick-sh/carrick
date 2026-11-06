/* Print argv[1..], one argument per line, to witness shebang argv splicing. */
.global _start
.section .text
_start:
    mov (%rsp), %r12
    lea 16(%rsp), %r13
    dec %r12
next_arg:
    test %r12, %r12
    jz done
    mov (%r13), %rsi
    xor %rdx, %rdx
length:
    cmpb $0, (%rsi,%rdx)
    je print_arg
    inc %rdx
    jmp length
print_arg:
    mov $1, %rax
    mov $1, %rdi
    syscall
    mov $1, %rax
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    syscall
    add $8, %r13
    dec %r12
    jmp next_arg
done:
    mov $60, %rax
    mov $7, %rdi
    syscall
.section .rodata
newline: .byte 10
.section .note.GNU-stack,"",@progbits
