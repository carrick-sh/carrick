# Same ELF on native Linux and CPL0. Native prints T after a positive tid;
# CPL0 must also return a positive tid; cpl0 exit custody is a separate gap.
.global _start
.text
_start:
    lea clear_tid(%rip), %rdi
    mov $218, %rax
    syscall
    cmp $-38, %rax
    je refused
    test %rax, %rax
    jle failed
    mov %rax, %r12
    mov $186, %rax
    syscall
    cmp %r12, %rax
    jne failed
    lea native_ok(%rip), %rsi
    jmp output
refused:
    lea cpl0_refused(%rip), %rsi
output:
    cmpl $1234, clear_tid(%rip)
    jne failed
    mov $1, %rax
    mov $1, %rdi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
failed:
    mov $91, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.data
.balign 4
clear_tid: .long 1234
.section .rodata
native_ok: .ascii "T\n"
cpl0_refused: .ascii "F\n"
.section .note.GNU-stack,"",@progbits
