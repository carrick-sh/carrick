# A live CPL0 retirement must remove this data page from the user root.
.global _start
.text
_start:
    lea target_page(%rip), %rdi
    mov $4096, %rsi
    mov $11, %rax
    syscall
    test %rax, %rax
    jne refused
    movb (%rdi), %al
refused:
    mov $99, %rdi
    mov $231, %rax
    syscall
    ud2
.data
.balign 4096
target_page: .space 4096
