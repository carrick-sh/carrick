.global _start
.text
_start:
    mov $1, %eax
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $2, %edx
    syscall
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2
.section .rodata
marker: .ascii "X\n"
.section .bss
.balign 4096
pressure: .space 8192
