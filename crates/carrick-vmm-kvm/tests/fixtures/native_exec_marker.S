.global _start
.text
_start:
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $2, %edx
    mov $1, %eax
    syscall
    cmp $2, %eax
    jne failure
    xor %edi, %edi
    jmp exit
failure:
    mov $92, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
marker: .ascii "X\n"
