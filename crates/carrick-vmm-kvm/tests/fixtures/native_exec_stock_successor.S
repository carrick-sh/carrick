.global _start
.text
_start:
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2
