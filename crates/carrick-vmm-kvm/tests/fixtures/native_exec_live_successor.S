/* fd 9 signals that the replacement runs; fd 8 keeps the replacement alive
 * until its still-live parent acknowledges it. These are inherited pipe ends. */
.global _start
.text
_start:
    mov $9, %edi
    lea marker(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne failure
    mov $8, %edi
    lea acknowledgement(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %eax
    jne failure
    cmpb $'A', acknowledgement(%rip)
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
marker: .ascii "X"
.section .bss
acknowledgement: .space 1
