/* Only the successfully installed successor can emit this marker. */
.global _start
.text
_start:
    mov $1, %eax
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $marker_end-marker, %edx
    syscall
    cmp $marker_end-marker, %rax
    jne failure
    xor %edi, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
marker: .ascii "root-exec-ok\n"
marker_end:
