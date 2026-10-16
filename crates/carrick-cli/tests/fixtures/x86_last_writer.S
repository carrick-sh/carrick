/* The exiting guest owns the only stdout writer. The host reader must
 * receive its byte and EOF after terminal fd-table retirement. */
.global _start
.text
_start:
    mov $1, %edi
    lea message(%rip), %rsi
    mov $2, %edx
    mov $1, %eax
    syscall
    cmp $2, %eax
    jne failure
    mov $7, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
message: .ascii "E\n"
