    .section .text
    .global _start
_start:
    mov $1, %eax                    # write
    mov $1, %edi                    # stdout
    lea message(%rip), %rsi
    mov $(message_end-message), %edx
    syscall
    cmp $(message_end-message), %rax
    jne write_failed
    mov $7, %edi
    jmp exit
write_failed:
    mov $8, %edi
exit:
    mov $231, %eax                  # exit_group
    syscall
    ud2

    .section .rodata
message:
    .ascii "child ran after exec\n"
message_end:

    .section .note.GNU-stack,"",@progbits
