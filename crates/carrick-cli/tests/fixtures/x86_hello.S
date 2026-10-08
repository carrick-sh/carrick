/* CLI process-boundary witness; native Linux executes the same static ELF. */
.intel_syntax noprefix
.global _start
.section .text
_start:
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + message]
    mov edx, 6
    syscall
    mov eax, 60
    mov edi, 7
    syscall
.section .rodata
message:
    .ascii "hello\n"
.section .note.GNU-stack,"",@progbits
