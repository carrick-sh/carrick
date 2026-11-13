/* #2142: the run root replaces itself; returning errno is failure. */
.global _start
.text
_start:
    lea path(%rip), %rdi
    lea argv(%rip), %rsi
    lea envp(%rip), %rdx
    mov $59, %eax
    syscall
    /* Preserve the refusal as the exit status (38 means ENOSYS). */
    neg %eax
    mov %eax, %edi
    mov $231, %eax
    syscall
    ud2
.section .rodata
path: .asciz EXEC_PATH
.balign 8
argv: .quad path, 0
envp: .quad 0
