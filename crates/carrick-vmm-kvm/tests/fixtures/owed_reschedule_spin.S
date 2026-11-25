/* #2962: write, spin in user space with no host crossing, write, exit 7.
 * The host's reschedule lands at the first write's boundary; the spin is the
 * stretch where only a guest-delivered kick can bring the CPU back. */
.intel_syntax noprefix
.global _start
.section .text
_start:
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + first]
    mov edx, 2
    syscall
    mov rcx, 3000000000
1:
    dec rcx
    jnz 1b
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + second]
    mov edx, 2
    syscall
    mov eax, 60
    mov edi, 7
    syscall
.section .rodata
first:
    .ascii "A\n"
second:
    .ascii "B\n"
.section .note.GNU-stack,"",@progbits
