/* #1714: the run root's stack grows below what the carrier built, as Linux
 * grows the stack VMA up to RLIMIT_STACK (8 MiB). Touch one byte in every
 * page of the next 1 MiB below the entry stack pointer, then exit 0. Past
 * the reservation the same walk is a SIGSEGV on both ISAs. */
.global _start
.text
_start:
    mov %rsp, %rbx
    mov $256, %ecx
1:
    sub $4096, %rsp
    movb $1, (%rsp)
    dec %ecx
    jnz 1b
    mov %rbx, %rsp
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
