/* #1756: a non-venue writev must be refused in ring, never host-replayed.
 * Native Linux oracle: build with -DNATIVE_ORACLE; EBADF (9), exit 0.
 * Carrick's strict ring-first contract: counted ENOSYS (38), exit 0.
 */
.global _start
.text
_start:
    mov $20, %eax
    mov $-1, %rdi
    lea vectors(%rip), %rsi
    mov $1, %edx
    syscall
#ifdef NATIVE_ORACLE
    cmp $-9, %rax
#else
    cmp $-38, %rax
#endif
    setne %dil
    movzbl %dil, %edi
    mov $231, %eax
    syscall
    ud2
.section .rodata
payload: .ascii "!"
.balign 8
vectors: .quad payload, 1
