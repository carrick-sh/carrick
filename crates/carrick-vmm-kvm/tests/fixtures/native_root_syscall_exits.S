/* #2679: the production x86 root makes LOOP_COUNT rounds of two ring-served
 * syscalls, then exits 0. getppid has no user operand; rt_sigprocmask
 * copies the eight-byte old mask out through the guarded CPL0 user copy. Exit 91 on any other
 * answer (218 would be an ENOSYS refusal).
 */
#ifndef LOOP_COUNT
#define LOOP_COUNT 1
#endif
.global _start
.text
_start:
    mov $LOOP_COUNT, %r12d
round:
    mov $110, %eax
    syscall
    test %rax, %rax
    js failure
    xor %edi, %edi
    xor %esi, %esi
    lea buffer(%rip), %rdx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    jnz failure
    dec %r12d
    jnz round
    xor %edi, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.bss
.align 8
buffer:
    .skip 8
