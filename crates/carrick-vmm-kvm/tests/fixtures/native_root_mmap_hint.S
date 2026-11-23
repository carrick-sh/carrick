/* The run root's free non-fixed hint outside the reservation arena is
 * honoured exactly (mmap(2): a free hint is used as the address). V8 reserves
 * its cage this way (#2706). With ROOT_EXEC the root first execs the
 * successor in place, which then maps the hint as the same root MM owner.
 * With FORKED_CHILD a forked child maps it while its parent waits live.
 * Exit: the mmap errno, 92 when placed elsewhere, 91 at a later step,
 * 100 plus the exec errno when ROOT_EXEC's execve returns, 93 when the
 * parent's wait fails or the child dies by a signal, 94 when fork fails.
 */
#define HINT 0x251774240000
#define LENGTH 0x7f000
.global _start
.text
_start:
#ifdef ROOT_EXEC
    lea successor(%rip), %rdi
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    neg %eax
    add $100, %eax
    mov %eax, %edi
    jmp exit
#endif
#ifdef FORKED_CHILD
    /* A live parent waits while its forked child maps the hint. */
    mov $57, %eax
    syscall
    test %rax, %rax
    js fork_errno
    jz map_hint
    mov %rax, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %rdi, %rax
    jne parent_failure
    mov status(%rip), %edi
    test $0x7f, %edi
    jnz parent_failure
    shr $8, %edi
    and $0xff, %edi
    jmp exit
parent_failure:
    mov $93, %edi
    jmp exit
fork_errno:
    mov $94, %edi
    jmp exit
map_hint:
#endif
    movabs $HINT, %rdi
    mov $LENGTH, %esi
    xor %edx, %edx
    mov $0x4022, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js mmap_errno
    movabs $HINT, %rcx
    cmp %rcx, %rax
    jne elsewhere
    mov %rax, %r14
    /* The exact reservation is ordinary anonymous memory. */
    mov %r14, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $10, %eax
    syscall
    test %eax, %eax
    jnz failure
    cmpb $0, (%r14)
    jne failure
    movb $51, (%r14)
    cmpb $51, (%r14)
    jne failure
    mov %r14, %rdi
    mov $LENGTH, %esi
    mov $11, %eax
    syscall
    test %eax, %eax
    jnz failure
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
elsewhere:
    mov $92, %edi
    jmp exit
failure:
    mov $91, %edi
    jmp exit
mmap_errno:
    neg %eax
    mov %eax, %edi
    jmp exit
#ifdef FORKED_CHILD
.bss
.balign 8
status: .quad 0
#endif
#ifdef ROOT_EXEC
.section .rodata
successor: .asciz SUCCESSOR_PATH
.balign 8
argv: .quad successor, 0
#endif
.section .note.GNU-stack,"",@progbits
