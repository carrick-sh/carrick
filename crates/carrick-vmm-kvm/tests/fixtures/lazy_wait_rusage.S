/* A successful wait4 must deliver rusage after reaping, without replaying wait. */
.global _start
.text
_start:
    /* Status is resident; only the post-reap rusage destination is untouched. */
    movl $0, status(%rip)
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
#ifdef BAD_RUSAGE
    mov $1, %r10d
#else
    lea usage(%rip), %r10
#endif
    mov $61, %eax
    syscall
#ifdef BAD_RUSAGE
    /* Linux reports EFAULT after consuming the child for a bad rusage. */
    cmp $-14, %eax
#else
    cmp %r12d, %eax
#endif
    jne failure
    cmpl $(19 << 8), status(%rip)
    jne failure
    /* The child was consumed exactly once, including across output supply. */
    mov %r12d, %edi
    xor %esi, %esi
    mov $1, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp $-10, %eax
    jne failure
    mov $7, %edi
    jmp exit
child:
    mov $19, %edi
    jmp exit
failure:
    mov $92, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.bss
.balign 4096
status: .space 4096
usage: .space 4096
