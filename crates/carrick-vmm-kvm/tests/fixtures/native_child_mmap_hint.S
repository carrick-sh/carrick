/* Both live processes independently reserve the same advisory ranges.
 * The child exits with the mmap errno on failure (38 on the original ring).
 */
.global _start
.text
_start:
#if !defined(EXEC_SUCCESSOR) && !defined(ROOT_ONLY)
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r13d
    mov $0x10000000, %edi
    call reserve
    mov %rax, %r14
    call writable
    movb $37, (%r14)
#if defined(ADVICE) || defined(REMAP)
    push %r14
#endif
    sub $16, %rsp
    mov %rsp, %rsi
    mov %r13d, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne failure
    cmpb $37, (%r14)
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
#if defined(ADVICE) || defined(REMAP)
    test %edi, %edi
    jnz exit
    add $16, %rsp
    pop %r14
    jmp advice
#else
    jmp exit
#endif

child:
#endif
    mov $0x10000000, %edi
    call reserve
    mov %rax, %r14
    mov $5, %edx
    call protect
    call writable
    cmpb $0, (%r14)
    jne failure
    movb $51, (%r14)
    cmpb $51, (%r14)
    jne failure
#if defined(ADVICE) || defined(REMAP)
    jmp advice
#endif
    mov %r14, %rdi
    call release

    movabs $0x200000000, %rdi
    call reserve
    mov %rax, %rdi
    call release

    /* The next advisory hint collides with the still-live anonymous range. */
    movabs $0x6100000000, %rdi
    call reserve
    mov %rax, %r15
    mov %rax, %rdi
    call reserve
    cmp %rax, %r15
    je failure
    mov %rax, %rdi
    call release
    mov %r15, %rdi
    call release

    movabs $0x1000000000000000, %rdi
    call reserve
    mov %rax, %rdi
    call release
    xor %edi, %edi
    call reserve
    mov %rax, %rdi
    call release
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
failure:
    mov $91, %edi
    jmp exit

reserve:
    mov $0x10000000, %esi
    xor %edx, %edx
    mov $0x4022, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js mmap_errno
    test $4095, %eax
    jnz failure
    ret
mmap_errno:
    neg %eax
#ifdef EXEC_SUCCESSOR
    add $100, %eax
#endif
    mov %eax, %edi
    jmp exit
writable:
    mov $3, %edx
protect:
    mov %r14, %rdi
    mov $4096, %esi
    mov $10, %eax
    syscall
    test %eax, %eax
    jnz failure
    ret
release:
    mov $0x10000000, %esi
    mov $11, %eax
    syscall
    test %eax, %eax
    jnz failure
    ret
#if defined(ADVICE) || defined(REMAP)
/* Run all steps even on red. r12 keeps the first errno for the test harness. */
.macro report name
    lea .Lname\@(%rip), %rsi
    mov $(.Lend\@ - .Lname\@), %edx
    call report_errno
    .pushsection .rodata
.Lname\@:
    .ascii "\name "
.Lend\@:
    .popsection
.endm

.macro advise name, value, size
    mov %r14, %rdi
    mov $\size, %esi
    mov $\value, %edx
    mov $28, %eax
    syscall
    report \name
.endm

advice:
    xor %r12d, %r12d
    xor %eax, %eax
    report mmap
    report mprotect
#ifdef ADVICE_BUSY
    /* The instrumented image holds the editor until the advice parks. */
    movabs $0xfffffffffffffe11, %rax
    syscall
    test %eax, %eax
    jne failure
#endif
    advise MADV_DONTNEED, 4, 0x10000000
    test %rax, %rax
    js 1f
#ifdef ADVICE_BUSY
    movabs $0xfffffffffffffe13, %rax
    syscall
    cmp $1, %eax
    jne failure
#endif
    cmpb $0, (%r14)
    jne failure
1:
    movb $73, (%r14)
    advise MADV_FREE, 8, 4096
    advise MADV_DONTDUMP, 16, 4096
    advise MADV_HUGEPAGE, 14, 4096
#ifdef REMAP
    mov %r14, %rdi
    mov $4096, %esi
    mov $8192, %edx
    mov $1, %r10d
    mov $25, %eax
    syscall
    report mremap
    test %rax, %rax
    js 2f
    cmpb $73, (%rax)
    jne failure
    cmpb $0, 4096(%rax)
    jne failure
    cmp %r14, %rax
    je 2f
    mov %rax, %rdi
    mov $8192, %esi
    mov $11, %eax
    syscall
    report munmap_moved
2:
#endif
    mov %r14, %rdi
    mov $0x10000000, %esi
    mov $11, %eax
    syscall
    report munmap
    mov %r12d, %edi
    jmp exit

report_errno:
    push %rax
    mov $1, %eax
    mov $1, %edi
    syscall
    mov (%rsp), %rax
    xor %edi, %edi
    test %rax, %rax
    jns 3f
    neg %eax
    mov %eax, %edi
    test %r12d, %r12d
    cmovz %eax, %r12d
3:
    sub $16, %rsp
    lea 15(%rsp), %rsi
    movb $10, (%rsi)
    mov %edi, %eax
    mov $10, %ecx
4:
    xor %edx, %edx
    div %ecx
    add $48, %dl
    dec %rsi
    mov %dl, (%rsi)
    test %eax, %eax
    jnz 4b
    lea 16(%rsp), %rdx
    sub %rsi, %rdx
    mov $1, %eax
    mov $1, %edi
    syscall
    add $16, %rsp
    pop %rax
    ret
#endif
.section .note.GNU-stack,"",@progbits
