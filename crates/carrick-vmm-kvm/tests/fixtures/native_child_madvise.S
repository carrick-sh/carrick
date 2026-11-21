/* madvise in a live native child (#1846). The parent keeps a written RW page
 * across fork; the child discards its inherited copy, then reproduces V8's
 * guard page (mprotect PROT_NONE, then MADV_DONTNEED) and discards a touched
 * RW page. A failed madvise exits with its errno (38 on the original ring);
 * other stages exit with their own status (71..73: which mprotect failed),
 * and the parent with the child's.
 */
.global _start
.text
_start:
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js map_failed
    mov %rax, %r12
    movb $0x37, (%r12)
    mov $57, %eax
    syscall
    test %eax, %eax
    js fork_failed
    jz child
    mov %eax, %r13d
    sub $16, %rsp
    mov %rsp, %rsi
    mov %r13d, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne wait_failed
    mov (%rsp), %edi
    test $127, %edi
    jnz child_signaled
    shr $8, %edi
    and $255, %edi
    jnz exit
    /* The child's discard never reaches the parent's copy. */
    cmpb $0x37, (%r12)
    jne parent_bytes_failed
    xor %edi, %edi
    jmp exit

child:
    /* V8's code-range shape: a PROT_NONE NORESERVE reservation, committed RW. */
    xor %edi, %edi
    mov $0x40000, %esi
    xor %edx, %edx
    mov $0x4022, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js map_failed
    mov %rax, %r14
    mov %r14, %rdi
    mov $0x40000, %esi
    mov $3, %edx
    mov $71, %ebx
    call protect

    /* V8's guard page: PROT_NONE, then MADV_DONTNEED. The chunk is touched
     * only afterwards: on x86 today, PROT_NONE over a page a first touch
     * already backed (or prepared) is refused before any madvise, a
     * separate mprotect gap. */
    lea 0x1000(%r14), %rdi
    mov $0x1000, %esi
    xor %edx, %edx
    mov $72, %ebx
    call protect
    lea 0x1000(%r14), %rdi
    mov $0x1000, %esi
    mov $4, %edx
    call advise
    /* It reads zero once it is readable again. */
    lea 0x1000(%r14), %rdi
    mov $0x1000, %esi
    mov $3, %edx
    mov $73, %ebx
    call protect
    cmpb $0, 0x1000(%r14)
    jne guard_bytes_failed

    /* An inherited, written RW page reads zero after its discard. */
    mov %r12, %rdi
    mov $4096, %esi
    mov $4, %edx
    call advise
    cmpb $0, (%r12)
    jne inherited_bytes_failed
    movb $0x51, (%r12)
    cmpb $0x51, (%r12)
    jne inherited_bytes_failed

    /* A touched RW page keeps RW and reads zero, then takes new bytes. */
    movb $0x42, (%r14)
    cmpb $0x42, (%r14)
    jne rw_bytes_failed
    mov %r14, %rdi
    mov $0x1000, %esi
    mov $4, %edx
    call advise
    cmpb $0, (%r14)
    jne rw_bytes_failed
    movb $0x55, (%r14)
    cmpb $0x55, (%r14)
    jne rw_bytes_failed

    /* Hint advice and a never-touched range return 0 without an effect. */
    mov %r14, %rdi
    mov $0x40000, %esi
    mov $3, %edx
    call advise
    cmpb $0x55, (%r14)
    jne rw_bytes_failed
    lea 0x20000(%r14), %rdi
    mov $0x10000, %esi
    mov $4, %edx
    call advise

    /* An unaligned start is EINVAL before any coverage. */
    lea 1(%r14), %rdi
    mov $1, %esi
    mov $4, %edx
    mov $28, %eax
    syscall
    cmp $-22, %rax
    jne einval_failed

    /* A mapped range may include a never-backed hole between two runs.
     * Commit only its endpoints before touching them. */
    xor %edi, %edi
    mov $0x4000, %esi
    xor %edx, %edx
    mov $0x4022, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js map_failed
    mov %rax, %r15
    mov %r15, %rdi
    mov $0x1000, %esi
    mov $3, %edx
    mov $74, %ebx
    call protect
    lea 0x3000(%r15), %rdi
    mov $0x1000, %esi
    mov $3, %edx
    mov $74, %ebx
    call protect
    movb $0x61, (%r15)
    movb $0x62, 0x3000(%r15)
    mov %r15, %rdi
    mov $0x4000, %esi
    mov $4, %edx
    call advise
    cmpb $0, (%r15)
    jne sparse_bytes_failed
    cmpb $0, 0x3000(%r15)
    jne sparse_bytes_failed

    xor %edi, %edi
    jmp exit

advise:
    mov $28, %eax
    syscall
    test %rax, %rax
    jnz advise_failed
    ret
advise_failed:
    neg %eax
    mov %eax, %edi
    jmp exit
protect:
    mov $10, %eax
    syscall
    test %rax, %rax
    jnz protect_failed
    ret

map_failed:
    mov $60, %edi
    jmp exit
fork_failed:
    mov $61, %edi
    jmp exit
wait_failed:
    mov $62, %edi
    jmp exit
child_signaled:
    mov $63, %edi
    jmp exit
parent_bytes_failed:
    mov $64, %edi
    jmp exit
inherited_bytes_failed:
    mov $65, %edi
    jmp exit
protect_failed:
    mov %ebx, %edi
    jmp exit
guard_bytes_failed:
    mov $67, %edi
    jmp exit
rw_bytes_failed:
    mov $68, %edi
    jmp exit
einval_failed:
    mov $69, %edi
    jmp exit
sparse_bytes_failed:
    mov $75, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
