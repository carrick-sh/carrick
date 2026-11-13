/* #1482: every exclusion of an MM's editor settles its owed returns, not only
 * the settlement doorbell. A brk shrink journals its resident pages as an
 * owed return; the first touch of a fresh anonymous page then crosses to the
 * carrier for its backing, which excludes the MM's editor and settles that
 * return on the way. The regrowth over the released pages is then served
 * without ringing the settlement doorbell.
 *
 * Exit status names the first step that differs from Linux:
 *   1 the first growth did not return the requested break
 *   2 the shrink did not return the requested break
 *   3 the anonymous mmap failed
 *   4 the regrowth did not return the requested break
 *   5 a regrown page was not zero-filled
 *   0 every step matched Linux */
.global _start
.text
_start:
    xor %edi, %edi
    mov $12, %eax
    syscall
    mov %rax, %r12              /* initial break */

    lea 0x40000(%r12), %r13     /* grown break */
    mov %r13, %rdi
    mov $12, %eax
    syscall
    mov $1, %edi
    cmp %r13, %rax
    jne exit

    mov %r12, %rbx              /* make every grown page resident */
1:
    movb $0xa5, (%rbx)
    add $4096, %rbx
    cmp %r13, %rbx
    jb 1b

    lea 0x20000(%r12), %r14     /* shrunk break */
    mov %r14, %rdi
    mov $12, %eax
    syscall
    mov $2, %edi
    cmp %r14, %rax
    jne exit

    xor %edi, %edi              /* mmap(NULL, 4096, RW, PRIVATE|ANON) */
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov $3, %edi
    cmp $-4096, %rax
    jae exit
    movb $0x11, (%rax)          /* first touch: a carrier backing grant */

    mov %r13, %rdi              /* regrow over the released pages */
    mov $12, %eax
    syscall
    mov $4, %edi
    cmp %r13, %rax
    jne exit

    mov %r14, %rbx              /* released and regrown pages read zero */
2:
    mov $5, %edi
    cmpb $0, (%rbx)
    jne exit
    add $4096, %rbx
    cmp %r13, %rbx
    jb 2b

    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
