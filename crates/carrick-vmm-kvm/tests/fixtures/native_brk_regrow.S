/* #2217: glibc malloc trims its heap with a brk(2) shrink and later grows it
 * back over the same pages. Linux serves the regrowth and hands back zeroed
 * pages. CPython's compiler does exactly this; when the regrowing brk
 * returns an errno, glibc stores it as the break and the next allocation
 * faults (exit 139).
 *
 * Grow the break by 256 KiB and touch every page, shrink it by 128 KiB, then
 * grow it back. Exit status names the first step that differs from Linux:
 *   1 the first growth did not return the requested break
 *   2 the shrink did not return the requested break
 *   3 the regrowth did not return the requested break
 *   4 a regrown page was not zero-filled
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

    mov %r13, %rdi              /* regrow over the released pages */
    mov $12, %eax
    syscall
    mov $3, %edi
    cmp %r13, %rax
    jne exit

    mov %r14, %rbx              /* released and regrown pages read zero */
2:
    mov $4, %edi
    cmpb $0, (%rbx)
    jne exit
    movb $0x5a, (%rbx)
    add $4096, %rbx
    cmp %r13, %rbx
    jb 2b

    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
