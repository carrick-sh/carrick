/* #2655: a root with more one-page residency rows than one table segment
 * holds forks, and both processes run on.
 *
 * PAGES one-page private anonymous mappings, each followed by an unmapped
 * page so no two share a grant window. Every page is written before the
 * fork, so each is a committed leaf with its own residency row; the fork
 * needs at least one more row per page for the child.
 *
 * Parent and child then write to inherited pages while both are live. The
 * child exits 3; the parent checks that its own bytes survived the child's
 * writes and exits WEXITSTATUS + 4 = 7. A wrong byte exits 9, a failed
 * mapping 10, a failed wait 12, a failed fork 100 + errno.
 */
#ifndef PAGES
#define PAGES 2400
#endif
.global _start
.text
_start:
    xor %r13d, %r13d            /* mappings made */
    xor %r15d, %r15d            /* first page */
map:
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx                /* PROT_READ | PROT_WRITE */
    mov $0x22, %r10d            /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                /* mmap */
    syscall
    cmp $-4096, %rax
    ja map_failed
    mov %rax, %r14              /* last page */
    test %r15, %r15
    jnz 1f
    mov %rax, %r15
1:
    lea 4096(%r14), %rdi
    mov $4096, %esi
    mov $11, %eax               /* munmap the second page: leave a hole */
    syscall
    test %eax, %eax
    jnz map_failed
    movb $0x5a, (%r14)          /* commit the leaf */
    inc %r13d
    cmp $PAGES, %r13d
    jb map

    mov $57, %eax               /* fork */
    syscall
    test %eax, %eax
    jz child
    js fork_failed
    mov %eax, %r12d
    movb $0x11, (%r15)          /* parent write while the child is live */
    mov %r12d, %edi
    lea -16(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax               /* wait4 */
    syscall
    cmp %r12d, %eax
    jne wait_failed
    cmpb $0x11, (%r15)
    jne wrong_byte
    cmpb $0x5a, (%r14)          /* the child's write stayed private */
    jne wrong_byte
    mov -16(%rsp), %edi
    shr $8, %edi
    and $0xff, %edi
    add $4, %edi
    jmp exit
child:
    cmpb $0x5a, (%r14)
    jne wrong_byte
    movb $0xa5, (%r14)          /* child writes to inherited pages */
    movb $0xa5, (%r15)
    cmpb $0xa5, (%r15)
    jne wrong_byte
    mov $3, %edi
    jmp exit
wrong_byte:
    mov $9, %edi
    jmp exit
map_failed:
    mov $10, %edi
    jmp exit
fork_failed:
    neg %eax                    /* 100 + errno */
    lea 100(%rax), %edi
    jmp exit
wait_failed:
    mov $12, %edi
exit:
    mov $231, %eax              /* exit_group */
    syscall
    ud2
