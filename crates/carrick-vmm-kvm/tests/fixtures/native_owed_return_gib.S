/* #1482 P0-2: a settlement's exclusion is held for at most one chunk.
 * One 1 GiB private mapping gets one resident page per 2 MiB piece. Each
 * piece is then unmapped on its own: one resident run per munmap, so EL1
 * retires it in place, and the abutting retirements merge into one owed
 * extent covering the whole GiB. No carrier exclusion runs between the
 * munmaps, so nothing settles them early. A MAP_FIXED page at the far end
 * of the extent then needs the settlement: one doorbell, which settles the
 * GiB in chunks, lowering the MM's editor gate between them.
 *
 * Exit status names the first step that differs from Linux:
 *   1 the 1 GiB mmap failed
 *   2 a piece's munmap failed
 *   3 the MAP_FIXED mmap did not return its address
 *   4 the fixed page was not zero-filled
 *   0 every step matched Linux */
#ifndef BASE
#define BASE 0x100000000
#endif
#ifndef GIB
#define GIB 0x40000000
#endif
.global _start
.text
_start:
    mov $BASE, %rdi             /* mmap(BASE, 1 GiB, RW, PRIVATE|ANON|NORESERVE|FIXED) */
    mov $GIB, %esi
    mov $3, %edx
    mov $0x4032, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov %eax, %edi
    neg %edi
    add $100, %edi
    cmp $-4096, %rax
    jae exit
    mov %rax, %r12              /* mapping base */
    lea GIB(%r12), %r13         /* mapping end */

    movb $0xa5, (%r12)          /* one resident page per half */
    movb $0xa5, GIB/2(%r12)

    mov %r12, %rdi              /* unmap each half on its own */
    mov $GIB/2, %esi
    mov $11, %eax
    syscall
    mov $2, %edi
    test %rax, %rax
    jnz exit
    lea GIB/2(%r12), %rdi
    mov $GIB/2, %esi
    mov $11, %eax
    syscall
    mov $2, %edi
    test %rax, %rax
    jnz exit

    lea -4096(%r13), %r14       /* mmap(end - 4 KiB, 4 KiB, RW, PRIVATE|ANON|FIXED) */
    mov %r14, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x32, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov $3, %edi
    cmp %r14, %rax
    jne exit
    mov $4, %edi
    cmpb $0, (%r14)
    jne exit
    movb $0x11, (%r14)

    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
