/* #2722: a large PROT_NONE|MAP_NORESERVE reservation must find a gap in the
 * initial mmap arena, as on Linux. The process named by -DCASE=n reserves,
 * commits a part with mprotect and writes it; it exits 7 when every step
 * succeeds, else with the errno of the first failing call (mmap errno + 100
 * when the mmap itself fails, 91 = harness, 92 = wrong memory contents):
 *   1 forked child: 1 GiB reserve, mprotect 1 MiB RW inside, write
 *   6/7 as 1 with a 16 MiB / 256 MiB reserve (size probe)
 *   8 as 1, run in the root (no fork)
 *   10 as 1 with a 4 GiB reserve, committed 3 GiB in
 *   9 the root reserves 4 GiB and commits a page 1 GiB in, grows brk by
 *     1 MiB and touches the stack 1 MiB down, then forks. The child sees all
 *     three, overwrites the reserved page (COW), reserves 1 GiB more and
 *     commits a page of it. The parent, alive throughout, still reads its
 *     own page.
 *   11 (#2874) the root maps 1.875 MiB anonymous RW, writes a `ret` into
 *     every page, mprotects it PROT_READ|PROT_EXEC and calls its first and
 *     last pages
 *   12 as 11, the range committed RW inside a 16 MiB PROT_NONE reserve
 *   13 as 11, in a forked child
 *   14 (#3073) the root reserves 16 MiB PROT_NONE and commits pages 0 and
 *     2 RW one at a time, writing each, so its resident pages form two runs
 *     with a hole between. mprotect over the whole 256 KiB to PROT_READ
 *     returns 0, and the written bytes and the hole's zero read back. munmap
 *     of the whole range returns 0 and the read of page 0 then faults: its
 *     SIGSEGV handler exits 7 (93 = no fault)
 *   15 as 14, in a forked child
 *   16 as 14 with every other page of the 256 KiB committed (32 runs)
 *   17 V8's FreePages: as 14, but one mprotect(PROT_NONE) over the whole
 *     range, then the read of page 0 must fault
 *   18 as 14 with no mprotect: munmap of the sparse range returns 0, and the
 *     read of page 2 (the second resident run, past the hole) then faults
 *   21 (#3121) the root writes a private RW page, mprotects it PROT_READ and
 *     forks. The child widens it back to RW and writes it; the parent, after
 *     the child exits, still reads its own byte (99 if the child's write
 *     reached it)
 * The parent propagates the child's exit status. */

/* rax = mmap(0, rsi, edx prot, r10 flags, -1, 0); r15 = base or exit errno */
.macro MMAP len, prot, flags
    xor %edi, %edi
    mov \len, %rsi
    mov \prot, %edx
    mov \flags, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_mmap
    mov %rax, %r15
.endm
/* mprotect(\addr, \len, \prot); errno -> exit */
.macro MPROTECT addr, len, prot
    mov \addr, %rdi
    mov \len, %rsi
    mov \prot, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    js fail
.endm

#if CASE == 6
#define RESERVE 0x1000000
#define COMMIT_AT 0x100000
#elif CASE == 7
#define RESERVE 0x10000000
#define COMMIT_AT 0x100000
#elif CASE == 10
#define RESERVE 0x100000000
#define COMMIT_AT 0xc0000000
#else
#define RESERVE 0x40000000
#define COMMIT_AT 0x100000
#endif
/* #2874: V8's code-range length */
#define CODE_LEN 0x1e0000
/* #3073: V8's allocation page */
#define SPARSE_LEN 0x40000

.global _start
.text
_start:
#if CASE == 8 || CASE == 11 || CASE == 12 || CASE == 14 || CASE == 16 || CASE == 17 || CASE == 18
    jmp child               /* the run root itself, no fork */
#endif
#if CASE == 21
    MMAP $0x1000, $3, $0x22
    mov %r15, %r14
    movb $0xa5, (%r14)
    MPROTECT %r14, $0x1000, $1
#endif
#if CASE == 9
    MMAP $0x100000000, $0, $0x4022
    mov $0x40000000, %r14
    add %r15, %r14          /* r14 = the committed page, 1 GiB in */
    MPROTECT %r14, $0x10000, $3
    movb $0xa5, (%r14)
    xor %edi, %edi
    mov $12, %eax
    syscall
    mov %rax, %r12          /* r12 = the initial break */
    lea 0x100000(%r12), %rdi
    mov $12, %eax
    syscall
    lea 0x100000(%r12), %rdx
    cmp %rdx, %rax
    jne harness
    movb $0x5a, 0xfffff(%r12)
    movb $0x11, -0x100000(%rsp)
#endif
    mov $57, %eax
    syscall
    test %eax, %eax
    js harness
    jz child
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js harness
#if CASE == 9
    cmpb $0xa5, (%r14)      /* the child's write stayed in the child */
    jne bad
#elif CASE == 21
    cmpb $0xa5, (%r14)      /* the child's write stayed in the child */
    mov $99, %edi
    jne exit
#endif
    mov status(%rip), %edi
    test $127, %edi
    jnz harness
    shr $8, %edi
    jmp exit
harness:
    mov $91, %edi
    jmp exit

child:
#if CASE == 9
    cmpb $0xa5, (%r14)
    jne bad
    movb $0x3c, (%r14)
    cmpb $0x5a, 0xfffff(%r12)
    jne bad
    cmpb $0x11, -0x100000(%rsp)
    jne bad
    MMAP $0x40000000, $0, $0x4022
    MPROTECT %r15, $0x1000, $3
    movb $1, (%r15)
    cmpb $0x3c, (%r14)
    jne bad
#elif CASE == 21
    MPROTECT %r14, $0x1000, $3
    movb $0x3c, (%r14)
    cmpb $0x3c, (%r14)
    jne bad
#elif CASE >= 14
    /* V8's code range: a PROT_NONE reserve, committed RW a page at a time */
    MMAP $0x1000000, $0, $0x4022
    mov %r15, %rbx
#if CASE == 16
    lea SPARSE_LEN(%r15), %r13
#else
    lea 0x3000(%r15), %r13
#endif
1:  MPROTECT %rbx, $0x1000, $3
    movb $0xa5, (%rbx)      /* every other page: runs with holes between */
    add $8192, %rbx
    cmp %r13, %rbx
    jb 1b
#if CASE == 17
    MPROTECT %r15, $SPARSE_LEN, $0  /* V8's FreePages */
#else
#if CASE != 18
    MPROTECT %r15, $SPARSE_LEN, $1
    cmpb $0xa5, (%r15)
    jne bad
    cmpb $0xa5, 8192(%r15)
    jne bad
    cmpb $0, 4096(%r15)     /* the hole reads zero */
    jne bad
#endif
    mov %r15, %rdi          /* munmap(base, SPARSE_LEN) */
    mov $SPARSE_LEN, %rsi
    mov $11, %eax
    syscall
    test %rax, %rax
    js fail
#endif
    lea segv(%rip), %rax
    mov %rax, act(%rip)
    movq $0x04000000, act+8(%rip)   /* SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, act+16(%rip)
    mov $11, %edi           /* rt_sigaction(SIGSEGV, &act, NULL, 8) */
    lea act(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js harness
#if CASE == 18
    movb 8192(%r15), %al    /* the second run, unmapped: must fault */
#else
    movb (%r15), %al        /* unmapped or PROT_NONE: must fault */
#endif
    mov $93, %edi
    jmp exit
segv:
    mov $7, %edi
    jmp exit
restorer:
    ud2
#elif CASE >= 11
#if CASE == 12
    MMAP $0x1000000, $0, $0x4022
    add $0x200000, %r15
    MPROTECT %r15, $CODE_LEN, $3
#else
    MMAP $CODE_LEN, $3, $0x22
#endif
    mov %r15, %rbx
    lea CODE_LEN(%r15), %r13
1:  movb $0xc3, (%rbx)      /* ret */
    add $4096, %rbx
    cmp %r13, %rbx
    jb 1b
    MPROTECT %r15, $CODE_LEN, $5
    call *%r15              /* the first page now executes */
    lea -4096(%r13), %rax
    call *%rax              /* and the last */
    cmpb $0xc3, -4096(%r13)
    jne bad
#else
    MMAP $RESERVE, $0, $0x4022
    mov $COMMIT_AT, %r14
    add %r15, %r14
    MPROTECT %r14, $0x100000, $3
    mov %r14, %rbx
    lea 0x100000(%r14), %r13
1:  movb $0xa5, (%rbx)
    add $4096, %rbx
    cmp %r13, %rbx
    jb 1b
#endif
    mov $7, %edi
    jmp exit
bad:
    mov $92, %edi
    jmp exit
fail_mmap:
    neg %eax
    add $100, %eax
    mov %eax, %edi
    jmp exit
fail:
    neg %eax
    mov %eax, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .bss
.balign 4
status: .space 4
.balign 8
act: .space 32
.section .note.GNU-stack,"",@progbits
