/* #2722: a large PROT_NONE|MAP_NORESERVE reservation must find a gap in the
 * initial mmap arena, as on Linux. The process named by -DCASE=n reserves,
 * commits a part with mprotect and writes it; it exits 7 when every step
 * succeeds, else with the errno of the first failing call (mmap errno + 100
 * when the mmap itself fails, 91 = harness, 92 = wrong memory contents):
 *   1 forked child: 1 GiB reserve, mprotect 1 MiB RW inside, write
 *   2 RW anonymous page, write code, flip to RX and call it
 *   3 as 2 with RWX
 *   4 one mprotect across two adjacent VMAs
 *   5 4 GiB reserve, commit 64 KiB, write code, flip to RX and call it
 *   6/7 as 1 with a 16 MiB / 256 MiB reserve (size probe)
 *   8 as 1, run in the root (no fork)
 *   10 as 1 with a 4 GiB reserve, committed 3 GiB in
 *   9 the root reserves 4 GiB and commits a page 1 GiB in, grows brk by
 *     1 MiB and touches the stack 1 MiB down, then forks. The child sees all
 *     three, overwrites the reserved page (COW), reserves 1 GiB more and
 *     commits a page of it. The parent, alive throughout, still reads its
 *     own page.
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

.macro WRITE_CODE addr
    mov \addr, %rdi
    movl $0x000007bf, (%rdi)      /* mov $7,%edi */
    movl $0x00e7b800, 4(%rdi)     /* (end of mov $7,%edi) mov $231,%eax */
    movl $0x050f0000, 8(%rdi)     /* (end of mov) syscall */
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

.global _start
.text
_start:
#if CASE == 8
    jmp child               /* the run root itself, no fork */
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
#elif CASE == 2 || CASE == 3
    MMAP $4096, $3, $0x22
    WRITE_CODE %r15
#if CASE == 2
    MPROTECT %r15, $4096, $5
#else
    MPROTECT %r15, $4096, $7
#endif
    call *%r15
    jmp success
#elif CASE == 4
    MMAP $0x8000, $3, $0x22
    MPROTECT %r15, $0x4000, $1
    lea 0x2000(%r15), %r14
    MPROTECT %r14, $0x4000, $3
    movb $1, 0x5000(%r15)
    movb $1, 0x2000(%r15)
    jmp success
#elif CASE == 5
    MMAP $0x100000000, $0, $0x4022
    lea 0x10000(%r15), %r14
    MPROTECT %r14, $0x10000, $3
    WRITE_CODE %r14
    MPROTECT %r14, $0x10000, $5
    call *%r14
    jmp success
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
#if CASE >= 2 && CASE <= 5
success:
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
.section .note.GNU-stack,"",@progbits
