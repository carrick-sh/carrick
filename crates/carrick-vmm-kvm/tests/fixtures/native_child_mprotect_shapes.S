/* #2620 part B: V8 aborts in OS::SetPermissions (an mprotect returned
 * non-zero). A forked child performs the mprotect shape named by -DCASE=n
 * and exits 7 when every step succeeds, else with the errno of the first
 * failing call (mmap errno + 100 when the mmap itself fails, 91 = harness,
 * 90 = the parent saw the child's write in its own page):
 *   1 1 GiB PROT_NONE|MAP_NORESERVE reserve, mprotect 1 MiB RW inside, write
 *   2 RW anonymous page, write code, mprotect R|X, call it
 *   3 as 2 with R|W|X
 *   4 two adjacent VMAs (8 pages, first 4 made R), one mprotect across both
 *   6/7 as 1 with a 16 MiB / 256 MiB reserve (size probe)
 *   8 as 1, run in the root (no fork)
 *   5 4 GiB reserve, commit 64 KiB RW inside, write code, flip R|X, call
 *   9 the parent maps RW and writes code before the fork; the child flips
 *     the inherited page R|X and calls it while the parent waits; the
 *     parent then writes its own copy, which must stay writable
 *  10 16 MiB PROT_NONE reserve, commit 16 KiB RW and touch it, then commit
 *     64 KiB RW elsewhere in the reserve, write code there, flip R|X, call
 *  11 the parent maps RW, writes a marker and makes it R before the fork;
 *     the child widens the inherited page to RW and overwrites it; the
 *     parent's marker must be unchanged (the frame stays private)
 *  12 two backed runs separated by one untouched page, whole range to NONE
 *  13 chunk with guard holes and all 60 code pages touched, whole range to NONE
 *  14 same chunk, whole range to RW
 *   16 as 1 with a 4 GiB reserve, committed 3 GiB in
 *   15 the root reserves 4 GiB and commits a page 1 GiB in, grows brk by
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

.global _start
.text
_start:
#if CASE == 8
    jmp child               /* the run root itself, no fork */
#endif
#if CASE == 9
    MMAP $4096, $3, $0x22
    WRITE_CODE %r15
#elif CASE == 11
    MMAP $4096, $3, $0x22
    movb $0x5a, (%r15)
    MPROTECT %r15, $4096, $1
#endif
#if CASE == 15
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
#if CASE == 15
    cmpb $0xa5, (%r14)      /* the child's write stayed in the child */
    jne bad
#endif
    mov status(%rip), %edi
    test $127, %edi
    jnz harness
    shr $8, %edi
#if CASE == 9
    movb $0xc3, (%r15)      /* the parent's own copy is still RW */
    cmpb $0xc3, (%r15)
    jne private_lost
#elif CASE == 11
    cmpb $0x5a, (%r15)      /* the child's write never reached this frame */
    jne private_lost
#endif
    jmp exit
harness:
    mov $91, %edi
    jmp exit
private_lost:
    mov $90, %edi
    jmp exit

#if CASE == 16
#define RESERVE 0x100000000
#elif CASE == 6
#define RESERVE 0x1000000
#elif CASE == 7
#define RESERVE 0x10000000
#else
#define RESERVE 0x40000000
#endif
child:
#if CASE == 15
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
    jmp done
#else
#if CASE == 1 || CASE == 6 || CASE == 7 || CASE == 8 || CASE == 16
    MMAP $RESERVE, $0, $0x4022
#if CASE == 16
    mov $0xc0000000, %r14
    add %r15, %r14
#else
    lea 0x100000(%r15), %r14
#endif
    MPROTECT %r14, $0x100000, $3
    mov %r14, %rbx
    lea 0x100000(%r14), %r13
1:  movb $0xa5, (%rbx)
    add $4096, %rbx
    cmp %r13, %rbx
    jb 1b
    jmp done
#elif CASE == 2 || CASE == 3
    MMAP $4096, $3, $0x22
    WRITE_CODE %r15
#if CASE == 2
    MPROTECT %r15, $4096, $5
#else
    MPROTECT %r15, $4096, $7
#endif
    call *%r15
    jmp done
#elif CASE == 4
    MMAP $0x8000, $3, $0x22
    MPROTECT %r15, $0x4000, $1
    lea 0x2000(%r15), %r14
    MPROTECT %r14, $0x4000, $3
    movb $1, 0x5000(%r15)
    movb $1, 0x2000(%r15)
    jmp done
#elif CASE == 5
    MMAP $0x100000000, $0, $0x4022
    lea 0x10000(%r15), %r14
    MPROTECT %r14, $0x10000, $3
    WRITE_CODE %r14
    MPROTECT %r14, $0x10000, $5
    call *%r14
    jmp done
#elif CASE == 9
    MPROTECT %r15, $4096, $5
    call *%r15
    jmp done
#elif CASE == 10
    MMAP $0x1000000, $0, $0x4022
    MPROTECT %r15, $0x4000, $3
    movb $1, (%r15)
    lea 0x10000(%r15), %r14
    MPROTECT %r14, $0x10000, $3
    WRITE_CODE %r14
    MPROTECT %r14, $0x10000, $5
    call *%r14
    jmp done
#elif CASE == 11
    MPROTECT %r15, $4096, $3
    movb $0xa5, (%r15)
    cmpb $0xa5, (%r15)
    jne harness
    jmp done
#elif CASE >= 12 && CASE <= 14
#if CASE == 12
    MMAP $0x6000, $0, $0x4022
    mov $0x6000, %r13d
    MPROTECT %r15, $0x2000, $3
    movb $0x5a, (%r15)
    movb $0x5a, 0x1000(%r15)
    lea 0x3000(%r15), %rbx
    MPROTECT %rbx, $0x3000, $3
#else
    MMAP $0x40000, $0, $0x4022
    mov $0x40000, %r13d
    MPROTECT %r15, $0x1000, $3
    movb $0x5a, (%r15)
    lea 0x3000(%r15), %rbx
    MPROTECT %rbx, $0x3c000, $3
#endif
    lea (%r15,%r13), %r14
#if CASE != 12
    sub $0x1000, %r14
#endif
1:  movb $0x5a, (%rbx)
    add $4096, %rbx
    cmp %r14, %rbx
    jb 1b
#if CASE == 14
    MPROTECT %r15, %r13, $3
    mov %r15, %rbx
    lea (%r15,%r13), %r14
2:  movb $0xa5, (%rbx)
    cmpb $0xa5, (%rbx)
    jne harness
    add $4096, %rbx
    cmp %r14, %rbx
    jb 2b
#else
    MPROTECT %r15, %r13, $0
    /* A pipe write must fail with EFAULT for every protected page. */
    lea pipefd(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax               /* pipe2 */
    syscall
    test %rax, %rax
    js fail
    mov %r15, %rbx
    lea (%r15,%r13), %r14
2:  mov pipefd+4(%rip), %edi
    mov %rbx, %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $-14, %rax
    jne harness
    add $4096, %rbx
    cmp %r14, %rbx
    jb 2b
#endif
    jmp done
#else
#error CASE
#endif
#endif
done:
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
pipefd: .space 8
.section .note.GNU-stack,"",@progbits
