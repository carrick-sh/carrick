/* #2620 part B: V8 aborts in OS::SetPermissions (an mprotect returned
 * non-zero). A forked child performs the mprotect shape named by -DCASE=n
 * and exits 7 when every step succeeds, else with the errno of the first
 * failing call (mmap errno + 100 when the mmap itself fails, 91 = harness):
 *   1 1 GiB PROT_NONE|MAP_NORESERVE reserve, mprotect 1 MiB RW inside, write
 *   2 RW anonymous page, write code, mprotect R|X, call it
 *   3 as 2 with R|W|X
 *   4 two adjacent VMAs (8 pages, first 4 made R), one mprotect across both
 *   6/7 as 1 with a 16 MiB / 256 MiB reserve (size probe)
 *   8 as 1, run in the root (no fork)
 *   5 4 GiB reserve, commit 64 KiB RW inside, write code, flip R|X, call
 *   9 negative control: a 256 TiB PROT_NONE|MAP_NORESERVE reserve is larger
 *     than the 128 TiB user address space and must fail with ENOMEM (exit 7;
 *     8 when it succeeds, else the other errno + 100)
 * The parent propagates the child's exit status. */
.global _start
.text
_start:
#if CASE == 8
    jmp child               /* the run root itself, no fork */
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
    mov status(%rip), %edi
    test $127, %edi
    jnz harness
    shr $8, %edi
    jmp exit
harness:
    mov $91, %edi
    jmp exit

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
#elif CASE == 7
#define RESERVE 0x10000000
#else
#define RESERVE 0x40000000
#endif
child:
#if CASE == 1 || CASE == 6 || CASE == 7 || CASE == 8
    MMAP $RESERVE, $0, $0x4022
    lea 0x100000(%r15), %r14
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
    xor %edi, %edi
    mov $0x1000000000000, %rsi
    xor %edx, %edx
    mov $0x4022, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-12, %rax
    je done
    test %rax, %rax
    js fail_mmap
    mov $8, %edi
    jmp exit
#else
#error CASE
#endif
done:
    mov $7, %edi
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
