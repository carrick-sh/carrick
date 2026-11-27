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
 *   17 (#2875) V8's FreePages: as 14, but one mprotect(PROT_NONE) over the
 *     whole range. A kernel read (write(2) to a pipe) and write (getrandom(2)) of the
 *     range are EFAULT (95, 96), and the read of page 0 must fault with
 *     SEGV_ACCERR at page 0 (97 = other si_code, 98 = other si_addr). The
 *     handler widens the range back to RW: pages 0 and 2 still hold their
 *     bytes and the hole reads zero
 *   18 as 14 with no mprotect: munmap of the sparse range returns 0, and the
 *     read of page 2 (the second resident run, past the hole) then faults
 *   19 as 14, then mprotect(PROT_READ|PROT_WRITE) over the whole range: pages
 *     0, 1 (the hole) and 2 take a write and read it back, then munmap
 *   20 (#2875) two live threads on two CPUs: a sibling thread reads a
 *     resident RW page and keeps reading it, so its CPU holds the
 *     translation, while the main thread mprotects it PROT_NONE and then
 *     sets a flag. The sibling's first read after it sees the flag (or any
 *     earlier one) must fault with SEGV_ACCERR at the page; the handler
 *     widens it back and its byte is still there (93 = the read after the
 *     flag did not fault: a stale translation; 94 = a wait timed out).
 *     The root may run on either CPU, so the sibling spins on one while the
 *     main thread runs on the other; Carrick's x86 ring does not yet serve
 *     getcpu(2) or sched_setaffinity(2) (#3131), so the placement itself is
 *     not checked
 *   21 (#3121) the root writes a private RW page, mprotects it PROT_READ and
 *     forks. The child widens it back to RW and writes it; the parent, after
 *     the child exits, still reads its own byte (99 if the child's write
 *     reached it)
 *   22 (#2875) the root writes a private RW page, mprotects it PROT_NONE
 *     and forks. On Linux the child widens it back to RW and reads the
 *     parent's byte, and the parent, after the child exits, widens its own
 *     copy and still reads its byte (99 if the child's write reached it).
 *     Until #2875's slice B, Carrick refuses that fork: the refusal must be
 *     clean, so the parent then widens the page and reads its byte, and
 *     exits 120 + the fork's errno
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

/* rt_sigaction(SIGSEGV, {\handler, SA_SIGINFO|SA_RESTORER}, NULL, 8) */
.macro SEGV_INFO handler
    lea \handler(%rip), %rax
    mov %rax, act(%rip)
    movq $0x04000004, act+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, act+16(%rip)
    mov $11, %edi
    lea act(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js harness
.endm
/* futex(\word, FUTEX_WAIT_PRIVATE, \old, &ten_seconds); 94 on timeout */
.macro WAIT_WHILE word, old
    lea \word(%rip), %rdi
    mov $128, %esi
    mov \old, %edx
    lea ten_seconds(%rip), %r10
    mov $202, %eax
    syscall
    cmp $-110, %rax
    je timed_out
.endm
/* futex(\word, FUTEX_WAKE_PRIVATE, 1) */
.macro WAKE word
    lea \word(%rip), %rdi
    mov $129, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
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
#if CASE == 8 || CASE == 11 || CASE == 12 || CASE == 14 || CASE == 16 || CASE == 17 || CASE == 18 || CASE == 19 || CASE == 20
    jmp child               /* the run root itself, no fork */
#endif
#if CASE == 21 || CASE == 22
    MMAP $0x1000, $3, $0x22
    mov %r15, %r14
    movb $0xa5, (%r14)
#if CASE == 21
    MPROTECT %r14, $0x1000, $1
#else
    MPROTECT %r14, $0x1000, $0
#endif
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
#if CASE == 22
    js fork_refused
#else
    js harness
#endif
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
#elif CASE == 21 || CASE == 22
#if CASE == 22
    MPROTECT %r14, $0x1000, $1
#endif
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
#if CASE == 22
fork_refused:
    neg %eax
    add $120, %eax
    mov %eax, %r13d
    MPROTECT %r14, $0x1000, $1  /* the parent keeps its page and its byte */
    cmpb $0xa5, (%r14)
    jne bad
    mov %r13d, %edi
    jmp exit
#endif

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
#elif CASE == 22
    MPROTECT %r14, $0x1000, $3
    cmpb $0xa5, (%r14)      /* the child inherits the parent's byte */
    jne bad
    movb $0x3c, (%r14)
#elif CASE == 20
    MMAP $0x1000, $3, $0x22
    mov %r15, base(%rip)
    mov %r15, %rbx
    movb $0xa5, (%rbx)
    SEGV_INFO segv_info
    MMAP $0x10000, $3, $0x22
    lea 0x10000(%r15), %rsi /* the sibling's stack */
    mov $0x50f00, %edi      /* VM|FS|FILES|SIGHAND|THREAD|SYSVSEM */
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js harness
    jz sibling
1:  cmpl $1, flag(%rip)     /* wait for the sibling's first read */
    je 2f
    WAIT_WHILE flag, $0
    jmp 1b
2:  MPROTECT %rbx, $0x1000, $0  /* PROT_NONE under the sibling's live translation */
    movl $2, flag(%rip)
3:  WAIT_WHILE never, $0    /* the sibling's handler ends the process */
    jmp 3b
sibling:
    cmpb $0xa5, (%rbx)
    jne bad
    movl $1, flag(%rip)
    WAKE flag
    mov $0x100000000, %r12  /* a bound of some seconds, then 94 */
1:  cmpb $0xa5, (%rbx)      /* keep the translation live on its CPU */
    jne bad
    cmpl $2, flag(%rip)
    je 2f
    dec %r12
    jnz 1b
    jmp timed_out
2:  movb (%rbx), %al        /* after the mprotect returned: must fault SEGV_ACCERR */
    mov $93, %edi
    jmp exit
restorer:
    ud2
/* SIGSEGV with siginfo: SEGV_ACCERR at the page, then widen it back to RW
 * and read the bytes it kept */
segv_info:
    cmpl $2, 8(%rsi)        /* si_code */
    mov $97, %edi
    jne exit
    mov base(%rip), %rax
    cmp 16(%rsi), %rax      /* si_addr */
    mov $98, %edi
    jne exit
#if CASE == 17
    MPROTECT base(%rip), $SPARSE_LEN, $3
    mov base(%rip), %rax
    cmpb $0xa5, (%rax)
    jne bad
    cmpb $0, 4096(%rax)
    jne bad
    cmpb $0xa5, 8192(%rax)
    jne bad
#else
    MPROTECT base(%rip), $0x1000, $3
    mov base(%rip), %rax
    cmpb $0xa5, (%rax)
    jne bad
#endif
    mov $7, %edi
    jmp exit
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
    mov %r15, base(%rip)
    lea fds(%rip), %rdi     /* pipe(fds) */
    mov $22, %eax
    syscall
    test %rax, %rax
    js harness
    movl fds+4(%rip), %edi  /* write(pipe, page 0, 1): a kernel read is EFAULT */
    mov %r15, %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $-14, %rax
    mov $95, %edi
    jne exit
    lea 8192(%r15), %rdi    /* getrandom(page 2, 1, 0): a kernel write is EFAULT */
    mov $1, %esi
    xor %edx, %edx
    mov $318, %eax
    syscall
    cmp $-14, %rax
    mov $96, %edi
    jne exit
    SEGV_INFO segv_info
    movb (%r15), %al        /* PROT_NONE: must fault SEGV_ACCERR */
    mov $93, %edi
    jmp exit
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
#if CASE == 19
    MPROTECT %r15, $SPARSE_LEN, $3  /* widen back to RW over the sparse range */
    movb $0x5a, (%r15)
    movb $0x5a, 4096(%r15)
    movb $0x5a, 8192(%r15)
    cmpb $0x5a, (%r15)
    jne bad
    cmpb $0x5a, 4096(%r15)
    jne bad
    cmpb $0x5a, 8192(%r15)
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
#if CASE == 17
/* SIGSEGV with siginfo: SEGV_ACCERR at the page, then widen it back to RW
 * and read the bytes it kept */
segv_info:
    cmpl $2, 8(%rsi)        /* si_code */
    mov $97, %edi
    jne exit
    mov base(%rip), %rax
    cmp 16(%rsi), %rax      /* si_addr */
    mov $98, %edi
    jne exit
#if CASE == 17
    MPROTECT base(%rip), $SPARSE_LEN, $3
    mov base(%rip), %rax
    cmpb $0xa5, (%rax)
    jne bad
    cmpb $0, 4096(%rax)
    jne bad
    cmpb $0xa5, 8192(%rax)
    jne bad
#else
    MPROTECT base(%rip), $0x1000, $3
    mov base(%rip), %rax
    cmpb $0xa5, (%rax)
    jne bad
#endif
    mov $7, %edi
    jmp exit
#endif
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
timed_out:
    mov $94, %edi
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
base: .space 8
flag: .space 4
never: .space 4
fds: .space 8
.section .rodata
.balign 8
ten_seconds: .quad 10, 0
.section .note.GNU-stack,"",@progbits
