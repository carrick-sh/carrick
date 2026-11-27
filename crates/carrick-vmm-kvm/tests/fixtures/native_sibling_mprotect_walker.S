/* #3133: a sibling thread's page walker against the main thread's mprotect.
 *
 * Two live threads share one 16 MiB private anonymous RW region. The sibling
 * writes the first byte of every page once, in order: each write first-touches
 * the page, and the CPU's page walker then sets ACCESSED and DIRTY in the leaf
 * the fault published. Meanwhile the main thread toggles the whole region
 * between PROT_READ|PROT_WRITE|PROT_EXEC and PROT_READ|PROT_WRITE, so every
 * mprotect edits every resident leaf, including ones the sibling has just
 * touched. Both protections keep the sibling's writes legal.
 *
 * Linux: every mprotect returns 0, the sibling writes all pages and exits,
 * and the main thread checks every page holds the byte, then exits 7. Any
 * mprotect error exits with its errno (38 = ENOSYS: a walker update taken as
 * a refused edit); a missing byte exits 92; 94 if the sibling never finished
 * within the main thread's bound.
 *
 * The root may run on either CPU, and the sibling's writes land wherever it
 * runs; the window is the walker's update between the edit's snapshot and its
 * store, so the witness counts on many toggles rather than on placement. */

#define LEN 0x1000000
#define PAGES (LEN / 0x1000)

.macro SYS nr
    mov \nr, %eax
    syscall
.endm
/* mprotect(%r14, LEN, \prot); errno -> exit */
.macro MPROTECT prot
    mov %r14, %rdi
    mov $LEN, %rsi
    mov \prot, %edx
    SYS $10
    test %rax, %rax
    js fail
.endm

.global _start
.text
_start:
    xor %edi, %edi          /* the shared region */
    mov $LEN, %rsi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    SYS $9
    test %rax, %rax
    js fail
    mov %rax, %r14
    xor %edi, %edi          /* the sibling's stack */
    mov $0x10000, %rsi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    SYS $9
    test %rax, %rax
    js fail
    lea 0x10000(%rax), %rsi
    mov $0x50f00, %edi      /* VM|FS|FILES|SIGHAND|THREAD|SYSVSEM */
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    SYS $56
    test %rax, %rax
    js fail
    jz sibling
    mov $0x100000, %r12     /* toggle bound, then 94 */
1:  MPROTECT $7
    MPROTECT $3
    cmpl $0, done(%rip)
    jne 2f
    dec %r12
    jnz 1b
    mov $94, %edi
    jmp exit
2:  mov %r14, %rbx          /* every page kept the sibling's byte */
    mov $PAGES, %ecx
3:  cmpb $0x3c, (%rbx)
    jne bad
    add $0x1000, %rbx
    dec %ecx
    jnz 3b
    mov $7, %edi
    jmp exit
sibling:
    mov %r14, %rbx
    mov $PAGES, %ecx
1:  movb $0x3c, (%rbx)
    add $0x1000, %rbx
    dec %ecx
    jnz 1b
    movl $1, done(%rip)
    xor %edi, %edi
    SYS $60                 /* this thread's raw exit; the main one runs on */
bad:
    mov $92, %edi
    jmp exit
fail:
    neg %rax
    mov %eax, %edi
exit:
    SYS $231

.bss
.balign 4
done:
    .long 0
