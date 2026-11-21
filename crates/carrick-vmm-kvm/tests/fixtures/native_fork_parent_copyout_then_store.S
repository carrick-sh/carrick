/* #2716: after a fork, the kernel copies into one of the parent's inherited
 * pages (a copy-on-write the kernel resolves), and the parent's next store
 * from user mode to another inherited page must resolve its own copy.
 * glibc does exactly this: read(2) into a buffer, then printf stores to
 * stdout's FILE.
 *
 * The parent maps private anonymous memory and writes three pages (A, B, C)
 * before the fork, so the fork arms all three copy-on-write. It forks a child
 * that blocks on a pipe (two live processes). It then:
 *   - stores to page C from user mode (the control: a user copy-on-write
 *     with no kernel write before it);
 *   - read(2)s eight bytes from a second pipe into page A (the kernel's
 *     copy-on-write);
 *   - stores to page B from user mode, with no syscall in between.
 * The parent uses no stack between the fork and that store: a push would be
 * a user store to an inherited page too. Exit status names the first step
 * that differs from Linux:
 *   1 pipe2 failed          2 mmap failed          3 fork failed
 *   4 the data write did not write eight bytes
 *   5 read(2) into page A did not return 8
 *   6 page A does not hold the bytes read, or lost its other bytes
 *   7 page B does not hold the stored byte, or lost its other bytes
 *   8 page C does not hold the control byte
 *   9 the release write failed
 *  10 wait4 did not return the child
 *  11 the child did not exit 42 (41: one of its pages changed)
 *   0 every step matched Linux */
.global _start
.text
_start:
    lea hold(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax              /* pipe2 */
    syscall
    mov $1, %edi
    test %eax, %eax
    jnz exit
    lea data(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    mov $1, %edi
    test %eax, %eax
    jnz exit

    xor %edi, %edi
    mov $0x10000, %esi
    mov $3, %edx                /* PROT_READ | PROT_WRITE */
    mov $0x22, %r10d            /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                /* mmap */
    syscall
    mov $2, %edi
    cmp $-4096, %rax
    ja exit
    mov %rax, %r12
    mov $0x5a5a5a5a5a5a5a5a, %rax
    mov %rax, 0x3000(%r12)      /* page A: the copy-out target */
    mov %rax, 0x3008(%r12)
    mov %rax, 0x9000(%r12)      /* page B: the user store after it */
    mov %rax, 0x6000(%r12)      /* page C: the control store */

    mov $57, %eax               /* fork */
    syscall
    test %eax, %eax
    jz child
    mov $3, %edi
    js exit
    mov %eax, %r13d

    movb $0x33, 0x6001(%r12)    /* control: user copy-on-write of page C */

    mov data+4(%rip), %edi
    lea bytes(%rip), %rsi
    mov $8, %edx
    mov $1, %eax                /* write */
    syscall
    mov $4, %edi
    cmp $8, %rax
    jne exit

    mov data(%rip), %edi
    lea 0x3008(%r12), %rsi
    mov $8, %edx
    xor %eax, %eax              /* read: the kernel's copy-on-write of page A */
    syscall
    movb $0x77, 0x9001(%r12)    /* the user copy-on-write of page B (#2716) */
    mov $5, %edi
    cmp $8, %rax
    jne exit

    mov $6, %edi
    mov bytes(%rip), %rax
    cmp %rax, 0x3008(%r12)
    jne exit
    mov $0x5a5a5a5a5a5a5a5a, %rax
    cmp %rax, 0x3000(%r12)
    jne exit
    mov $7, %edi
    mov $0x5a5a5a5a5a5a775a, %rax
    cmp %rax, 0x9000(%r12)
    jne exit
    mov $8, %edi
    mov $0x5a5a5a5a5a5a335a, %rax
    cmp %rax, 0x6000(%r12)
    jne exit

    mov hold+4(%rip), %edi
    lea bytes(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    mov $9, %edi
    cmp $1, %rax
    jne exit

    mov %r13d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax               /* wait4 */
    syscall
    mov $10, %edi
    cmp %r13d, %eax
    jne exit
    mov $11, %edi
    cmpl $(42 << 8), -24(%rsp)
    jne exit
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2

child:
    mov hold(%rip), %edi
    lea -16(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax              /* blocks until the parent's stores are done */
    syscall
    mov $40, %edi
    cmp $1, %rax
    jne exit
    mov $41, %edi               /* none of the parent's bytes reach the child */
    mov $0x5a5a5a5a5a5a5a5a, %rax
    cmp %rax, 0x3000(%r12)
    jne exit
    cmp %rax, 0x3008(%r12)
    jne exit
    cmp %rax, 0x9000(%r12)
    jne exit
    cmp %rax, 0x6000(%r12)
    jne exit
    mov $42, %edi
    jmp exit

.section .rodata
bytes: .ascii "abcdefgh"
.bss
.balign 4096
hold: .space 8
data: .space 8
.section .note.GNU-stack,"",@progbits
