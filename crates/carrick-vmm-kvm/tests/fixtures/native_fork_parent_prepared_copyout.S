/* #2701 / #2668: after a fork, the kernel writes into a parent page that is
 * mapped but was never touched. Linux makes the page resident and private to
 * the writer. Go reads its child's pipe into such a page ("read |0: bad
 * address"), and every signal frame pushed onto a fresh signal stack is such
 * a write.
 *
 * The parent maps 256 KiB of private anonymous memory and touches only its
 * first byte, so the pages behind it are mapped and never touched. It forks
 * a child that blocks on a pipe (two live processes), then read(2)s eight
 * bytes from a second pipe into the fourth page. Exit status names the first
 * step that differs from Linux:
 *   1 pipe2 failed          2 mmap failed          3 fork failed
 *   4 the data write did not write eight bytes
 *   5 read(2) into the untouched page did not return 8 (EFAULT before the fix)
 *   6 the page does not hold the bytes read
 *   7 the release write failed
 *   8 wait4 did not return the child
 *   9 the child did not exit 42 (41: its copy of the page was not zero)
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
    mov $0x40000, %esi
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
    movb $1, (%r12)             /* only the first page is touched */
    lea 0x3005(%r12), %r14      /* the copy-out target, never touched */

    mov $57, %eax               /* fork */
    syscall
    test %eax, %eax
    jz child
    mov $3, %edi
    js exit
    mov %eax, %r13d

    mov data+4(%rip), %edi
    lea bytes(%rip), %rsi
    mov $8, %edx
    mov $1, %eax                /* write */
    syscall
    mov $4, %edi
    cmp $8, %rax
    jne exit

    mov data(%rip), %edi
    mov %r14, %rsi
    mov $8, %edx
    xor %eax, %eax              /* read into the untouched page */
    syscall
    mov $5, %edi
    cmp $8, %rax
    jne exit
    mov $6, %edi
    mov bytes(%rip), %rax
    cmp %rax, (%r14)
    jne exit

    mov hold+4(%rip), %edi
    lea bytes(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    mov $7, %edi
    cmp $1, %rax
    jne exit

    mov %r13d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax               /* wait4 */
    syscall
    mov $8, %edi
    cmp %r13d, %eax
    jne exit
    mov $9, %edi
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
    xor %eax, %eax              /* blocks until the parent's read is done */
    syscall
    mov $40, %edi
    cmp $1, %rax
    jne exit
    mov $41, %edi
    cmpq $0, (%r14)             /* the parent's bytes never reach the child */
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
