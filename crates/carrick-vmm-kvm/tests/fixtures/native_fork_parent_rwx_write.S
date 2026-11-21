/* #2668 (R1): a parent keeps its writable-and-executable private pages
 * across a fork. Linux arms the page copy-on-write in both processes; the
 * parent's next store resolves the copy and the child still sees the page as
 * it was at the fork. libffi closures live in such pages, so CPython's ctypes
 * and anything that frees a closure after spawning a child depends on it.
 *
 * The parent maps one PROT_READ|PROT_WRITE|PROT_EXEC private anonymous page,
 * writes it, and forks. The child blocks on a pipe, so two processes are
 * live while the parent stores to the page; the parent then releases and
 * reaps the child and stores again. Exit status names the first step that
 * differs from Linux:
 *   1 pipe2 failed
 *   2 mmap failed
 *   3 fork failed
 *   5 the release write did not write one byte
 *   6 wait4 did not return the child
 *   7 the child did not exit 42 (its own status says why: 40 its read
 *     failed, 41 its copy of the page was not the fork-time contents)
 *   8 the parent's page lost a store
 *   0 every step matched Linux
 * A parent killed at the first post-fork store never reaches an exit. */
.global _start
.text
_start:
    lea fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax              /* pipe2 */
    syscall
    mov $1, %edi
    test %eax, %eax
    jnz exit

    xor %edi, %edi
    mov $4096, %esi
    mov $7, %edx                /* PROT_READ | PROT_WRITE | PROT_EXEC */
    mov $0x22, %r10d            /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                /* mmap */
    syscall
    mov $2, %edi
    cmp $-4096, %rax
    ja exit
    mov %rax, %r12
    movb $0x11, (%r12)          /* resident before the fork */

    mov $57, %eax               /* fork */
    syscall
    test %eax, %eax
    jz child
    mov $3, %edi
    js exit
    mov %eax, %r13d

    movb $0x22, 1(%r12)         /* the child is alive, blocked on the pipe */

    mov fds+4(%rip), %edi
    lea release(%rip), %rsi
    mov $1, %edx
    mov $1, %eax                /* write */
    syscall
    mov $5, %edi
    cmp $1, %rax
    jne exit

    mov %r13d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax               /* wait4 */
    syscall
    mov $6, %edi
    cmp %r13d, %eax
    jne exit
    mov $7, %edi
    cmpl $(42 << 8), status(%rip)
    jne exit

    movb $0x33, 2(%r12)         /* the child is reaped */
    mov $8, %edi
    cmpb $0x11, (%r12)
    jne exit
    cmpb $0x22, 1(%r12)
    jne exit
    cmpb $0x33, 2(%r12)
    jne exit
    xor %edi, %edi
exit:
    mov $231, %eax              /* exit_group */
    syscall
    ud2

child:
    mov fds(%rip), %edi
    lea held(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax              /* read: blocks until the parent's store is done */
    syscall
    mov $40, %edi
    cmp $1, %rax
    jne exit
    mov $41, %edi
    cmpb $0x11, (%r12)
    jne exit
    cmpb $0, 1(%r12)
    jne exit
    mov $42, %edi
    jmp exit

.section .rodata
release: .byte 0x52
.bss
.balign 4096
fds: .space 4096
status: .space 4096
held: .space 4096
.section .note.GNU-stack,"",@progbits
