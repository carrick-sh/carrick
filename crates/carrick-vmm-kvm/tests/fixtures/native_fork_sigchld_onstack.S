/* #2701 / #2668 (R2): a SIGCHLD handler with SA_ONSTACK runs after a fork
 * when its signal stack was mapped but never touched. Linux makes the stack
 * resident as it pushes the frame. Go allocates every thread's signal stack
 * this way; before the fix the frame write answered a fault and the process
 * was sent SIGSEGV (si_code SI_KERNEL) instead of its handler.
 *
 * The root maps 256 KiB, touches only its first byte, and registers the
 * 60 KiB behind the first page as its alternate signal stack. It installs a
 * SIGCHLD handler with SA_ONSTACK, forks a child that exits 7, and reaps it.
 * Exit status names the first step that differs from Linux:
 *   2 mmap failed     3 sigaltstack failed     4 rt_sigaction failed
 *   5 fork failed     6 wait4 failed (other than EINTR)
 *   7 the child's status was not exit 7
 *   8 the handler did not run
 *   9 the handler did not run on the alternate stack
 *   0 every step matched Linux
 * A parent killed by the forced SIGSEGV never reaches an exit. */
.global _start
.text
_start:
    xor %edi, %edi
    mov $0x40000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax                /* mmap */
    syscall
    mov $2, %edi
    cmp $-4096, %rax
    ja exit
    mov %rax, %r12
    movb $1, (%r12)             /* only the first page is touched */

    lea 0x1000(%r12), %rax
    mov %rax, altstack(%rip)    /* ss_sp */
    movq $0, altstack+8(%rip)   /* ss_flags */
    movq $0xf000, altstack+16(%rip) /* ss_size */
    lea altstack(%rip), %rdi
    xor %esi, %esi
    mov $131, %eax              /* sigaltstack */
    syscall
    mov $3, %edi
    test %eax, %eax
    jnz exit

    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x0c000000, action+8(%rip) /* SA_ONSTACK | SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)
    mov $17, %edi               /* SIGCHLD */
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax               /* rt_sigaction */
    syscall
    mov $4, %edi
    test %eax, %eax
    jnz exit

    mov $57, %eax               /* fork */
    syscall
    test %eax, %eax
    jz child
    mov $5, %edi
    js exit
    mov %eax, %r13d
reap:
    mov %r13d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax               /* wait4 */
    syscall
    cmp $-4, %rax               /* EINTR: the handler ran first */
    je reap
    mov $6, %edi
    cmp %r13d, %eax
    jne exit
    mov $7, %edi
    cmpl $(7 << 8), -24(%rsp)
    jne exit
    mov $8, %edi
    mov handler_sp(%rip), %rax
    test %rax, %rax
    jz exit
    mov $9, %edi
    lea 0x1000(%r12), %rcx
    cmp %rcx, %rax
    jb exit
    lea 0x10000(%r12), %rcx
    cmp %rcx, %rax
    ja exit
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2

child:
    mov $7, %edi
    jmp exit

handler:
    mov %rsp, handler_sp(%rip)
    ret
restorer:
    mov $15, %eax               /* rt_sigreturn */
    syscall
    ud2

.data
.balign 4096
altstack: .space 24
action: .space 32
handler_sp: .quad 0
.section .note.GNU-stack,"",@progbits
