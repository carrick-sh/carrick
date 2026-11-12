/* #2157 B0 T1: two live fork children each make an x86-allowed host
 * crossing that no ring stage serves. A child has no host task context, so
 * each call must be a counted ENOSYS in ring (as ARM answers a fork child's
 * unclaimed native call), not a carrier failure. Child A calls
 * read(0, buf, 0) and child B calls lseek(0, 0, SEEK_CUR). The root's own
 * read(0, buf, 0) keeps its host route and returns 0.
 *
 * Liveness is a handshake, not a delay. (A forked child's pipe write and
 * shared mapping, and a root kill of a child, are unsupported here, so
 * signals between the children carry it.) The root blocks SIGUSR1, SIGUSR2
 * and SIGHUP before forking, so every signal stays pending until waited for.
 * Child A makes its call, reports SIGUSR1 to the root, and waits for SIGHUP.
 * Child B makes its call, reports SIGUSR2 to the root, sends SIGHUP to A, and
 * waits for SIGHUP. A, once woken, broadcasts SIGHUP to its process group,
 * which releases B. A cannot exit before B has made its call, and B cannot
 * exit before A has made its call and been woken: children that ran one
 * after another time out. Every wait is an rt_sigtimedwait with a 5 s
 * limit: a timeout is a failure exit, never a hang.
 *
 * Children exit with the negated value their call returned (38 = ENOSYS),
 * or 93 if the release never came. The root exits 7 = all as expected;
 * 81 its read returned ENOSYS, 82 it returned something else; 64 | A's
 * status, 128 | B's status name a wrong child answer; 91 fork/wait/signal
 * setup failed; 92 a report never arrived or both were the same signal. */
.global _start
.text
_start:
    xor %edi, %edi                 /* rt_sigprocmask(SIG_BLOCK, all three) */
    lea block_set(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %eax, %eax
    jnz fail_wait

    mov $57, %eax                  /* fork: child A */
    syscall
    test %eax, %eax
    js fail_wait
    jz child_a
    mov %eax, %r12d
    mov $57, %eax                  /* fork: child B */
    syscall
    test %eax, %eax
    js fail_wait
    jz child_b
    mov %eax, %r13d

    xor %edi, %edi                 /* root: read(0, buf, 0) */
    lea buffer(%rip), %rsi
    xor %edx, %edx
    xor %eax, %eax
    syscall
    cmp $-38, %rax
    je fail_root_enosys
    test %rax, %rax
    jnz fail_root_other

    call take_report               /* both children have made their call */
    mov %eax, %r14d
    call take_report
    cmp %eax, %r14d
    je fail_report                 /* the same child twice */

    mov %r12d, %edi                /* wait4(A, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fail_wait
    movzbl status+1(%rip), %edi
    cmp $38, %edi
    je 1f
    or $64, %edi
    jmp exit
1:
    mov %r13d, %edi                /* wait4(B, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne fail_wait
    movzbl status+1(%rip), %edi
    cmp $38, %edi
    je 2f
    or $128, %edi
    jmp exit
2:
    mov $7, %edi
    jmp exit

/* take_report: rt_sigtimedwait({SIGUSR1, SIGUSR2}, NULL, 5 s); signo in eax. */
take_report:
    lea usr_set(%rip), %rdi
    xor %esi, %esi
    lea limit(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    test %eax, %eax
    jle fail_report
    ret

child_a:
    xor %edi, %edi                 /* read(0, buf, 0) */
    lea buffer(%rip), %rsi
    xor %edx, %edx
    xor %eax, %eax
    syscall
    mov %rax, %r14
    mov $10, %esi                  /* SIGUSR1 */
    jmp child_report

child_b:
    xor %edi, %edi                 /* lseek(0, 0, SEEK_CUR) */
    xor %esi, %esi
    mov $1, %edx
    mov $8, %eax
    syscall
    mov %rax, %r14
    mov $12, %esi                  /* SIGUSR2 */

child_report:
    mov $110, %eax                 /* getppid */
    mov %esi, %ebx
    syscall
    mov %eax, %edi                 /* kill(parent, report signal) */
    mov %ebx, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz fail_wait
    cmp $12, %ebx
    jne 5f
    mov %r12d, %edi                /* B: kill(A, SIGHUP) */
    mov $1, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz fail_wait
5:
    lea hup_set(%rip), %rdi        /* stay live until the sibling has called */
    xor %esi, %esi
    lea limit(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    test %eax, %eax
    jle child_timeout
    cmp $10, %ebx
    jne 6f
    xor %edi, %edi                 /* A: kill(0, SIGHUP) releases B */
    mov $1, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz fail_wait
6:
    neg %r14
    mov %r14d, %edi
    jmp exit

child_timeout:
    mov $93, %edi
    jmp exit
fail_root_enosys:
    mov $81, %edi
    jmp exit
fail_root_other:
    mov $82, %edi
    jmp exit
fail_report:
    mov $92, %edi
    jmp exit
fail_wait:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
.balign 8
block_set: .quad 0xa01
usr_set: .quad 0xa00
hup_set: .quad 0x1
limit: .quad 5, 0

.section .data
.balign 8
status: .long 0
buffer: .long 0
