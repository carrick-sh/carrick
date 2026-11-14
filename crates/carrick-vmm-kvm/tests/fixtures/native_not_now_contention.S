/* #2306: owner contention at a production lifecycle entry is "not now". The
 * call meets contention exactly once and must then complete; it never
 * reaches the guest as an errno. Exit 7 is success; 100 + n reports errno n
 * (111 = EAGAIN, 114 = EFAULT); 90..96 a wrong answer.
 *   FORK_EDITOR    the parent's space editor is held once at fork
 *                  preparation: fork reruns and returns the child's pid
 *   WAITID_BUSY    waitid(P_ALL, WEXITED|WNOHANG) with a live child: its
 *                  empty siginfo copy is Busy once; the call reruns and
 *                  answers 0 with a zeroed siginfo
 *   SETTID_BUSY    fork with CLONE_CHILD_SETTID: the child's tid store is
 *                  Busy once before its first instruction; the child then
 *                  finds its tid stored (the store used to be dropped)
 */
#define INJECT_EDITOR_BUSY_ONCE -495     /* 0x...fe11 */
#define INJECT_OWNED_COPY_BUSY_ONCE -485 /* 0x...fe1b */
#define INJECT_OWNED_COPY_CENSUS -484    /* 0x...fe1c */
#define SIGCHLD 17
#define CLONE_CHILD_SETTID 0x01000000
.global _start
.text
_start:
    /* Make every output page resident in this MM before contention. */
    movq $-1, info(%rip)
    movl $0, status(%rip)
    movl $0, ctid(%rip)
    movl $-1, info+16(%rip)
#if defined(FORK_EDITOR)
    mov $INJECT_EDITOR_BUSY_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_inject
    mov $57, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz exit_child
    mov %rax, %r12
#elif defined(WAITID_BUSY)
    mov $57, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz sleep_child
    mov %rax, %r12
    mov $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_inject
    /* waitid(P_ALL, 0, &info, WEXITED | WNOHANG, NULL) */
    xor %edi, %edi
    xor %esi, %esi
    lea info(%rip), %rdx
    mov $5, %r10d
    xor %r8d, %r8d
    mov $247, %eax
    syscall
    test %rax, %rax
    jnz errno_exit
    /* No child changed state: the kernel zeroes si_signo and si_pid. */
    cmpq $0, info(%rip)
    jne fail_output
    cmpl $0, info+16(%rip)
    jne fail_output
    mov $INJECT_OWNED_COPY_CENSUS, %rax
    syscall
    mov $0x0000000100000000, %rcx
    cmp %rcx, %rax
    jne fail_census
    /* kill(child, SIGKILL) */
    mov %r12, %rdi
    mov $9, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jnz errno_exit
#elif defined(SETTID_BUSY)
    mov $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_inject
    /* clone(SIGCHLD | CLONE_CHILD_SETTID, 0, NULL, &ctid, 0) */
    mov $(SIGCHLD | CLONE_CHILD_SETTID), %edi
    xor %esi, %esi
    xor %edx, %edx
    lea ctid(%rip), %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz settid_child
    mov %rax, %r12
#else
#error "FORK_EDITOR, WAITID_BUSY or SETTID_BUSY"
#endif
    /* wait4(child, &status, 0, NULL) */
    mov %r12, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %rax, %rax
    js errno_exit
    cmp %r12, %rax
    jne fail_pid
    mov status(%rip), %edi
#if defined(WAITID_BUSY)
    cmp $9, %edi
    jne fail_status
    mov $7, %edi
    jmp exit
#else
    test $127, %edi
    jnz fail_status
    shr $8, %edi
#if defined(SETTID_BUSY)
    /* The child's own exit code reports its stored tid; then the census. */
    cmp $7, %edi
    jne exit
    mov $INJECT_OWNED_COPY_CENSUS, %rax
    syscall
    shr $32, %rax
    cmp $1, %rax
    jne fail_census
    mov $7, %edi
#endif
    jmp exit
#endif
exit_child:
    mov $7, %edi
    jmp exit
sleep_child:
    /* nanosleep({30, 0}, NULL): killed long before it expires. */
    lea sleep_time(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    mov $95, %edi
    jmp exit
settid_child:
    mov $186, %eax
    syscall
    cmpl %eax, ctid(%rip)
    jne fail_output
    mov $7, %edi
    jmp exit
errno_exit:
    neg %rax
    lea 100(%rax), %rdi
    jmp exit
fail_inject:
    mov $90, %edi
    jmp exit
fail_pid:
    mov $91, %edi
    jmp exit
fail_output:
    mov $92, %edi
    jmp exit
fail_census:
    mov $93, %edi
    jmp exit
fail_status:
    mov $94, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
.balign 8
sleep_time:
    .quad 30, 0

.bss
.balign 4096
status:
    .skip 8
.balign 64
ctid:
    .skip 8
.balign 64
info:
    .skip 128
