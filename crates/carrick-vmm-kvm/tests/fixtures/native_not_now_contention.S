/* #2306: owner contention at a production lifecycle entry is "not now". The
 * call meets contention exactly once and must then complete; it never
 * reaches the guest as an errno. Exit 7 is success; 100 + n reports errno n
 * (111 = EAGAIN, 114 = EFAULT); 90..96 a wrong answer.
 *   FORK_EDITOR    the parent's space editor is held once at fork
 *                  preparation: fork reruns and returns the child's pid
 *   FORK_CENSUS_ROOT  the reservation root is held once while fork counts
 *                  the parent's mappings: fork reruns, returns the child's
 *                  pid, and exactly one acquisition was refused
 *   FORK_COMMIT_ROOT  as above, while fork commits the child's MM
 *   WAITID_BUSY    waitid(P_ALL, WEXITED|WNOHANG) with a live child: its
 *                  empty siginfo copy is Busy once; the call reruns and
 *                  answers 0 with a zeroed siginfo
 *   SETTID_BUSY    fork with CLONE_CHILD_SETTID: the child's tid store is
 *                  Busy once before its first instruction; the child then
 *                  finds its tid stored (the store used to be dropped)
 *   ENTROPY_SETTLED_BEFORE_PARK  #2416: the child's getrandom into a COW
 *                  page finds its space editor held, and the holder
 *                  releases it before the child enrolls on the owner wait.
 *                  The wait settles inline; getrandom restarts and returns
 *                  8, the parent's page keeps its bytes, and exactly one
 *                  wait was released before its park
 *   FORK_LOAN_INVENTORY  #2441: the carrier refuses the next fork's stock
 *                  loan Inventory once: fork reruns and returns the
 *                  child's pid, never EAGAIN (111)
 *   FORK_LOAN_STALE  #2441: the carrier refuses the next fork's stock loan
 *                  Stale, a broken invariant: the run ends at the fork,
 *                  which must never return (EAGAIN 111 formerly)
 *   FORK_SCRATCH_EXHAUSTED  #2441: not contention but its counterpart. The
 *                  next fork's scratch finds the kernel heap exhausted:
 *                  fork answers ENOMEM (-12), never EFAULT (114). That
 *                  refusal returned its loan, so the next fork succeeds
 */
#define INJECT_EDITOR_BUSY_ONCE -495     /* 0x...fe11 */
#define INJECT_OWNED_COPY_BUSY_ONCE -485 /* 0x...fe1b */
#define INJECT_OWNED_COPY_CENSUS -484    /* 0x...fe1c */
#define INJECT_FORK_CENSUS_ROOT_HELD_ONCE -473 /* 0x...fe27 */
#define INJECT_FORK_COMMIT_ROOT_HELD_ONCE -472 /* 0x...fe28 */
#define INJECT_FORK_ROOT_HOLD_CENSUS -471      /* 0x...fe29 */
#define INJECT_EDITOR_RELEASED_BEFORE_PARK_ONCE -468   /* 0x...fe2c */
#define INJECT_EDITOR_RELEASED_BEFORE_PARK_CENSUS -467 /* 0x...fe2d */
#define INJECT_FORK_SCRATCH_EXHAUSTED_ONCE -466 /* 0x...fe2e */
#define INJECT_FORK_LOAN_INVENTORY_ONCE -461 /* 0x...fe33 */
#define INJECT_FORK_LOAN_STALE_ONCE -460     /* 0x...fe34 */
#define ENOMEM 12
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
#elif defined(FORK_CENSUS_ROOT) || defined(FORK_COMMIT_ROOT)
#if defined(FORK_CENSUS_ROOT)
    mov $INJECT_FORK_CENSUS_ROOT_HELD_ONCE, %rax
#else
    mov $INJECT_FORK_COMMIT_ROOT_HELD_ONCE, %rax
#endif
    syscall
    test %rax, %rax
    jnz fail_inject
    mov $57, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz exit_child
    mov %rax, %r12
#elif defined(FORK_LOAN_INVENTORY) || defined(FORK_LOAN_STALE)
#if defined(FORK_LOAN_INVENTORY)
    mov $INJECT_FORK_LOAN_INVENTORY_ONCE, %rax
#else
    mov $INJECT_FORK_LOAN_STALE_ONCE, %rax
#endif
    syscall
    test %rax, %rax
    jnz fail_inject
    mov $57, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz exit_child
    mov %rax, %r12
#elif defined(FORK_SCRATCH_EXHAUSTED)
    mov $INJECT_FORK_SCRATCH_EXHAUSTED_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_inject
    mov $57, %eax
    syscall
    cmp $-ENOMEM, %rax
    jne scratch_not_enomem
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
#elif defined(ENTROPY_SETTLED_BEFORE_PARK)
    /* Resident here before fork, so the child's write is a COW edit. */
    movq $0x12345678, entropy_buffer(%rip)
    mov $57, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz entropy_child
    mov %rax, %r12
#else
#error "FORK_EDITOR, FORK_CENSUS_ROOT, FORK_COMMIT_ROOT, FORK_LOAN_INVENTORY, FORK_LOAN_STALE, FORK_SCRATCH_EXHAUSTED, WAITID_BUSY, SETTID_BUSY or ENTROPY_SETTLED_BEFORE_PARK"
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
#elif defined(FORK_CENSUS_ROOT) || defined(FORK_COMMIT_ROOT)
    /* The child exited 7; the hold refused exactly one acquisition. */
    cmp $7, %edi
    jne exit
    mov $INJECT_FORK_ROOT_HOLD_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_census
#elif defined(ENTROPY_SETTLED_BEFORE_PARK)
    /* The child exited 7; its random bytes went to its own copy. */
    cmp $7, %edi
    jne exit
    cmpq $0x12345678, entropy_buffer(%rip)
    jne fail_output
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
entropy_child:
    mov $INJECT_EDITOR_RELEASED_BEFORE_PARK_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_inject
    /* getrandom(entropy_buffer, 8, 0) */
    lea entropy_buffer(%rip), %rdi
    mov $8, %esi
    xor %edx, %edx
    mov $318, %eax
    syscall
    test %rax, %rax
    js errno_exit
    cmp $8, %rax
    jne fail_output
    mov $INJECT_EDITOR_RELEASED_BEFORE_PARK_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_census
    mov $7, %edi
    jmp exit
settid_child:
    mov $186, %eax
    syscall
    cmpl %eax, ctid(%rip)
    jne fail_output
    mov $7, %edi
    jmp exit
scratch_not_enomem:
    /* The refused fork's answer: an errno, or a child that must not exist. */
    test %rax, %rax
    js errno_exit
    jz exit_child
    mov $91, %edi
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

.data
.balign 4096
entropy_buffer:
    .quad 0
