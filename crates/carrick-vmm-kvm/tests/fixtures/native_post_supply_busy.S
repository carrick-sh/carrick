/* #2141: an owner fault meets MM contention after its physical supply
 * crossing returned, before the guest applied the supplied grant. Every
 * faulting store writes AL with RAX holding a canary; the rerun must leave
 * RAX and the stored byte intact. The root exits 7 on success, 91 on a
 * failed check, 92 on a clobbered canary, 93 when the census shows the
 * injected Busy did not land after the expected supply, and 100 + n when
 * its child exited n.
 *   POST_SUPPLY_COW        the root's COW write parks after its COW supply;
 *                          its fork child, a second live member, takes its
 *                          own COW grant while the root's fault is parked
 *                          (on the root's CPU when both are pinned to CPU
 *                          0), then releases the root's held contention
 *   POST_SUPPLY_EXIT_GROUP a fork child's worker thread parks after its COW
 *                          supply and the child's main thread calls
 *                          exit_group before the worker reruns (a rerun
 *                          that won ends the child with 6, read as 106);
 *                          the root then needs a COW grant
 *   POST_SUPPLY_RAW_EXIT   as above, but the main thread raw-exits (a
 *                          non-last exit); the parked worker reruns its
 *                          store and exits the child
 *   POST_SUPPLY_PREPARE    the root's first touch of fresh anonymous memory
 *                          parks after its Prepare supply; its fork child
 *                          is a second live member touching its own memory
 */
#define INJECT_POST_SUPPLY_BUSY_ONCE -478 /* 0x...fe22 */
#define INJECT_POST_SUPPLY_CENSUS -477    /* 0x...fe23 */
#define INJECT_POST_SUPPLY_BUSY_HELD -476 /* 0x...fe24 */
#define INJECT_RELEASE_POST_SUPPLY_HOLD -475 /* 0x...fe25 */
#define CANARY 0x1122334455667788
#define CHILD_STATUS 5
#define WORKER_STATUS 6
.global _start
.text
_start:
    /* Commit the private .data page before fork, so a later write is COW. */
    movb $1, cow_page(%rip)
#if defined(POST_SUPPLY_PREPARE)
    /* mmap(NULL, 1 MiB, RW, PRIVATE|ANONYMOUS, -1, 0), untouched. */
    xor %edi, %edi
    mov $0x100000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    lea 0x80000(%rax), %rbx
#endif
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
#if defined(POST_SUPPLY_COW) || defined(POST_SUPPLY_PREPARE)
#if defined(POST_SUPPLY_COW)
    lea cow_page(%rip), %rbx
#endif
    call faulting_store
    mov $INJECT_POST_SUPPLY_CENSUS, %rax
    syscall
#if defined(POST_SUPPLY_COW)
    movabs $(1 << 32), %rcx
#else
    mov $1, %ecx
#endif
    cmp %rcx, %rax
    jne census_failure
    call wait_child
#else
    /* The child's worker parked after its supply and the child ended. */
    call wait_child
    mov $INJECT_POST_SUPPLY_CENSUS, %rax
    syscall
    movabs $(1 << 32), %rcx
    cmp %rcx, %rax
    jne census_failure
    /* The root's own COW write needs a grant on the parked worker's CPU. */
    lea cow_page(%rip), %rbx
    movb $0x44, 16(%rbx)
    cmpb $0x44, 16(%rbx)
    jne failure
#endif
    mov $7, %edi
    jmp exit

child:
#if defined(POST_SUPPLY_COW)
    /* Yield until the root's COW write met its held post-supply Busy, so
     * this second member's own COW grant lands while the root's fault is
     * parked (on the root's CPU when both are pinned to CPU 0). */
    call await_post_supply_busy
    /* The root's write is not visible to this copy. */
    lea cow_page(%rip), %rbx
    movb $0x33, 8(%rbx)
    cmpb $0x33, 8(%rbx)
    jne failure
    cmpb $1, (%rbx)
    jne failure
    /* Only now release the root's holder: its fault reruns. */
    mov $INJECT_RELEASE_POST_SUPPLY_HOLD, %rax
    syscall
    cmp $1, %rax
    jne failure
    mov $CHILD_STATUS, %edi
    jmp exit
#elif defined(POST_SUPPLY_PREPARE)
    /* A second member's own first touch of its copy of the mapping. */
    movb $0x33, 0x1000(%rbx)
    cmpb $0x33, 0x1000(%rbx)
    jne failure
    mov $CHILD_STATUS, %edi
    jmp exit
#else
    /* Break this copy's stack COW before the worker exists: the witness is
     * the parked worker's exit custody, not a second concurrent COW supply
     * of this MM (followup-2: that host crossing is still fatal on Busy). */
    push %rax
    pop %rax
    /* glibc's thread flags: VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID. */
    mov $0x3d0f00, %edi
    lea thread_stack_top(%rip), %rsi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    lea tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
    /* Yield until the worker's COW write met its post-supply Busy: the
     * worker then parked, and its wake queued it behind this thread. */
    call await_post_supply_busy
#if defined(POST_SUPPLY_EXIT_GROUP)
    /* exit_group with the worker parked. */
    mov $CHILD_STATUS, %edi
    jmp exit
#else
    /* A non-last raw exit; the parked worker ends the child. */
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
#endif
worker:
    lea cow_page(%rip), %rbx
    call faulting_store
#if defined(POST_SUPPLY_EXIT_GROUP)
    /* Only a rerun that beat the main thread's exit_group gets here. */
    mov $WORKER_STATUS, %edi
#else
    mov $CHILD_STATUS, %edi
#endif
    jmp exit
#endif

/* Arm the post-supply Busy, then store AL at (%rbx) with RAX a canary. In
 * POST_SUPPLY_COW its holder stays held until the child releases it. */
faulting_store:
#if defined(POST_SUPPLY_COW)
    mov $INJECT_POST_SUPPLY_BUSY_HELD, %rax
#else
    mov $INJECT_POST_SUPPLY_BUSY_ONCE, %rax
#endif
    syscall
    test %rax, %rax
    jnz failure
    movabs $CANARY, %rax
    mov %al, (%rbx)
    movabs $CANARY, %rcx
    cmp %rcx, %rax
    jne canary_failure
    cmpb $0x88, (%rbx)
    jne failure
    ret

/* sched_yield until the injected post-supply Busy has landed (bounded). */
await_post_supply_busy:
    mov $1000, %r13d
1:
    dec %r13d
    jz census_failure
    mov $24, %eax
    syscall
    mov $INJECT_POST_SUPPLY_CENSUS, %rax
    syscall
    test %rax, %rax
    jz 1b
    ret

wait_child:
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov status(%rip), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    cmp $CHILD_STATUS, %edi
    je 1f
    add $100, %edi
    jmp exit
1:
    ret
canary_failure:
    mov $92, %edi
    jmp exit
census_failure:
    mov $93, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

/* Private file-backed storage: every page is COW after fork. */
.data
.balign 4096
cow_page: .byte 0
.balign 4096
/* Ordinary zero-fill ELF storage. */
.bss
.balign 4096
status: .space 8
parent_tid: .space 8
child_tid: .space 8
tls: .space 256
.balign 16
thread_stack: .space 16384
thread_stack_top:
