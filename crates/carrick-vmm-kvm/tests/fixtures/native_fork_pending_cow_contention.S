/* #2581: a sibling thread write-faults a page its process's fork has
 * write-protected, while that fork's publication is still pending (Go
 * forks from one goroutine while others keep running). The fixture image
 * holds the leader's fork before its commit (INJECT_HOLD_NEXT_FORK_COMMIT)
 * until the worker parks or releases it, so the contention is
 * deterministic: no sleeps.
 *
 * Leader: touch the data page; arm the hold; clone a worker; fork (held);
 * reap the child; join the worker.
 * Worker: poll INJECT_FORK_COMMIT_HELD; write the data page. The write
 * must park on the pending fork's release (never a fatal fault), and land
 * in the parent only: the fork child still reads the old value.
 *
 * FIRST_TOUCH=1: the data page is instead a second mapping nobody touched
 * before the fork, so the worker's write takes the owner's first-touch
 * supply, not COW; the fork child reads zero there. (A first touch of the
 * shared mapping would not do: its window made all four pages resident.)
 *
 * Exit 7: all of that held. 90: the worker's write did not park; 91: the
 * parent lost the worker's write; 92: the fork child saw it; 100 + n: the
 * fork failed with errno n. Other codes name a failed setup step.
 */
#define INJECT_WAIT_PARK_CENSUS         0xfffffffffffffe13
#define INJECT_HOLD_NEXT_FORK_COMMIT    0xfffffffffffffe31
#define INJECT_FORK_COMMIT_HELD         0xfffffffffffffe32
#define INJECT_RELEASE_HELD_FORK_COMMIT 0xfffffffffffffe33
#define POLL_LIMIT                      0x10000000
#ifdef FIRST_TOUCH
#define OLD_VALUE                       0
#else
#define OLD_VALUE                       0x11
#endif
#define NEW_VALUE                       0x22

.global _start
.text
_start:
    /* mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_mmap
    mov %rax, %r12

    /* Shared layout in %r12:
     * +0x00: u32 worker tid / CLEARTID word
     * +0x18: i32 worker ready
     * +0x30: i32 worker result
     * +0x40: timespec join timeout = { 5, 0 }
     * +0x50: i32 fork child wait status
     * +0x58: u64 address of the data page
     * +0x3000: the data page, resident before the fork
     */
    movq $5, 0x40(%r12)
    movq $0, 0x48(%r12)
#ifdef FIRST_TOUCH
    /* The data page: its own mapping, untouched until the worker writes. */
    xor %edi, %edi
    mov $0x1000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_mmap
    mov %rax, 0x58(%r12)
#else
    lea 0x3000(%r12), %rax
    mov %rax, 0x58(%r12)
    movq $OLD_VALUE, (%rax)
#endif

    mov $INJECT_HOLD_NEXT_FORK_COMMIT, %rax
    syscall
    test %rax, %rax
    jnz fail_arm

    /* Worker thread (CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID). */
    mov $0x003d0f00, %edi
    lea 0x2ff0(%r12), %rsi
    mov %r12, %rdx
    mov %r12, %r10
    lea 0x100(%r12), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker

    /* Let the worker start: once it runs, the idle CPU holds one of the
     * two members, so the held fork never starves it of a CPU. */
    mov $POLL_LIMIT, %r13
ready_loop:
    cmpl $0, 0x18(%r12)
    jne ready
    dec %r13
    jz fail_ready
    mov $24, %eax
    syscall
    jmp ready_loop
ready:

    /* The held fork; its child reports what it reads in the data page. */
    mov $57, %eax
    syscall
    test %rax, %rax
    jz fork_child
    js fork_errno
    mov %rax, %r15

    /* wait4(child, &status, 0, NULL) */
    mov %r15, %rdi
    lea 0x50(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail_wait

    /* Join the worker through its CLONE_CHILD_CLEARTID word. */
join_loop:
    mov (%r12), %edx
    test %edx, %edx
    jz joined
    mov %r12, %rdi
    xor %esi, %esi
    lea 0x40(%r12), %r10
    mov $202, %eax
    syscall
    cmp $-110, %rax
    je fail_join
    jmp join_loop
joined:
    mov 0x30(%r12), %edi
    cmp $22, %edi
    jne die
    mov 0x58(%r12), %rcx
    cmpq $NEW_VALUE, (%rcx)
    jne fail_parent_value
    cmpl $0, 0x50(%r12)
    jne fail_child_value
    mov $7, %edi
    jmp die

fork_errno:
    neg %eax
    add $100, %eax
    mov %eax, %edi
    jmp die

fork_child:
    xor %edi, %edi
    mov 0x58(%r12), %rcx
    cmpq $OLD_VALUE, (%rcx)
    je child_exit
    mov $1, %edi
child_exit:
    mov $231, %eax
    syscall
    ud2

worker:
    movl $1, 0x18(%r12)

    mov $POLL_LIMIT, %r13
held_loop:
    mov $INJECT_FORK_COMMIT_HELD, %rax
    syscall
    cmp $1, %rax
    je held
    dec %r13
    jz worker_never_held
    pause
    jmp held_loop
held:
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    mov %rax, %r14

    /* Write the data page while the fork is pending. */
    mov 0x58(%r12), %rcx
    movq $NEW_VALUE, (%rcx)

    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    mov %rax, %rbx
    mov $INJECT_RELEASE_HELD_FORK_COMMIT, %rax
    syscall
    cmp %r14, %rbx
    jbe worker_not_parked
    movl $22, 0x30(%r12)
    jmp worker_exit
worker_not_parked:
    movl $90, 0x30(%r12)
    jmp worker_exit
worker_never_held:
    movl $99, 0x30(%r12)
    mov $INJECT_RELEASE_HELD_FORK_COMMIT, %rax
    syscall
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fail_parent_value:
    mov $91, %edi
    jmp die
fail_child_value:
    mov $92, %edi
    jmp die
fail_mmap:
    mov $81, %edi
    jmp die
fail_wait:
    mov $84, %edi
    jmp die
fail_arm:
    mov $85, %edi
    jmp die
fail_clone:
    mov $86, %edi
    jmp die
fail_ready:
    mov $87, %edi
    jmp die
fail_join:
    mov $88, %edi
die:
    mov $231, %eax
    syscall
    ud2
