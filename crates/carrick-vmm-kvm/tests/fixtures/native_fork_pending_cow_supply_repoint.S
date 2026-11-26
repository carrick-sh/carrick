/* #2923: a sibling's copy-on-write admitted before a fork selects its
 * parent's frames must not repoint a selected leaf while that fork is
 * pending. The carrier checks every inherited frame against the parent's
 * live leaf after the fork's publication; a leaf a sibling repointed in
 * between no longer names the selected storage, and the carrier died with
 * "selected source does not name retained storage" (Go forks from one
 * goroutine while others keep writing).
 *
 * The fixture image orders it on events, with no sleeps:
 *  - INJECT_HOLD_NEXT_COW_SUPPLY holds the worker's COW fault in the ring
 *    after the carrier supplied its replacement grant, before it resolves:
 *    the grant is ready in the MM's pool, and the leaf is still the old one.
 *  - INJECT_HOLD_NEXT_FORK_COMMIT holds the leader's fork after its parent
 *    root is published fork-pending, before the carrier checks the
 *    inherited frames; INJECT_FORK_COMMIT_RELEASES_SUPPLY makes that hold
 *    release the worker, so its resolution runs while the fork is pending.
 *  - The fork hold ends on the first real event of the two: the worker
 *    parks (it registered with INJECT_REGISTER_FORK_COMMIT_WAITER), or the
 *    worker's COW completes under the pending fork.
 *    INJECT_FORK_COMMIT_RELEASE_CAUSE says which.
 *
 * Leader: make the private page P resident; fork child 1, which blocks on
 * a pipe (so P is copy-on-write, two live processes); clone a worker,
 * which parks on its go word (two live threads); arm both holds; wake the
 * worker; poll INJECT_COW_SETTLE_HELD; fork child 2 (held); reap child 2;
 * read the release cause; join the worker; reap child 1.
 * Worker: leave the leader's CPU; register as the fork's waiter; write P
 * (held after its supply, then released by the fork's hold).
 * Children: each reads P's value from before the worker's write.
 *
 * Exit 7: the worker waited for the fork, and every value held. 91: the
 * parent lost the worker's write; 92: child 2 saw the wrong value; 93:
 * child 1 saw the wrong value; 94: the worker's go wait timed out; 95: the
 * worker never left the leader's CPU; 100: the supply hold never engaged;
 * 120 + n: the fork's hold ended for cause n, not the worker's park (2:
 * the worker's COW completed while the fork was pending); 151: the supply
 * hold reached its bound; 160 + n: the worker exited before the hold
 * engaged, with result n. Other codes name a failed setup step.
 */
#define INJECT_COW_SETTLE_HELD             0xfffffffffffffe23
#define INJECT_RELEASE_HELD_COW_SETTLE     0xfffffffffffffe24
#define INJECT_COW_SETTLE_TIMED_OUT        0xfffffffffffffe25
#define INJECT_CURRENT_CPU                 0xfffffffffffffe26
#define INJECT_HOLD_NEXT_FORK_COMMIT       0xfffffffffffffe31
#define INJECT_RELEASE_HELD_FORK_COMMIT    0xfffffffffffffe33
#define INJECT_HOLD_NEXT_COW_SUPPLY        0xfffffffffffffe47
#define INJECT_FORK_COMMIT_RELEASES_SUPPLY 0xfffffffffffffe48
#define INJECT_REGISTER_FORK_COMMIT_WAITER 0xfffffffffffffe49
#define INJECT_FORK_COMMIT_RELEASE_CAUSE   0xfffffffffffffe4a
#define POLL_LIMIT                         0x1000000
#define OLD_VALUE                          0x11
#define NEW_VALUE                          0x55

.global _start
.text
_start:
    /* P: mmap(NULL, 0x1000, RW, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0), resident. */
    xor %edi, %edi
    mov $0x1000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4096, %rax
    jae fail_mmap_p
    mov %rax, %r14
    movq $OLD_VALUE, (%r14)

    /* pipe2(fds on the stack, 0): child 1 blocks on its read end. */
    lea -16(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe
    movl -16(%rsp), %ebx        /* read end */
    movl -12(%rsp), %ebp        /* write end */

    mov $57, %eax
    syscall
    test %eax, %eax
    js fail_fork
    jz first_child
    mov %eax, %r15d             /* child 1's pid */

    /* Shared layout, mapped after the first fork so no write to it is a COW:
     * +0x00: u32 worker tid / CLEARTID word
     * +0x2c: u32 the worker's go word
     * +0x30: i32 worker result
     * +0x34: u32 the leader's CPU
     * +0x38: u32 a word nothing wakes
     * +0x40: timespec timeout = { 5, 0 }
     * +0x50: timespec park = { 0, 1 ms }
     * +0x60: i32 child 2's wait status
     * +0x64: i32 child 1's wait status */
    xor %edi, %edi
    mov $0x3000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4096, %rax
    jae fail_mmap_shared
    mov %rax, %r12
    movq $5, 0x40(%r12)
    movq $0, 0x48(%r12)
    movq $0, 0x50(%r12)
    movq $1000000, 0x58(%r12)

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

    mov $INJECT_CURRENT_CPU, %rax
    syscall
    mov %eax, 0x34(%r12)

    mov $INJECT_HOLD_NEXT_COW_SUPPLY, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
    mov $INJECT_HOLD_NEXT_FORK_COMMIT, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
    mov $INJECT_FORK_COMMIT_RELEASES_SUPPLY, %rax
    syscall
    test %rax, %rax
    jnz fail_arm

    /* futex(&go, FUTEX_WAKE_PRIVATE, 1): the worker writes P. */
    movl $1, 0x2c(%r12)
    lea 0x2c(%r12), %rdi
    mov $129, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
    test %rax, %rax
    js fail_wake

    mov $POLL_LIMIT, %r13
held_loop:
    mov $INJECT_COW_SETTLE_HELD, %rax
    syscall
    cmp $1, %rax
    je held
    cmpl $0, (%r12)             /* the worker exited unheld: report it */
    je worker_gone
    dec %r13
    jz never_held
    pause
    jmp held_loop
held:

    /* The worker's supplied grant is ready in the pool, and P's leaf still
     * names the frame child 1 shares. This fork selects that frame; its
     * hold, after publication, releases the worker. */
    mov $57, %eax
    syscall
    test %rax, %rax
    jz second_child
    js fork_errno
    mov %rax, %r13              /* child 2's pid */

    /* wait4(child 2, &status, 0, NULL) */
    mov %r13, %rdi
    lea 0x60(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13, %rax
    jne fail_wait

    mov $INJECT_FORK_COMMIT_RELEASE_CAUSE, %rax
    syscall
    mov %rax, %r13

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
    cmp $1, %r13
    jne wrong_cause
    mov 0x30(%r12), %edi
    cmp $22, %edi
    jne die
    mov $INJECT_COW_SETTLE_TIMED_OUT, %rax
    syscall
    test %rax, %rax
    jnz fail_hold_bound
    cmpq $NEW_VALUE, (%r14)
    jne fail_parent_value
    cmpl $0, 0x60(%r12)
    jne fail_second_child

    /* Close the write end: child 1 reads EOF, checks P and exits. */
    mov %ebp, %edi
    mov $3, %eax
    syscall
    mov %r15d, %edi
    lea 0x64(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail_wait
    cmpl $0, 0x64(%r12)
    jne fail_first_child
    mov $7, %edi
    jmp die

wrong_cause:
    lea 120(%r13), %edi
    jmp die

fork_errno:
    mov $INJECT_RELEASE_HELD_COW_SETTLE, %rax
    syscall
    mov $89, %edi
    jmp die

worker:
    /* futex(&go, FUTEX_WAIT_PRIVATE, 0, {5, 0}) until the leader arms. */
go_loop:
    cmpl $0, 0x2c(%r12)
    jne go
    lea 0x2c(%r12), %rdi
    mov $128, %esi
    xor %edx, %edx
    lea 0x40(%r12), %r10
    mov $202, %eax
    syscall
    cmp $-110, %rax
    je worker_go_timeout
    jmp go_loop
go:
    /* Leave the leader's CPU first: the held COW spins where it runs, and
     * the leader polls and forks on its own CPU. A bounded park lets the
     * leader run on; this worker's wake then goes to the idle CPU. */
    mov $0x1000, %r13
off_loop:
    mov $INJECT_CURRENT_CPU, %rax
    syscall
    cmp 0x34(%r12), %eax
    jne off
    dec %r13
    jz worker_stuck
    lea 0x38(%r12), %rdi        /* futex(&never, FUTEX_WAIT_PRIVATE, 0, 1 ms) */
    mov $128, %esi
    xor %edx, %edx
    lea 0x50(%r12), %r10
    mov $202, %eax
    syscall
    jmp off_loop
off:
    /* A park from here on is the wait the pending fork owes this write. */
    mov $INJECT_REGISTER_FORK_COMMIT_WAITER, %rax
    syscall
    test %rax, %rax
    jnz worker_arm
    /* The COW fault: held after its supply, released by the fork's hold. */
    movq $NEW_VALUE, (%r14)
    cmpq $NEW_VALUE, (%r14)
    jne worker_bad_write
    movl $22, 0x30(%r12)
    jmp worker_exit
worker_bad_write:
    movl $91, 0x30(%r12)
    jmp worker_exit
worker_go_timeout:
    movl $94, 0x30(%r12)
    jmp worker_exit
worker_stuck:
    movl $95, 0x30(%r12)
    jmp worker_exit
worker_arm:
    movl $85, 0x30(%r12)
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

second_child:
    xor %edi, %edi
    cmpq $OLD_VALUE, (%r14)
    je second_exit
    mov $1, %edi
second_exit:
    mov $231, %eax
    syscall
    ud2

first_child:
    mov %ebp, %edi              /* close(write end) */
    mov $3, %eax
    syscall
    mov %ebx, %edi              /* read(read end, &scratch, 1): EOF */
    lea -32(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    xor %edi, %edi
    cmpq $OLD_VALUE, (%r14)
    je first_exit
    mov $1, %edi
first_exit:
    mov $231, %eax
    syscall
    ud2

worker_gone:
    mov $INJECT_RELEASE_HELD_COW_SETTLE, %rax
    syscall
    mov 0x30(%r12), %edi
    add $160, %edi
    jmp die
never_held:
    mov $INJECT_RELEASE_HELD_COW_SETTLE, %rax
    syscall
    mov $100, %edi
    jmp die
fail_hold_bound:
    mov $151, %edi
    jmp die
fail_parent_value:
    mov $91, %edi
    jmp die
fail_second_child:
    mov $92, %edi
    jmp die
fail_first_child:
    mov $93, %edi
    jmp die
fail_mmap_p:
    mov $81, %edi
    jmp die
fail_pipe:
    mov $82, %edi
    jmp die
fail_fork:
    mov $83, %edi
    jmp die
fail_mmap_shared:
    mov $84, %edi
    jmp die
fail_arm:
    mov $85, %edi
    jmp die
fail_clone:
    mov $86, %edi
    jmp die
fail_wake:
    mov $87, %edi
    jmp die
fail_join:
    mov $88, %edi
    jmp die
fail_wait:
    mov $90, %edi
die:
    mov $231, %eax
    syscall
    ud2
