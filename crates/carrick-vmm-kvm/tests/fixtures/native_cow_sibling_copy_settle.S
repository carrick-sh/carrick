/* #2716 (review P0): a sibling's kernel copy must not ring the COW
 * settlement crossing for a completion it does not own. The fixture image
 * holds the worker's user-fault COW in the ring after its guest copy and
 * repoint completed and before its settlement crossing
 * (INJECT_HOLD_NEXT_COW_SETTLE), so the interleaving is deterministic: no
 * sleeps. While it is held the MM has one completed grant, and the host
 * holds it as pending on the worker's CPU only.
 *
 * Leader: make two private pages P and Q resident; fork a child that
 * blocks on a pipe (so both stay copy-on-write, two live processes); clone a
 * worker, which parks on its go word (two live threads); arm the hold; wake
 * the worker; poll INJECT_COW_SETTLE_HELD; then write(2) eight bytes from a
 * resident page into a second pipe and read(2) them back into Q; release
 * the hold. The ring prepares a copy only after the direct copy refuses, so
 * the read into Q is the preparation: its first selection finds the pool
 * holding the worker's completion while the leader's CPU has asked the host
 * for nothing yet.
 * Worker: write P (COW fault, held), then settle its own grant.
 *
 * The leader is its CPU's home thread and never yields while it polls; the
 * worker writes only once it runs on the other CPU, so the held COW spins
 * there and never starves the leader.
 *
 * Exit 7: every step held. 91: the worker's write did not land; 92: the
 * worker's go wait timed out; 93: the worker never left the leader's CPU;
 * 100: the hold never engaged; 110: the leader's write(2) did not write
 * eight bytes; 111: its read(2) did not return eight; 112: the bytes read
 * differ, or Q lost its other bytes; 151: the hold reached its bound
 * before the release; 160 + n: the worker exited before the hold engaged,
 * with result n. Other codes name a failed setup step.
 */
#define INJECT_HOLD_NEXT_COW_SETTLE    0xfffffffffffffe22
#define INJECT_COW_SETTLE_HELD         0xfffffffffffffe23
#define INJECT_RELEASE_HELD_COW_SETTLE 0xfffffffffffffe24
#define INJECT_COW_SETTLE_TIMED_OUT    0xfffffffffffffe25
#define INJECT_CURRENT_CPU             0xfffffffffffffe26
#define POLL_LIMIT                     0x1000000

.global _start
.text
_start:
    /* P and Q: mmap(NULL, 0x2000, RW, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0),
     * both resident. */
    xor %edi, %edi
    mov $0x2000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4096, %rax
    jae fail_mmap_p
    mov %rax, %r14
    movq $0x11, (%r14)
    movq $0x22, 0x1000(%r14)

    /* pipe2(fds on the stack, 0): the child blocks on its read end. */
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
    jz child
    mov %eax, %r15d             /* child pid */


    /* Shared layout, mapped after the fork so no write to it is a COW:
     * +0x00: u32 worker tid / CLEARTID word
     * +0x2c: u32 the worker's go word
     * +0x30: i32 worker result
     * +0x34: u32 the leader's CPU
     * +0x38: u32 a word nothing wakes
     * +0x40: timespec timeout = { 5, 0 }
     * +0x50: timespec park = { 0, 1 ms }
     * +0x60: the leader's second pipe (read end, write end)
     * +0x70: eight source bytes */
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
    mov $0x6867666564636261, %rax
    mov %rax, 0x70(%r12)
    lea 0x60(%r12), %rdi        /* pipe2 into the resident shared page */
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe


    /* Worker thread (CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID). The clone returns here once the
     * worker parks on its go word. */
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

    mov $INJECT_HOLD_NEXT_COW_SETTLE, %rax
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

    /* The worker's completion is in the pool and its settlement has not
     * run. The leader's CPU has no grant pending when its copy-out into Q
     * is first prepared. */
    mov 0x64(%r12), %edi
    lea 0x70(%r12), %rsi
    mov $8, %edx
    mov $1, %eax                /* write: a copy-in preparation */
    syscall
    cmp $8, %rax
    jne fail_write
    mov 0x60(%r12), %edi
    lea 0x1008(%r14), %rsi
    mov $8, %edx
    xor %eax, %eax              /* read into Q: a copy-out preparation */
    syscall
    cmp $8, %rax
    jne fail_read
    mov 0x70(%r12), %rax
    cmp %rax, 0x1008(%r14)
    jne fail_bytes
    cmpq $0x22, 0x1000(%r14)
    jne fail_bytes

    mov $INJECT_COW_SETTLE_TIMED_OUT, %rax
    syscall
    test %rax, %rax
    jnz fail_hold_bound
    mov $INJECT_RELEASE_HELD_COW_SETTLE, %rax
    syscall

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
    mov 0x30(%r12), %r13d
    cmp $22, %r13d
    jne worker_failed

    /* Close the write end: the child reads EOF and exits 0. */
    mov %ebp, %edi
    mov $3, %eax
    syscall
    mov %r15d, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail_wait
    mov $7, %edi
    jmp die
worker_failed:
    mov %r13d, %edi
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
     * the leader polls on its own CPU. A bounded park (sched_yield does not
     * switch back to a CPU's queued home thread, see followup) lets the
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
    /* The held COW fault: its own settlement crossing follows the hold. */
    movq $0x55, (%r14)
    cmpq $0x55, (%r14)
    jne worker_bad_write
    movl $22, 0x30(%r12)
    jmp worker_exit
worker_bad_write:
    movl $91, 0x30(%r12)
    jmp worker_exit
worker_go_timeout:
    movl $92, 0x30(%r12)
    jmp worker_exit
worker_stuck:
    movl $93, 0x30(%r12)
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

child:
    mov %ebp, %edi              /* close(write end) */
    mov $3, %eax
    syscall
    mov %ebx, %edi              /* read(read end, &scratch, 1): EOF */
    lea -32(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    xor %edi, %edi
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
fail_write:
    mov $110, %edi
    jmp release_and_die
fail_read:
    mov $111, %edi
    jmp release_and_die
fail_bytes:
    mov $112, %edi
    jmp release_and_die
fail_hold_bound:
    mov $151, %edi
release_and_die:
    mov $INJECT_RELEASE_HELD_COW_SETTLE, %rax
    syscall
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
    mov $89, %edi
die:
    mov $231, %eax
    syscall
    ud2
