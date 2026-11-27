/* #3082 (pre-review P0-1): a kernel copy into user memory that meets its
 * MM's editor held at the COW settlement crossing waits for that editor's
 * release, then completes: it does not rerun a bare "Busy" as carrier work
 * while the holder keeps the editor.
 *
 * Every step is ordered on an event, never on timing: the worker's
 * user-fault COW is held in the ring after its guest copy and repoint and
 * before its settlement crossing until the leader releases it
 * (INJECT_HOLD_NEXT_COW_SETTLE_UNTIL_RELEASED), so the MM has a completion
 * the carrier has not settled when the leader's read(2) copies into Q; the
 * image holds the MM's real editor across that copy's first settlement
 * crossing (INJECT_HOLD_EDITOR_AT_COPY_COW_SETTLE) and drops it through
 * the editor's own release only once the reading leader is parked. Polls
 * and futex waits have no bound and no deadline: the test's watchdog
 * bounds a run that hangs. No sleeps.
 *
 * Leader: make two private pages P and Q resident; fork a child that blocks
 * on a pipe (so both stay copy-on-write, two live processes); clone a
 * worker, which parks on its go word (two live threads); arm the COW hold;
 * wake the worker; poll INJECT_COW_SETTLE_HELD; write eight bytes into a
 * second pipe; arm the editor hold; read(2) them back into Q (its first
 * write in the parent, so the copy needs COW supply and rings the
 * settlement); check the count and the bytes; read the census; release the
 * COW hold; join the worker; reap the child.
 * Worker: leave the leader's CPU, write P (COW fault, held), then settle its
 * own grant.
 *
 * Exit 7: every step held. 91: the worker's write did not land; 110: the
 * write(2) did not write eight bytes; 111: the read(2) did not return
 * eight (zero included); 112: the bytes read differ, or Q lost its other
 * bytes; 120: the editor hold could not be armed; 121: the copy never met
 * the held editor; 122: the held editor was not released with the copy
 * parked on it; 123: the copy met the held editor more than once (it
 * reran as bare carrier work instead of waiting for the release); 160 + n: the worker exited before the hold engaged, with
 * result n. Other codes name a failed setup step.
 */
#define INJECT_HOLD_EDITOR_AT_COPY_COW_SETTLE 0xfffffffffffffe37
#define INJECT_COPY_COW_EDITOR_HELD_CENSUS 0xfffffffffffffe38
#define INJECT_FORK_COW_SETTLE_CENSUS  0xfffffffffffffe35
#define INJECT_HOLD_NEXT_COW_SETTLE_UNTIL_RELEASED 0xfffffffffffffe36
#define INJECT_COW_SETTLE_HELD         0xfffffffffffffe23
#define INJECT_RELEASE_HELD_COW_SETTLE 0xfffffffffffffe24
#define INJECT_CURRENT_CPU             0xfffffffffffffe26

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
    movq $0x33, 0x1010(%r14)

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

    mov $INJECT_HOLD_NEXT_COW_SETTLE_UNTIL_RELEASED, %rax
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

    /* No poll bound: the test's watchdog bounds a run that never holds. */
held_loop:
    mov $INJECT_COW_SETTLE_HELD, %rax
    syscall
    cmp $1, %rax
    je held
    cmpl $0, (%r12)             /* the worker exited unheld: report it */
    je worker_gone
    pause
    jmp held_loop
held:

    /* The worker's completion is in the pool and its settlement has not
     * run: the read's copy into Q finds the MM unsettled. */
    mov 0x64(%r12), %edi
    lea 0x70(%r12), %rsi
    mov $8, %edx
    mov $1, %eax
    syscall
    cmp $8, %rax
    jne fail_write
    mov $INJECT_HOLD_EDITOR_AT_COPY_COW_SETTLE, %rax
    syscall
    test %rax, %rax
    jnz fail_arm_editor
    mov 0x60(%r12), %edi
    lea 0x1008(%r14), %rsi
    mov $8, %edx
    xor %eax, %eax
    syscall
    cmp $8, %rax
    jne fail_read
    mov 0x70(%r12), %rax
    cmp %rax, 0x1008(%r14)
    jne fail_bytes
    cmpq $0x22, 0x1000(%r14)
    jne fail_bytes
    cmpq $0x33, 0x1010(%r14)
    jne fail_bytes

    mov $INJECT_FORK_COW_SETTLE_CENSUS, %rax
    syscall
    mov %rax, %rcx
    shr $32, %rcx
    and $0xffff, %ecx
    cmp $1, %ecx
    jne fail_never_waited
    mov %rax, %rcx
    shr $16, %rcx
    and $0xffff, %ecx
    cmp $1, %ecx
    jne fail_not_parked
    mov $INJECT_COPY_COW_EDITOR_HELD_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_reran

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
    jmp join_loop               /* a timeout only re-checks the word */
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
    jmp go_loop                 /* a timeout only re-checks the word */
go:
    /* Leave the leader's CPU first: the held COW spins where it runs, and
     * the leader polls on its own CPU. A bounded park (sched_yield does not
     * switch back to a CPU's queued home thread, see followup) lets the
     * leader run on; this worker's wake then goes to the idle CPU. */
off_loop:
    mov $INJECT_CURRENT_CPU, %rax
    syscall
    cmp 0x34(%r12), %eax
    jne off
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
fail_arm_editor:
    mov $120, %edi
    jmp release_and_die
fail_never_waited:
    mov $121, %edi
    jmp release_and_die
fail_not_parked:
    mov $122, %edi
    jmp release_and_die
fail_reran:
    mov $123, %edi
    jmp release_and_die
fail_write:
    mov $110, %edi
    jmp release_and_die
fail_read:
    mov $111, %edi
    jmp release_and_die
fail_bytes:
    mov $112, %edi
    jmp release_and_die
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
fail_wait:
    mov $89, %edi
die:
    mov $231, %eax
    syscall
    ud2
