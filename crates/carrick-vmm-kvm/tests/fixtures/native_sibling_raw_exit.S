/* #2359: two clone threads of the root raw-exit(2) at the same moment on
 * the two CPUs, 32 rounds. Each was born with CLONE_CHILD_CLEARTID, so its
 * exit writes zero to its child-tid word through the MM owner while its
 * sibling's exit may hold that MM's editor. The root joins both as
 * pthread_join does (FUTEX_WAIT on each CLEARTID word), then starts the next
 * round. Native Linux exits 0.
 *
 * The barrier spins so that two workers on two CPUs leave it together, but
 * only for a bounded count: a worker whose sibling was queued on its own CPU
 * then waits on the barrier word and gives that CPU up. A syscall-free
 * spinner would otherwise keep the sibling off its CPU (#2360), and a
 * sched_yield join would not hand the CPU over (#2354); this witness must
 * not depend on either.
 *
 * -DOWNED_COPY_BUSY_ONCE: worker 1 also arms the test image's
 * INJECT_OWNED_COPY_BUSY_ONCE after the barrier, so one clear-tid copy-out
 * per round is refused Busy once. The root then reads the injected-copy
 * census: every refusal must be followed by a completed rerun of the copy.
 * Exit 3: the census differs.
 *
 * -DOWNED_COPY_PUBLISH_GATE (#2648): one worker, one round. The worker arms
 * the refusal as above and also INJECT_OWNED_COPY_PUBLISH_GATE, which holds
 * its rerun copy-out in the kernel right after the zero reached the CLEARTID
 * word. The root polls INJECT_OWNED_COPY_PUBLISH_HELD, so the word it then
 * reads is the published zero, and reads the census while the copy is held:
 * the refusal's rerun must already be counted, since a joiner that sees the
 * zero may read the census at once. Exit 3: the census differs; 5: the word
 * is not the published zero; 100: the gate never engaged.
 *
 * -DEDITOR_BUSY_ONCE: worker 1 arms INJECT_EDITOR_BUSY_ONCE after the
 * barrier, which holds the next MM editor acquisition until its waiter has
 * parked. A clear-tid copy-out then finds the editor held, so its exit must
 * park on the holder's release and rerun. The root reads the zone's park
 * census at the end. Exit 4: fewer parks than rounds.
 */
#define ROUNDS 32
#define BARRIER_SPINS 0x100000
#define FUTEX_WAIT 0
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define INJECT_OWNED_COPY_BUSY_ONCE 0xfffffffffffffe1b
#define INJECT_OWNED_COPY_CENSUS 0xfffffffffffffe1c
#define INJECT_OWNED_COPY_PUBLISH_GATE 0xfffffffffffffe2e
#define INJECT_OWNED_COPY_PUBLISH_HELD 0xfffffffffffffe2f
#define INJECT_RELEASE_OWNED_COPY_PUBLISH 0xfffffffffffffe30
#define POLL_LIMIT 0x1000000
#define INJECT_EDITOR_BUSY_ONCE 0xfffffffffffffe11
#define INJECT_WAIT_PARK_CENSUS 0xfffffffffffffe13
.global _start
.text
_start:
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov %rax, %r12
    movl $0, 0x08(%r12)
    movl $0, 0x1000(%r12)
    movl $0, 0x2000(%r12)
    movl $0, 0x3000(%r12)
#ifdef OWNED_COPY_PUBLISH_GATE
    jmp gate_main
#endif
    mov $ROUNDS, %r15d
round:
    movl $0, 0x20(%r12)
    mov $1, %ebx
    lea 0x1ff0(%r12), %rsi
    call spawn
    mov $2, %ebx
    lea 0x2ff0(%r12), %rsi
    call spawn
    lea 0x3000(%r12), %rdi
    call join
    lea 0x3004(%r12), %rdi
    call join
    dec %r15d
    jnz round
#ifdef OWNED_COPY_BUSY_ONCE
    movabs $INJECT_OWNED_COPY_CENSUS, %rax
    syscall
    movabs $((ROUNDS << 32) | ROUNDS), %rcx
    cmp %rcx, %rax
    je 8f
    mov $3, %edi
    mov $231, %eax
    syscall
8:
#endif
#ifdef EDITOR_BUSY_ONCE
    movabs $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    cmp $ROUNDS, %rax
    jae 8f
    mov $4, %edi
    mov $231, %eax
    syscall
8:
#endif
    mov $0, %edi
    mov $231, %eax
    syscall
join:
    mov (%rdi), %edx
    test %edx, %edx
    jz 1f
    /* The CLEARTID wake is a shared wake, as glibc's join wait is. */
    mov $FUTEX_WAIT, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp join
1:  ret
spawn:
    mov $0x00350f00, %edi
    lea 0x2ffc(%r12,%rbx,4), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    ret
worker:
    lock incl 0x20(%r12)
2:  mov $BARRIER_SPINS, %ecx
7:  cmpl $2, 0x20(%r12)
    je wexit
    pause
    dec %ecx
    jnz 7b
    lea 0x20(%r12), %rdi
    mov $FUTEX_WAIT_PRIVATE, %esi
    mov $1, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp 2b
wexit:
    lea 0x20(%r12), %rdi
    mov $FUTEX_WAKE_PRIVATE, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
#ifdef OWNED_COPY_BUSY_ONCE
    /* Both workers are past their births: the next exact-MM write is a
     * clear-tid copy-out, not the root's clone output. */
    cmp $1, %ebx
    jne 9f
    movabs $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
9:
#endif
#ifdef EDITOR_BUSY_ONCE
    cmp $1, %ebx
    jne 9f
    movabs $INJECT_EDITOR_BUSY_ONCE, %rax
    syscall
9:
#endif
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

#ifdef OWNED_COPY_PUBLISH_GATE
gate_main:
    mov $0x00350f00, %edi
    lea 0x1ff0(%r12), %rsi
    lea 0x3000(%r12), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz gate_worker
    mov $POLL_LIMIT, %r15d
1:  movabs $INJECT_OWNED_COPY_PUBLISH_HELD, %rax
    syscall
    test %rax, %rax
    jnz 2f
    dec %r15d
    jnz 1b
    mov $100, %edi
    mov $231, %eax
    syscall
2:  mov 0x3000(%r12), %r14d
    movabs $INJECT_OWNED_COPY_CENSUS, %rax
    syscall
    mov %rax, %r13
    movabs $INJECT_RELEASE_OWNED_COPY_PUBLISH, %rax
    syscall
    test %r14d, %r14d
    jz 3f
    mov $5, %edi
    mov $231, %eax
    syscall
3:  movabs $((1 << 32) | 1), %rcx
    cmp %rcx, %r13
    je 4f
    mov $3, %edi
    mov $231, %eax
    syscall
4:  xor %edi, %edi
    mov $231, %eax
    syscall
gate_worker:
    movabs $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
    movabs $INJECT_OWNED_COPY_PUBLISH_GATE, %rax
    syscall
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
#endif
