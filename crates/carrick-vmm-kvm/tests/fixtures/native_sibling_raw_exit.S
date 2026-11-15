/* #2359: two clone threads of the root raw-exit(2) at the same moment on
 * the two CPUs, 32 rounds. Each was born with CLONE_CHILD_CLEARTID, so its
 * exit writes zero to its child-tid word through the MM owner while its
 * sibling's exit may hold that MM's editor. The root waits for both words
 * to clear, then starts the next round. Native Linux exits 0.
 *
 * -DOWNED_COPY_BUSY_ONCE: worker 1 also arms the test image's
 * INJECT_OWNED_COPY_BUSY_ONCE before the barrier, so one clear-tid copy-out
 * per round is refused Busy once. The root then reads the injected-copy
 * census: every refusal must be followed by a completed rerun of the copy.
 * Exit 3: the census differs.
 */
#define ROUNDS 32
#define INJECT_OWNED_COPY_BUSY_ONCE 0xfffffffffffffe1b
#define INJECT_OWNED_COPY_CENSUS 0xfffffffffffffe1c
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
    mov $ROUNDS, %r15d
round:
    movl $0, 0x20(%r12)
    mov $1, %ebx
    lea 0x1ff0(%r12), %rsi
    call spawn
    mov $2, %ebx
    lea 0x2ff0(%r12), %rsi
    call spawn
5:  mov 0x3000(%r12), %eax
    or 0x3004(%r12), %eax
    jz 6f
    mov $24, %eax
    syscall
    jmp 5b
6:  dec %r15d
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
    mov $0, %edi
    mov $231, %eax
    syscall
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
#ifdef OWNED_COPY_BUSY_ONCE
    cmp $1, %ebx
    jne 9f
    movabs $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
9:
#endif
    lock incl 0x20(%r12)
7:  cmpl $2, 0x20(%r12)
    je wexit
    pause
    jmp 7b
wexit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
