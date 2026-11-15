/* #2359 round 4: a thread clone's CLONE_PARENT_SETTID copy-out refused
 * "not now". The root arms the test image's INJECT_OWNED_COPY_BUSY_ONCE, so
 * the next owned copy-out, the clone's parent-tid word, is refused Busy once.
 * Contention is never an errno: the clone keeps its call and reruns, and
 * the parent sees the child's tid in the word. No CLONE_CHILD_CLEARTID: the
 * child clears its own done word and wakes the parent, so no exit reaches
 * a clear-tid copy-out. Native Linux exits 0 (the inject syscall is ENOSYS
 * there and changes nothing).
 * Exit 100 + errno: the clone failed. Exit 3: the parent-tid word is not
 * the child's tid. Exit 4: the census saw no refusal or no rerun.
 */
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define INJECT_OWNED_COPY_BUSY_ONCE 0xfffffffffffffe1b
#define INJECT_OWNED_COPY_CENSUS 0xfffffffffffffe1c
.global _start
.text
_start:
    xor %edi, %edi
    mov $0x2000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov %rax, %r12
    movl $0x55, 0x0(%r12)
    movl $1, 0x4(%r12)
    movl $0, 0x1000(%r12)
#ifdef INJECT
    movabs $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
#endif
    /* VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID */
    mov $0x00150f00, %edi
    lea 0x1ff0(%r12), %rsi
    mov %r12, %rdx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz child
    jns 1f
    neg %rax
    lea 100(%rax), %rdi
    mov $231, %eax
    syscall
1:  cmp (%r12), %eax
    je join
    mov $3, %edi
    mov $231, %eax
    syscall
join:
    cmpl $0, 0x4(%r12)
    je joined
    lea 0x4(%r12), %rdi
    mov $FUTEX_WAIT_PRIVATE, %esi
    mov $1, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp join
joined:
#ifdef INJECT
    /* The refusal and its completed rerun were both counted. */
    movabs $INJECT_OWNED_COPY_CENSUS, %rax
    syscall
    movabs $((1 << 32) | 1), %rcx
    cmp %rcx, %rax
    je 2f
    mov $4, %edi
    mov $231, %eax
    syscall
2:
#endif
    xor %edi, %edi
    mov $231, %eax
    syscall
child:
    movl $0, 0x4(%r12)
    lea 0x4(%r12), %rdi
    mov $FUTEX_WAKE_PRIVATE, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
