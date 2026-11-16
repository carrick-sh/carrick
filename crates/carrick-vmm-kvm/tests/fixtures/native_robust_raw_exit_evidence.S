/* #2109: a clone thread born as glibc starts one (CLONE_CHILD_CLEARTID)
 * registers a robust list, as glibc does for every thread, and ends with a
 * raw exit(2) while the root stays live. The root joins it as pthread_join
 * does (FUTEX_WAIT on its CLEARTID word), ROUNDS times. Native Linux exits 0.
 *
 * -DTWO_LIVE: a robust-registered sibling is also live. It waits on a gate
 * word while the first worker exits; the root checks it is still live after
 * the join, opens the gate, and joins it in turn: two live threads, then a
 * non-last thread's raw exit twice over.
 *
 * Exit 2: set_robust_list failed. Exit 5: the sibling was gone after the
 * first worker's join. Exit 100 + errno: a clone failed.
 */
#define ROUNDS 8
#define FUTEX_WAIT 0
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
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
    /* Touch the CLEARTID words' page first: on x86 a thread clone whose
     * parent tid word lies on an untouched anonymous page fails with ENOSYS,
     * which this witness does not cover. */
#ifndef UNTOUCHED
    movl $0, 0x3000(%r12)
#endif
    mov $ROUNDS, %r15d
round:
    movl $0, 0x24(%r12)
    mov $1, %ebx
    lea 0x1ff0(%r12), %rsi
    call spawn
#ifdef TWO_LIVE
    mov $2, %ebx
    lea 0x2ff0(%r12), %rsi
    call spawn
#endif
    lea 0x3000(%r12), %rdi
    call join
#ifdef TWO_LIVE
    /* The sibling stays parked on the gate: its CLEARTID word still names it. */
    cmpl $0, 0x3004(%r12)
    jne 3f
    mov $5, %edi
    mov $231, %eax
    syscall
3:  movl $1, 0x24(%r12)
    lea 0x24(%r12), %rdi
    mov $FUTEX_WAKE_PRIVATE, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
    lea 0x3004(%r12), %rdi
    call join
#endif
    dec %r15d
    jnz round
    xor %edi, %edi
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
    /* glibc's thread flags without CLONE_SETTLS: VM, FS, FILES, SIGHAND,
     * THREAD, SYSVSEM, PARENT_SETTID, CHILD_CLEARTID. */
    mov $0x00350f00, %edi
    lea 0x2ffc(%r12,%rbx,4), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js 1f
    ret
    /* A failed clone exits 100 + errno. */
1:  neg %rax
    lea 100(%rax), %rdi
    mov $231, %eax
    syscall
worker:
#ifndef NO_ROBUST
    /* An empty robust_list_head (list.next points at itself), as glibc's
     * thread start registers. */
    mov %rbx, %rdi
    shl $5, %rdi
    lea 0x40(%r12,%rdi), %rdi
    mov %rdi, (%rdi)
    movq $0, 8(%rdi)
    movq $0, 16(%rdi)
    mov $24, %esi
    mov $273, %eax
    syscall
    test %rax, %rax
    jz 4f
    mov $2, %edi
    mov $231, %eax
    syscall
#endif
4:
#ifdef TWO_LIVE
    cmp $2, %ebx
    jne wexit
    /* The sibling waits, live, until the root has joined worker 1. */
5:  cmpl $0, 0x24(%r12)
    jne wexit
    lea 0x24(%r12), %rdi
    mov $FUTEX_WAIT_PRIVATE, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp 5b
#endif
wexit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
