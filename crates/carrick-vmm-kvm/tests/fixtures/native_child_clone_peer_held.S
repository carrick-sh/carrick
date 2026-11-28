/* Discovery (#3117 clone ENOSYS): a forked child clones one thread while
 * the other CPU's idle pass is held at its top with interrupts masked
 * (INJECT_HOLD_PEER_SCAN, 20 ms). -DNO_HOLD clones with no hold.
 * -DTOUCH_TID writes the PARENT_SETTID word's page before the clone.
 *
 * Exit 7: the clone succeeded and the thread was joined. 80: fork or reap
 * failed. 81: arming the hold failed. 150 + n: clone failed with errno n.
 * 82: the join's futex failed.
 */
#define INJECT_HOLD_PEER_SCAN 0xfffffffffffffe2a
#define INJECT_PEER_SCAN_HELD 0xfffffffffffffe2b

.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js fail_fork
    jz witness
    mov %eax, %edi
    sub $16, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %rax, %rax
    js fail_fork
    mov (%rsp), %edi
    test $0x7f, %edi
    jnz fail_fork
    shr $8, %edi
    and $0xff, %edi
    jmp die

witness:
    xor %edi, %edi
    mov $0x3000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_arm
    mov %rax, %r12
#ifdef TOUCH_TID
    /* Populate the tid/TLS page before the clone. */
    movl $0, (%r12)
#endif
#ifndef NO_HOLD
    mov $INJECT_HOLD_PEER_SCAN, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
held_loop:
    mov $INJECT_PEER_SCAN_HELD, %rax
    syscall
    cmp $1, %rax
    je held
    pause
    jmp held_loop
held:
#endif
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
join:
    mov (%r12), %edx
    test %edx, %edx
    jz joined
    mov %r12, %rdi
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    cmp $-11, %rax
    je join
    test %rax, %rax
    js fail_futex
    jmp join
joined:
    mov $7, %edi
    jmp die
worker:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
fail_fork:
    mov $80, %edi
    jmp die
fail_arm:
    mov $81, %edi
    jmp die
fail_futex:
    mov $82, %edi
    jmp die
fail_clone:
    neg %eax
    lea 150(%rax), %edi
die:
    mov $231, %eax
    syscall
    ud2
