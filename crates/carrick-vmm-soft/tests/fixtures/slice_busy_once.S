/* Deterministic two-thread contended-head slice witness: the root leader
 * clones one CLONE_CHILD_CLEARTID worker (whose wake self-IPIs RESCHED_VECTOR
 * onto slot 0, rotating the worker onto the CPU with the homed leader queued
 * behind it). The worker spins in CPL3 until the leader writes 8(%r12) = 1;
 * only a user-origin slice interrupt can preempt the polling worker.
 */
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
    test %rax, %rax
    js fail
    mov %rax, %r12
    movq $0, (%r12)
    movq $0, 8(%r12)
    movq $0, 0x1ff0(%r12)

    mov $0x00350f00, %edi
    lea 0x1ff0(%r12), %rsi
    mov %r12, %rdx
    mov %r12, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js fail

    movl $1, 8(%r12)

join:
    mov (%r12), %edx
    test %edx, %edx
    jz joined
    mov %r12, %rdi
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp join

joined:
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2

worker:
    cmpl $1, 8(%r12)
    jne worker
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fail:
    mov $1, %edi
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
