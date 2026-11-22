/* #2749 fatal 1: a forked child and one clone sibling each run ROUNDS of
 * mmap / first touch / mprotect / munmap on their shared MM. The two threads
 * contend for that MM's reservation root and descriptor editor; contention
 * is "not now", so every call must still return what Linux returns.
 *
 * The child exits with the errno of the first failing call (38 when a
 * contended call was lowered to a counted ENOSYS), or 0. The root reaps it
 * and exits with the same code. Native Linux exits 0.
 *
 * The child writes its inherited stack page once before the sibling exists,
 * so its copy-on-write is not part of the contention. -DCOW_UNDER_CONTENTION
 * leaves that first write to the churn loop's `call`, where the sibling may
 * hold the MM's editor when the fault's copy is supplied.
 */
#define ROUNDS 2000
#define LEN 0x10000
#define FUTEX_WAIT 0
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r13d
    sub $16, %rsp
    mov %rsp, %rsi
    mov %r13d, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit

child:
#ifndef COW_UNDER_CONTENTION
    push %rax
    pop %rax
#endif
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    mov %rax, %r12
    movl $0, 0x10(%r12)
    movl $0, 0x3000(%r12)
    mov $0x00350f00, %edi
    lea 0x1ff0(%r12), %rsi
    lea 0x3000(%r12), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
    call churn
    lea 0x3000(%r12), %rdi
join:
    mov (%rdi), %edx
    test %edx, %edx
    jz 1f
    mov $FUTEX_WAIT, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    lea 0x3000(%r12), %rdi
    jmp join
1:  mov 0x10(%r12), %edi
exit:
    mov $231, %eax
    syscall
    ud2
failure:
    mov $91, %edi
    jmp exit

worker:
    call churn
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

churn:
    mov $ROUNDS, %r15d
1:  xor %edi, %edi
    mov $LEN, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js record
    mov %rax, %r14
    movb $1, (%r14)
    mov %r14, %rdi
    mov $LEN, %esi
    mov $1, %edx
    mov $10, %eax
    syscall
    test %eax, %eax
    jnz record
    mov %r14, %rdi
    mov $LEN, %esi
    mov $11, %eax
    syscall
    test %eax, %eax
    jnz record
    dec %r15d
    jnz 1b
    ret
/* Keep the first errno; later ones do not replace it. */
record:
    neg %eax
    mov %eax, %ecx
    xor %eax, %eax
    lock cmpxchg %ecx, 0x10(%r12)
    ret
.section .note.GNU-stack,"",@progbits
