/* #2157 B0 T1: two live fork children each make an x86-allowed host
 * crossing that no ring stage serves. A child has no host task context, so
 * each call must be a counted ENOSYS in ring (as ARM answers a fork child's
 * unclaimed native call), not a carrier failure. Child A calls
 * read(0, buf, 0) and then sleeps 50 ms, so it is still live while child B
 * calls lseek(0, 0, SEEK_CUR). The root's own read(0, buf, 0) keeps its host
 * route and returns 0.
 *
 * Each child exits with the negated value its call returned (38 = ENOSYS).
 * Exit 7 = all three answers as expected; 81 the root's read returned
 * ENOSYS, 82 it returned something else; 64 | A's status and 128 | B's
 * status name a wrong child answer; 91 fork/wait failed. */
.global _start
.text
_start:
    mov $57, %eax                  /* fork: child A */
    syscall
    test %eax, %eax
    js fail_wait
    jz child_a
    mov %eax, %r12d
    mov $57, %eax                  /* fork: child B */
    syscall
    test %eax, %eax
    js fail_wait
    jz child_b
    mov %eax, %r13d
    xor %edi, %edi                 /* root: read(0, buf, 0) */
    lea buffer(%rip), %rsi
    xor %edx, %edx
    xor %eax, %eax
    syscall
    cmp $-38, %rax
    je fail_root_enosys
    test %rax, %rax
    jnz fail_root_other
    mov %r12d, %edi                /* wait4(A, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fail_wait
    movzbl status+1(%rip), %edi
    cmp $38, %edi
    je 1f
    or $64, %edi
    jmp exit
1:
    mov %r13d, %edi                /* wait4(B, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne fail_wait
    movzbl status+1(%rip), %edi
    cmp $38, %edi
    je 2f
    or $128, %edi
    jmp exit
2:
    mov $7, %edi
    jmp exit

child_a:
    xor %edi, %edi                 /* read(0, buf, 0) */
    lea buffer(%rip), %rsi
    xor %edx, %edx
    xor %eax, %eax
    syscall
    mov %rax, %rbx
    lea sleep_for(%rip), %rdi      /* nanosleep(50 ms): stay live for B */
    xor %esi, %esi
    mov $35, %eax
    syscall
    mov %rbx, %rax
    neg %rax
    mov %eax, %edi
    jmp exit

child_b:
    xor %edi, %edi                 /* lseek(0, 0, SEEK_CUR) */
    xor %esi, %esi
    mov $1, %edx
    mov $8, %eax
    syscall
    neg %rax
    mov %eax, %edi
    jmp exit

fail_root_enosys:
    mov $81, %edi
    jmp exit
fail_root_other:
    mov $82, %edi
    jmp exit
fail_wait:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
.balign 8
sleep_for: .quad 0, 50000000

.section .data
.balign 8
status: .long 0
buffer: .long 0
