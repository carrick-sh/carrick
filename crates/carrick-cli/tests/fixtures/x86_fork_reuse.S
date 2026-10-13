# Fork stock reuse witness. Twelve sequential rounds, more than the x86
# carrier's eight fork lifecycle records: each child first-touches fresh
# private anonymous pages (they must read zero, so a reused frame or record
# never leaks a previous child's bytes), writes and verifies a per-round
# pattern, and exits 0; the parent waits for it before the next fork.
# Rounds past eight succeed only if retired children's stock is reclaimed.
# Exit 91 = fork refusal; 93 = mmap refusal; 94 = stale or lost leaf;
# 95 = wait failure; 96 = child status not zero.
.global _start
.text
_start:
#ifdef AUTOREAP
    lea action(%rip), %rsi
    mov $17, %edi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %eax, %eax
    jnz wait_fail
    /* Existing in-zone signal-wait protocol; no host-forwarded child I/O. */
    mov $14, %eax
    mov $2, %edi
    lea ack_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %eax, %eax
    jnz wait_fail
    mov $39, %eax
    syscall
    mov %rax, %rbp
#endif
    xor %rbx, %rbx
round:
    mov $57, %rax
    syscall
    cmp $-4095, %rax
    jae fork_fail
    test %rax, %rax
    jz child
    mov %rax, %r12
    sub $16, %rsp
#ifdef AUTOREAP
    mov $-1, %rdi
#else
    mov %r12, %rdi
#endif
    mov %rsp, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
#ifdef AUTOREAP
    cmp $-10, %rax
    jne wait_fail
    mov $128, %eax
    lea ack_mask(%rip), %rdi
    xor %esi, %esi
    lea ack_timeout(%rip), %rdx
    mov $8, %r10d
    syscall
    cmp $10, %rax
    jne leaf_fail
#else
    cmp %r12, %rax
    jne wait_fail
    cmpl $0, (%rsp)
    jne status_fail
#endif
    add $16, %rsp
    inc %rbx
    cmp $12, %rbx
    jne round
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
child:
    mov $0x40000000, %rdi
    mov $16384, %rsi
    mov $3, %rdx
    mov $0x32, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $0x40000000, %rax
    jne map_fail
    mov %rax, %r14
    lea 0x100(%rbx), %r13
    xor %r15, %r15
touch:
    cmpq $0, (%r14,%r15)
    jne leaf_fail
    mov %r13, (%r14,%r15)
    add $4096, %r15
    cmp $16384, %r15
    jne touch
    xor %r15, %r15
verify:
    cmp %r13, (%r14,%r15)
    jne leaf_fail
    add $4096, %r15
    cmp $16384, %r15
    jne verify
#ifdef AUTOREAP
    /* Exit status is unavailable: acknowledge verified private data in-zone. */
    mov %rbp, %rdi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jne leaf_fail
#endif
    xor %rdi, %rdi
    jmp exit
fork_fail:
    mov $91, %rdi
    jmp exit
map_fail:
    mov $93, %rdi
    jmp exit
leaf_fail:
    mov $94, %rdi
    jmp exit
wait_fail:
    mov $95, %rdi
    jmp exit
status_fail:
    mov $96, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
ok: .ascii "R\n"

#ifdef AUTOREAP
.balign 8
ack_mask: .quad 0x200
ack_timeout: .quad 0, 0
action:
#ifdef IGNORE_SIGCHLD
    .quad 1, 0, 0, 0
#else
    .quad 0, 2, 0, 0
#endif
#endif
