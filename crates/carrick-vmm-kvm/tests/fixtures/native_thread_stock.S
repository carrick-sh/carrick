/* #2734: one process holds more live ring-born threads than one stock page.
   The members clone LIVE threads that each block in a futex wait, then
   one more that ends with a raw exit (a non-last thread's exit, joined
   through its clear-child-tid word), and the leader calls exit_group
   with every worker still parked. Every clone must return a tid, and the
   tids must be consecutive: a clone never burns an identity on the way.
   CHURN instead creates and joins LIVE threads one at a time.
   FORK_CHILD runs the members in a fork child; the root reaps it and
   ends with the child's exit status.
   Exit status: 0 ok; 100+i clone #i failed with EAGAIN; 140+i clone #i
   failed otherwise; 60+i tid #i is not the previous tid + 1; 91 fork,
   wait4 or futex failure; 92 the child died by a signal. */
#ifndef LIVE
#define LIVE 16
#endif
#define CLONE_THREAD_FLAGS 0x3d0f00
#define STACK_BYTES 4096
.global _start
.text
_start:
#ifdef FORK_CHILD
    mov $57, %eax
    syscall
    test %eax, %eax
    jz members
    js failure
    mov %eax, %r12d
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov status(%rip), %eax
    test $0x7f, %eax
    jnz killed
    shr $8, %eax
    and $0xff, %eax
    mov %eax, %edi
    jmp exit
killed:
    mov $92, %edi
    jmp exit
#endif
members:
    xor %ebx, %ebx
spawn:
    cmp $LIVE, %ebx
    je spawned
#ifdef CHURN
    mov $1, %r13d
#else
    xor %r13d, %r13d
#endif
    call clone_member
#ifdef CHURN
    call join_member
#endif
    inc %ebx
    jmp spawn
spawned:
    /* tids[i] == tids[i - 1] + 1 for every i. */
    mov $1, %ebx
consecutive:
    cmp $LIVE, %ebx
    je consecutive_done
    lea tids(%rip), %rax
    mov -4(%rax,%rbx,4), %ecx
    inc %ecx
    cmp %ecx, (%rax,%rbx,4)
    jne not_consecutive
    inc %ebx
    jmp consecutive
not_consecutive:
    lea 60(%rbx), %edi
    jmp exit
consecutive_done:
#ifdef CHURN
    xor %edi, %edi
    jmp exit
#else
    /* Every worker is parked or about to park before the raw exit. */
wait_ready:
    lea ready(%rip), %rdi
    mov (%rdi), %edx
    cmp $LIVE, %edx
    je all_ready
    mov $128, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    cmp $0, %rax
    je wait_ready
    cmp $-11, %rax
    je wait_ready
    jmp failure
all_ready:
#ifndef NINTH_CLONE
    /* A non-last member's raw exit, joined by its clear-child-tid word. */
    mov $LIVE, %ebx
    mov $1, %r13d
    call clone_member
    call join_member
#endif
    /* exit_group with LIVE workers still parked in their futex waits. */
    xor %edi, %edi
    jmp exit
#endif

/* Clone member %ebx; %r13d selects its body (0 park, 1 raw exit). */
clone_member:
    mov $CLONE_THREAD_FLAGS, %edi
    lea 1(%rbx), %rsi
    shl $12, %rsi
    lea stacks(%rip), %rax
    add %rax, %rsi
    lea tids(%rip), %rdx
    lea (%rdx,%rbx,4), %rdx
    lea child_tids(%rip), %r10
    lea (%r10,%rbx,4), %r10
    mov %rbx, %r8
    shl $6, %r8
    lea tls(%rip), %rax
    add %rax, %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz member
    js clone_failed
    ret
clone_failed:
    cmp $-11, %rax
    jne clone_failed_other
    lea 100(%rbx), %edi
    jmp exit
clone_failed_other:
    lea 140(%rbx), %edi
    jmp exit

/* Wait until member %ebx's clear-child-tid word is zero. */
join_member:
    lea child_tids(%rip), %rdi
    lea (%rdi,%rbx,4), %rdi
join_again:
    mov (%rdi), %edx
    test %edx, %edx
    jz joined
    push %rdi
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    pop %rdi
    cmp $0, %rax
    je join_again
    cmp $-11, %rax
    je join_again
    cmp $-4, %rax
    je join_again
    jmp failure
joined:
    ret

member:
    test %r13d, %r13d
    jnz member_exit
    mov $1, %edx
    lock xadd %edx, ready(%rip)
    cmp $(LIVE - 1), %edx
    jne member_park
    lea ready(%rip), %rdi
    mov $129, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
member_park:
    lea go(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp failure
member_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.bss
.balign 4096
status: .space 8
ready: .space 8
go: .space 8
.balign 64
tids: .space 4 * (LIVE + 1)
.balign 64
child_tids: .space 4 * (LIVE + 1)
.balign 64
tls: .space 64 * (LIVE + 1)
.balign 4096
stacks: .space STACK_BYTES * (LIVE + 1)
