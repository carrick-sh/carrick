/* Native x86 epoll_pwait(281) copy-out on a ring epoll (#1671). An eventfd
 * created ready (initval 1) is watched EPOLLIN|EPOLLET; epoll_pwait(ep,
 * events, 4, 0, NULL, 8) reports into a fresh anonymous page nothing has
 * touched, so the ring's copy refuses it until the native owner prepares
 * it. x86 epoll_event is packed: u32 events, u64 data at +4 (12 bytes).
 *  - one report, events == EPOLLIN, data == 0x1671, the next entry still 0;
 *  - a second wait reports nothing: the edge is reported once;
 *  - a second ready eventfd: a wait into an unmapped buffer is EFAULT with
 *    the report kept queued, and a valid wait then reports it once.
 * Exit 7 = success. 100 + errno: the first wait failed with that errno;
 * every other code names the failed stage.
 */
.global _start
.text
_start:
    mov $1, %edi
    mov $0x800, %esi               /* eventfd2(1, EFD_NONBLOCK) */
    mov $290, %eax
    syscall
    test %eax, %eax
    js fail_eventfd
    mov %eax, %r12d
    xor %edi, %edi
    mov $291, %eax                 /* epoll_create1(0) */
    syscall
    test %eax, %eax
    js fail_epoll
    mov %eax, %r13d
    mov %r13d, %edi
    mov $1, %esi                   /* EPOLL_CTL_ADD */
    mov %r12d, %edx
    lea interest(%rip), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    jnz fail_ctl
    /* mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS) */
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4096, %rax
    ja fail_mmap
    mov %rax, %r14
    /* epoll_pwait(ep, page, 4, 0, NULL, 8) into the untouched page */
    mov %r13d, %edi
    mov %r14, %rsi
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    mov $281, %eax
    syscall
    test %rax, %rax
    js first_errno
    cmp $1, %rax
    jne fail_first
    cmpl $1, (%r14)                /* EPOLLIN */
    jne fail_events
    movabs $0x1671, %rax
    cmp %rax, 4(%r14)
    jne fail_data
    cmpl $0, 12(%r14)              /* one entry: the next is untouched */
    jne fail_duplicate
    cmpq $0, 16(%r14)
    jne fail_duplicate
    /* The edge was reported: the same wait now reports nothing. */
    mov %r13d, %edi
    lea 64(%r14), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    mov $281, %eax
    syscall
    test %rax, %rax
    jnz fail_again
    /* A second ready eventfd, then a wait into an unmapped buffer. */
    mov $1, %edi
    mov $0x800, %esi
    mov $290, %eax
    syscall
    test %eax, %eax
    js fail_eventfd
    mov %r13d, %edi
    mov $1, %esi
    mov %eax, %edx
    lea interest2(%rip), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    jnz fail_ctl
    mov %r13d, %edi
    mov $16, %esi                  /* page zero: never mapped */
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    mov $281, %eax
    syscall
    cmp $-14, %rax                 /* EFAULT */
    jne fail_efault
    /* Linux keeps the report queued after a failed copy. */
    mov %r13d, %edi
    lea 128(%r14), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    mov $281, %eax
    syscall
    cmp $1, %rax
    jne fail_requeued
    cmpl $1, 128(%r14)
    jne fail_requeued
    movabs $0x2671, %rax
    cmp %rax, 132(%r14)
    jne fail_requeued
    mov $7, %edi
    jmp exit
first_errno:
    neg %rax
    lea 100(%rax), %edi
    jmp exit
fail_eventfd:
    mov $20, %edi
    jmp exit
fail_epoll:
    mov $21, %edi
    jmp exit
fail_ctl:
    mov $22, %edi
    jmp exit
fail_mmap:
    mov $23, %edi
    jmp exit
fail_first:
    mov $24, %edi
    jmp exit
fail_events:
    mov $25, %edi
    jmp exit
fail_data:
    mov $26, %edi
    jmp exit
fail_duplicate:
    mov $27, %edi
    jmp exit
fail_again:
    mov $28, %edi
    jmp exit
fail_efault:
    mov $29, %edi
    jmp exit
fail_requeued:
    mov $30, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
interest: .long 0x80000001         /* EPOLLIN | EPOLLET */
          .quad 0x1671
interest2: .long 0x80000001
           .quad 0x2671
