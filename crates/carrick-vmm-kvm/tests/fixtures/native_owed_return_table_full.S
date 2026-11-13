/* #1482 P0-1: a full owed-return table whose holders are busy.
 * Eight holder children each map 16 pages, touch every other page, then
 * unmap each touched page on its own: eight disjoint resident retirements,
 * eight owed returns, that child's whole share (all touches come first: a
 * first touch's carrier exclusion settles whatever its MM already owes). Eight holders fill the
 * shared 64-slot table. Each holder then reports ready and blocks reading
 * the hold pipe, owning its slots and doing nothing else.
 *
 * WAITERS processes then retire one resident page each, which needs a
 * slot in the full table: the root itself and, with -DWAITERS=2, one more
 * child that holds no slot (ten live MMs: more than the x86 carrier's eight
 * fork lifecycle records admit today, so only the root waits there). Each rings the settlement doorbell, whose
 * drain must settle another holder to free a slot. Every holder is the
 * same busy MM to the drain (the KVM witness holds their editors), so the
 * waiter must park on a holder's release, and complete once it comes.
 *
 * Exit status names the first step that differs from Linux:
 *   1 pipe2 failed
 *   2 fork failed
 *   3 a holder's mmap failed
 *   4 a holder's munmap failed
 *   5 the ready handshake failed
 *   6 a waiter's mmap failed
 *   7 a waiter's munmap failed
 *   8 releasing the holders or a wait4 failed
 *   9 a child exited non-zero
 *   0 every step matched Linux */
#ifndef WAITERS
#define WAITERS 1
#endif
#define HOLDERS 8
.global _start
.text
_start:
    lea ready(%rip), %rdi          /* pipe2(ready, 0) */
    xor %esi, %esi
    mov $293, %eax
    syscall
    mov $1, %edi
    test %rax, %rax
    jnz exit
    lea hold(%rip), %rdi           /* pipe2(hold, 0) */
    xor %esi, %esi
    mov $293, %eax
    syscall
    mov $1, %edi
    test %rax, %rax
    jnz exit
    lea go(%rip), %rdi             /* pipe2(go, 0) */
    xor %esi, %esi
    mov $293, %eax
    syscall
    mov $1, %edi
    test %rax, %rax
    jnz exit

    xor %r15d, %r15d               /* holders forked */
fork_holder:
    mov $57, %eax                  /* fork */
    syscall
    mov $2, %edi
    test %rax, %rax
    js exit
    jz holder
    inc %r15d
    cmp $HOLDERS, %r15d
    jne fork_holder

#if WAITERS > 1
    mov $57, %eax                  /* fork the second waiter */
    syscall
    mov $2, %edi
    test %rax, %rax
    js exit
    jz second_waiter
#endif

    xor %r15d, %r15d               /* every holder reports ready */
await_ready:
    mov ready(%rip), %edi          /* read(ready[0], byte, 1) */
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    mov $5, %edi
    cmp $1, %rax
    jne exit
    inc %r15d
    cmp $HOLDERS, %r15d
    jne await_ready

#if WAITERS > 1
    mov go+4(%rip), %edi           /* write(go[1], byte, 1): second waiter */
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    mov $5, %edi
    cmp $1, %rax
    jne exit
#endif

    call retire_one_page           /* the root needs a slot too */
    test %edi, %edi
    jnz exit

    xor %r15d, %r15d               /* release the holders */
release_holders:
    mov hold+4(%rip), %edi         /* write(hold[1], byte, 1) */
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    mov $8, %edi
    cmp $1, %rax
    jne exit
    inc %r15d
    cmp $HOLDERS, %r15d
    jne release_holders

    mov $HOLDERS + WAITERS - 1, %r15d
reap:
    mov $-1, %edi                  /* wait4(-1, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    mov $8, %edi
    test %rax, %rax
    js exit
    mov $9, %edi
    movzbl status+1(%rip), %eax    /* WEXITSTATUS */
    test %eax, %eax
    jnz child_status
    cmpb $0, status(%rip)          /* a signal-terminated child */
    jne exit
    dec %r15d
    jnz reap
    xor %edi, %edi
    jmp exit
child_status:
    mov %eax, %edi
    jmp exit

/* Map one page, touch it and unmap it: one resident retirement. Returns
 * 0, or the exit status of the failed step, in %edi. */
retire_one_page:
    xor %edi, %edi                 /* mmap(NULL, 4 KiB, RW, PRIVATE|ANON) */
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov $6, %edi
    cmp $-4096, %rax
    jae 1f
    movb $0x5a, (%rax)
    mov %rax, %rdi                 /* munmap(page, 4 KiB) */
    mov $4096, %esi
    mov $11, %eax
    syscall
    mov $7, %edi
    test %rax, %rax
    jnz 1f
    xor %edi, %edi
1:
    ret

#if WAITERS > 1
second_waiter:
    mov go(%rip), %edi             /* read(go[0], byte, 1) */
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    mov $5, %edi
    cmp $1, %rax
    jne exit
    call retire_one_page
    jmp exit
#endif

holder:
    xor %edi, %edi                 /* mmap(NULL, 64 KiB, RW, PRIVATE|ANON) */
    mov $0x10000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov $3, %edi
    cmp $-4096, %rax
    jae exit
    mov %rax, %r12                 /* the mapping */
    xor %r13d, %r13d               /* touch every other page first: a */
holder_touch:                      /* first touch crosses to the carrier, */
    mov %r13, %r14                 /* whose exclusion would settle any */
    shl $13, %r14                  /* return already owed */
    movb $0xa5, (%r12,%r14)
    inc %r13d
    cmp $8, %r13d
    jne holder_touch
    xor %r13d, %r13d               /* then unmap each touched page alone */
holder_page:
    mov %r13, %r14
    shl $13, %r14                  /* every other page: pair * 8 KiB */
    add %r12, %r14
    mov %r14, %rdi                 /* munmap(page, 4 KiB) */
    mov $4096, %esi
    mov $11, %eax
    syscall
    mov $4, %edi
    test %rax, %rax
    jnz exit
    inc %r13d
    cmp $8, %r13d
    jne holder_page
    mov ready+4(%rip), %edi        /* write(ready[1], byte, 1) */
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    mov $5, %edi
    cmp $1, %rax
    jne exit
    mov hold(%rip), %edi           /* read(hold[0], byte, 1): hold the slots */
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    mov $8, %edi
    cmp $1, %rax
    jne exit
    xor %edi, %edi
exit:
    mov $231, %eax                 /* exit_group */
    syscall
    ud2

.data
ready: .long -1, -1
hold: .long -1, -1
go: .long -1, -1
status: .long 0
byte: .byte 0x48
/* Never touched: its worst-case initial tables (three per page) are left to
 * the carrier's fork table stock, which nine live MMs need. */
.bss
.skip 0x40000
.section .note.GNU-stack,"",@progbits
