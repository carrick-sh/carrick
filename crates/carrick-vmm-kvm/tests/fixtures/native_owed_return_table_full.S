/* #1482 P0-1: a full owed-return table whose holders are busy.
 * Eight holder children each map 16 pages, touch every other page, then
 * unmap each touched page on its own: eight disjoint resident retirements,
 * eight owed returns (an MM's whole share), and eight holders fill the
 * shared 64-slot table. All touches come first, and each holder takes its
 * inherited stack page's COW before them: a carrier exclusion of the
 * holder after its munmaps (a first touch, a COW fault) would settle its
 * returns. Each holder then closes its copy of the ready pipe's write end
 * and sleeps, owning its slots and doing nothing else, until the root
 * kills it.
 *
 * x86 CPL0 has no ring IPC venue for a zone pipe's read or write yet
 * (#1756), and a fork child's blocking poll on a zone pipe is not served
 * there either, so the one handshake is the root's poll on the ready
 * pipe, which hangs up once every holder has closed its writer.
 *
 * The root then retires one resident page, which needs a slot in the full
 * table: it rings the settlement doorbell, whose drain must settle another
 * holder to free a slot. Every holder is the same busy MM to the drain
 * (the KVM witness holds their editors), so the root must park on a
 * holder's release, and complete once it comes. (A second waiting process
 * would be a ninth child: more than the x86 carrier's eight fork lifecycle
 * records admit today.)
 *
 * Exit status names the first step that differs from Linux:
 *   1 pipe2 failed
 *   2 fork failed
 *   3 a holder's mmap failed
 *   4 a holder's munmap failed
 *   5 the ready handshake (close, or poll for POLLHUP) failed
 *   6 the root's mmap failed
 *   7 the root's munmap failed
 *   8 killing a holder or a wait4 failed
 *   9 a holder ended other than by SIGKILL
 *  10 a holder's sleep returned
 *   0 every step matched Linux */
#define HOLDERS 8
#define HOLDER_PAGES 8
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

    xor %r15d, %r15d               /* holders forked */
fork_holder:
    mov $57, %eax                  /* fork */
    syscall
    mov $2, %edi
    test %rax, %rax
    js exit
    jz holder
    lea pids(%rip), %rcx
    mov %eax, (%rcx,%r15,4)
    inc %r15d
    cmp $HOLDERS, %r15d
    jne fork_holder

    mov ready+4(%rip), %edi        /* every holder reports ready: the */
    call close_fd                  /* root drops its writer, then waits */
    jnz exit                       /* for the last one to hang up */
    mov ready(%rip), %edi
    call await_hangup
    jnz exit

    call retire_one_page           /* the root needs a slot too */
    test %edi, %edi
    jnz exit

    xor %r15d, %r15d               /* release the holders */
release_holders:
    lea pids(%rip), %rcx
    mov (%rcx,%r15,4), %edi        /* kill(holder, SIGKILL) */
    mov $9, %esi
    mov $62, %eax
    syscall
    mov $8, %edi
    test %rax, %rax
    jnz exit
    inc %r15d
    cmp $HOLDERS, %r15d
    jne release_holders

    mov $HOLDERS, %r15d
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
    cmpl $9, status(%rip)          /* killed by SIGKILL */
    jne exit
    dec %r15d
    jnz reap
    xor %edi, %edi
    jmp exit

/* close(%edi). ZF set on success; otherwise %edi is 5. */
close_fd:
    mov $3, %eax
    syscall
    mov $5, %edi
    test %rax, %rax
    jnz 1f
    xor %edi, %edi
1:
    test %edi, %edi
    ret

/* Block in poll until every writer of the pipe read end %edi has closed:
 * poll(&{fd, POLLIN}, 1, -1) answers 1 with POLLHUP. ZF set on success;
 * otherwise %edi is 5. */
await_hangup:
    mov %edi, pfd(%rip)
    movw $1, pfd+4(%rip)
    movw $0, pfd+6(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
    mov $-1, %edx
    mov $7, %eax
    syscall
    mov $5, %edi
    cmp $1, %rax
    jne 1f
    testw $0x10, pfd+6(%rip)       /* POLLHUP */
    jz 1f
    xor %edi, %edi
1:
    test %edi, %edi
    ret
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

holder:
    push %rax                      /* take the inherited stack page's COW */
    pop %rax                       /* now: a COW fault after the munmaps */
    mov $HOLDER_PAGES, %ebx        /* would settle this holder's returns */
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
    cmp %ebx, %r13d
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
    cmp %ebx, %r13d
    jne holder_page
    mov ready+4(%rip), %edi        /* ready: drop this holder's writer */
    call close_fd
    jnz exit
    lea forever(%rip), %rdi        /* hold the slots until the root's */
    xor %esi, %esi                 /* SIGKILL: nanosleep({3600, 0}) */
    mov $35, %eax
    syscall
    mov $10, %edi
exit:
    mov $231, %eax                 /* exit_group */
    syscall
    ud2

.data
ready: .long -1, -1
pids: .long 0, 0, 0, 0, 0, 0, 0, 0
pfd: .long -1
     .short 0, 0
status: .long 0
forever: .quad 3600, 0
/* Never touched: its worst-case initial tables (three per page) are left to
 * the carrier's fork table stock, which nine live MMs need. */
.bss
.skip 0x40000
.section .note.GNU-stack,"",@progbits
