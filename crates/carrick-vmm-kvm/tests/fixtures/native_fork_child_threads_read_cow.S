/* #3042: a native fork child's two live threads read(2) into one
 * copy-on-write page at once. The kernel's copy, not a user store, is the
 * page's first write in the child, so the user-copy supply must serve the
 * fork child's copy-on-write stock (on ARM it was refused: "no guest COW
 * state", EFAULT or SIGSEGV). Two live processes and two live threads.
 *
 * Parent: fill the data page; fork; reap the child; the data page is
 * unchanged.
 * Child: queue 8 bytes in each of two pipes; clone two workers; release
 * them together; each read(2)s its pipe into its own offset of the one data
 * page; join both. Both reads return 8, both messages landed, and every
 * other byte of the page is the parent's.
 *
 * Exit 7: all of that held. 100 + n: worker A's read failed with errno n;
 * 120 + n: worker B's (n < 20). 93: a short read; 94: a message missing;
 * 95: another byte of the child's page changed; 91: the parent's page
 * changed. Other codes name a failed setup step.
 */
#define POLL_LIMIT 0x10000000
#define FILL       0x11

.global _start
.text
_start:
    /* mmap(NULL, 0x5000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    xor %edi, %edi
    mov $0x5000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_mmap
    mov %rax, %r12

    /* Layout in %r12:
     * +0x00: u32 worker A CLEARTID word; +0x08: worker B's
     * +0x10: u32 release flag; +0x14: u32 ready count
     * +0x20: i64 worker A read result; +0x28: worker B's
     * +0x40: timespec join timeout = { 5, 0 }
     * +0x50: i32 child wait status
     * +0x60: pipe A fds; +0x68: pipe B fds
     * +0x1ff0: worker A stack top; +0x2ff0: worker B's
     * +0x4000: the data page, resident and filled before the fork
     */
    movq $5, 0x40(%r12)
    movq $0, 0x48(%r12)
    lea 0x4000(%r12), %rdi
    mov $FILL, %eax
    mov $0x1000, %ecx
    rep stosb

    mov $57, %eax
    syscall
    test %rax, %rax
    jz child
    js fail_fork
    mov %rax, %r15

    /* wait4(child, &status, 0, NULL) */
    mov %r15, %rdi
    lea 0x50(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail_wait
    mov 0x50(%r12), %eax
    test $0x7f, %eax
    jnz fail_child_signal
    shr $8, %eax
    and $0xff, %eax
    cmp $7, %eax
    jne child_code
    /* The parent's page is exactly what it wrote. */
    lea 0x4000(%r12), %rsi
    mov $0x1000, %ecx
parent_check:
    cmpb $FILL, (%rsi)
    jne fail_parent_page
    inc %rsi
    dec %ecx
    jnz parent_check
    mov $7, %edi
    jmp die
child_code:
    mov %eax, %edi
    jmp die

child:
    /* Queue each worker's message before any worker runs. */
    lea 0x60(%r12), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe
    lea 0x68(%r12), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe
    movslq 0x64(%r12), %rdi
    lea msg_a(%rip), %rsi
    mov $8, %edx
    mov $1, %eax
    syscall
    cmp $8, %rax
    jne fail_pipe_write
    movslq 0x6c(%r12), %rdi
    lea msg_b(%rip), %rsi
    mov $8, %edx
    mov $1, %eax
    syscall
    cmp $8, %rax
    jne fail_pipe_write

    /* Workers (CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|
     * CHILD_CLEARTID: the word holds the tid until the worker exits);
     * %r14 names the worker in the clone. */
    xor %r14d, %r14d
    mov $0x00350f00, %edi
    lea 0x1ff0(%r12), %rsi
    lea 0x00(%r12), %rdx
    lea 0x00(%r12), %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker
    mov $1, %r14d
    mov $0x00350f00, %edi
    lea 0x2ff0(%r12), %rsi
    lea 0x08(%r12), %rdx
    lea 0x08(%r12), %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker

    /* Release both workers together once both run. */
    mov $POLL_LIMIT, %r13
ready_loop:
    cmpl $2, 0x14(%r12)
    je released
    dec %r13
    jz fail_ready
    mov $24, %eax
    syscall
    jmp ready_loop
released:
    movl $1, 0x10(%r12)

    /* Join both through their CLONE_CHILD_CLEARTID words. */
    lea 0x00(%r12), %rbx
    call join
    lea 0x08(%r12), %rbx
    call join

    mov 0x20(%r12), %rax
    test %rax, %rax
    js worker_a_errno
    mov 0x28(%r12), %rax
    test %rax, %rax
    js worker_b_errno
    cmpq $8, 0x20(%r12)
    jne fail_short
    cmpq $8, 0x28(%r12)
    jne fail_short
    mov msg_a(%rip), %rax
    cmp 0x4000(%r12), %rax
    jne fail_message
    mov msg_b(%rip), %rax
    cmp 0x4800(%r12), %rax
    jne fail_message
    /* Every other byte is the parent's. */
    xor %ecx, %ecx
child_check:
    cmp $0x1000, %ecx
    je child_ok
    mov %ecx, %edx
    and $0x7ff, %edx
    cmp $8, %edx
    jb child_next
    cmpb $FILL, 0x4000(%r12,%rcx)
    jne fail_child_page
child_next:
    inc %ecx
    jmp child_check
child_ok:
    mov $7, %edi
    jmp die

worker_a_errno:
    neg %eax
    add $100, %eax
    mov %eax, %edi
    jmp die
worker_b_errno:
    neg %eax
    add $120, %eax
    mov %eax, %edi
    jmp die

/* join: wait for the CLEARTID word at (%rbx) to clear. */
join:
    mov (%rbx), %edx
    test %edx, %edx
    jz joined
    mov %rbx, %rdi
    xor %esi, %esi
    lea 0x40(%r12), %r10
    mov $202, %eax
    syscall
    cmp $-110, %rax
    je fail_join
    jmp join
joined:
    ret

worker:
    lock incl 0x14(%r12)
    mov $POLL_LIMIT, %r13
release_loop:
    cmpl $0, 0x10(%r12)
    jne go
    dec %r13
    jz worker_exit
    pause
    jmp release_loop
go:
    /* read(pipe[r14][0], data + r14 * 0x800, 8) */
    movslq 0x60(%r12,%r14,8), %rdi
    mov %r14, %rsi
    shl $11, %rsi
    lea 0x4000(%r12,%rsi), %rsi
    mov $8, %edx
    xor %eax, %eax
    syscall
    mov %rax, 0x20(%r12,%r14,8)
worker_exit:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fail_child_signal:
    mov $90, %edi
    jmp die
fail_parent_page:
    mov $91, %edi
    jmp die
fail_short:
    mov $93, %edi
    jmp die
fail_message:
    mov $94, %edi
    jmp die
fail_child_page:
    mov $95, %edi
    jmp die
fail_mmap:
    mov $81, %edi
    jmp die
fail_fork:
    mov $82, %edi
    jmp die
fail_pipe:
    mov $83, %edi
    jmp die
fail_wait:
    mov $84, %edi
    jmp die
fail_pipe_write:
    mov $85, %edi
    jmp die
fail_clone:
    mov $86, %edi
    jmp die
fail_ready:
    mov $87, %edi
    jmp die
fail_join:
    mov $88, %edi
die:
    mov $231, %eax
    syscall
    ud2

.section .rodata
msg_a:
    .ascii "CARRICK0"
msg_b:
    .ascii "CARRICK1"
