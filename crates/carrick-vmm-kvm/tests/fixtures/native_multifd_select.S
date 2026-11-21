/* #2621: apt's select shape on zone pipes. The root forks a native parent
 * that makes three pipes A, B and W (W non-blocking) and forks a poller.
 * The poller selects with A and B's read ends in the read set and W's write
 * end in the write set (nfds = W's writer + 1; 9 when stdio is open):
 *   1. W has room: pselect6 answers at once with the write bit alone;
 *   2. it fills W until EAGAIN, so nothing in the set is ready;
 *   3. a blocking pselect6 parks on all three members. The parent writes
 *      to B only after the host saw the poller enrolled (SELECT_GATE_PORT;
 *      -DNO_GATE sleeps 50 ms instead, for a native run): the poller must
 *      wake with exactly B's read bit and an empty write set.
 * -DSET_TIMEOUT: after filling W, a {0, 20 ms} pselect6 returns 0 with both
 * sets and the timeout cleared (no parent action).
 * -DSET_EINTR: the poller catches SIGUSR1 (no SA_RESTART); the parent sends
 * it instead of writing: the wait ends with EINTR and the handler ran.
 * -DSET_SIGMASK: the wait blocks SIGUSR1 through pselect6's mask; the parent
 * sends it, then writes B: the wait reports B, the persistent mask is empty
 * again and the handler ran after the call.
 * -DTWO_POLLERS: two pollers park on the same set at once (the default
 * 2-vCPU pool must still run the parent); one write wakes both.
 * Exit 7 = success; every other code names the failed stage. */
.global _start
.text
_start:
    mov $57, %eax                  /* the root only reaps the native parent */
    syscall
    test %eax, %eax
    js fail_fork
    jz parent_main
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    movzbl status+1(%rip), %edi    /* the parent's verdict, 7 on success */
    jmp exit

parent_main:
    lea fds_a(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax                 /* pipe2(A, 0) */
    syscall
    test %rax, %rax
    jnz fail_pipe
    lea fds_b(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax                 /* pipe2(B, 0) */
    syscall
    test %rax, %rax
    jnz fail_pipe
    lea fds_w(%rip), %rdi
    mov $0x800, %esi
    mov $293, %eax                 /* pipe2(W, O_NONBLOCK) */
    syscall
    test %rax, %rax
    jnz fail_pipe
#ifdef TWO_POLLERS
    call fill_w                    /* both pollers find nothing ready */
#endif
    mov $57, %eax                  /* fork the poller */
    syscall
    test %eax, %eax
    js fail_fork
    jz poller
    mov %eax, %r12d
    mov %r12d, poller_pids(%rip)
#ifdef TWO_POLLERS
    mov $57, %eax                  /* fork the second poller */
    syscall
    test %eax, %eax
    js fail_fork
    jz poller
    mov %eax, %r15d
    mov %r15d, poller_pids+4(%rip)
#endif
#ifndef SET_TIMEOUT
    call gate
#if defined(SET_EINTR) || defined(SET_SIGMASK)
    mov %r12d, %edi
    mov $10, %esi
    mov $62, %eax                  /* kill(poller, SIGUSR1) while it waits */
    syscall
    test %rax, %rax
    jnz fail_signal
#endif
#ifndef SET_EINTR
    mov fds_b+4(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax                   /* write(B, "x", 1): the one wake */
    syscall
    cmp $1, %rax
    jne fail_write
#endif
#endif
    mov %r12d, %edi
    call reap
#ifdef TWO_POLLERS
    mov %r15d, %edi
    call reap
#endif
    mov $7, %edi
    jmp exit

/* wait4(edi) and exit with the poller's stage code unless it exited 0. */
reap:
    mov %edi, %ebx
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %ebx, %eax
    jne fail_wait
    cmpl $0, status(%rip)
    je 1f
    movzbl status+1(%rip), %edi
    test %edi, %edi
    jz fail_wait
    jmp exit
1:
    ret

/* Hand the poller pids to the host and wait until it has seen every poller
 * enrolled in its wait. */
gate:
#ifdef NO_GATE
    lea delay(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax                  /* nanosleep({0, 50 ms}) */
    syscall
    ret
#else
    mov $2, %edi                   /* AF_INET */
    mov $2, %esi                   /* SOCK_DGRAM */
    xor %edx, %edx
    mov $41, %eax
    syscall
    test %rax, %rax
    js fail_gate
    mov %eax, %r13d
    mov %r13d, %edi
    lea select_gate_peer(%rip), %rsi
    mov $16, %edx
    mov $42, %eax                  /* connect */
    syscall
    test %rax, %rax
    jnz fail_gate
    mov %r13d, %edi
    lea poller_pids(%rip), %rsi
    mov $8, %edx
    mov $1, %eax                   /* send the poller pids */
    syscall
    cmp $8, %rax
    jne fail_gate
    mov %r13d, pfd(%rip)
    movw $1, pfd+4(%rip)
    movw $0, pfd+6(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
    mov $8000, %edx                /* bound fixture cleanup */
    mov $7, %eax
    syscall
    cmp $1, %rax
    jne fail_gate
    mov %r13d, %edi
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne fail_gate
    ret
#endif

/* read_set = {A, B} readers, write_set = {W} writer; r14/r15 keep them. */
set_sets:
    mov fds_a(%rip), %ecx
    mov $1, %r14d
    shl %cl, %r14
    mov fds_b(%rip), %ecx
    mov $1, %eax
    shl %cl, %rax
    or %rax, %r14
    mov %r14, read_set(%rip)
    mov fds_w+4(%rip), %ecx
    mov $1, %r15d
    shl %cl, %r15
    mov %r15, write_set(%rip)
    ret

/* pselect6(W writer + 1, &read_set, &write_set, NULL, r8, r9) */
select_call:
    mov fds_w+4(%rip), %edi
    inc %edi
    lea read_set(%rip), %rsi
    lea write_set(%rip), %rdx
    xor %r10d, %r10d
    mov $270, %eax
    syscall
    ret

/* 2. Fill W until EAGAIN. */
fill_w:
    mov $1024, %ebx                /* bound: far beyond any pipe capacity */
1:
    mov fds_w+4(%rip), %edi
    lea chunk(%rip), %rsi
    mov $4096, %edx
    mov $1, %eax
    syscall
    cmp $-11, %rax
    je 2f
    test %rax, %rax
    jle fail_fill
    dec %ebx
    jz fail_fill
    jmp 1b
2:
    ret

poller:
#ifdef TWO_POLLERS
    jmp filled                     /* the parent filled W before forking */
#endif
#if defined(SET_EINTR) || defined(SET_SIGMASK)
    mov $10, %edi
    lea usr1_action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax                  /* rt_sigaction(SIGUSR1, &action, NULL, 8) */
    syscall
    test %rax, %rax
    jnz fail_signal
#endif
    /* 1. W has room: the write bit alone, at once. */
    call set_sets
    movq $5, select_time(%rip)
    movq $0, select_time+8(%rip)
    lea select_time(%rip), %r8
    xor %r9d, %r9d
    call select_call
    cmp $1, %rax
    jne fail_immediate
    cmpq $0, read_set(%rip)
    jne fail_immediate_sets
    cmp %r15, write_set(%rip)
    jne fail_immediate_sets
    call fill_w
filled:
    call set_sets
#ifdef SET_TIMEOUT
    movq $0, select_time(%rip)
    movq $20000000, select_time+8(%rip)
    lea select_time(%rip), %r8
    xor %r9d, %r9d
    call select_call
    test %rax, %rax
    jnz fail_result
    cmpq $0, read_set(%rip)
    jne fail_sets
    cmpq $0, write_set(%rip)
    jne fail_sets
    mov select_time(%rip), %rax
    or select_time+8(%rip), %rax
    jnz fail_time
    xor %edi, %edi
    jmp exit
#else
    /* 3. Nothing is ready: park on every member. */
    xor %r8d, %r8d
#ifdef SET_SIGMASK
    lea usr1_mask_pair(%rip), %r9  /* {&{SIGUSR1}, 8} */
#else
    xor %r9d, %r9d
#endif
    call select_call
#ifdef SET_EINTR
    cmp $-4, %rax
    jne fail_result
    cmpl $1, usr1_seen(%rip)
    jne fail_handler
    xor %edi, %edi
    jmp exit
#else
    cmp $1, %rax
    jne fail_result
    mov fds_b(%rip), %ecx
    mov $1, %eax
    shl %cl, %rax
    cmp %rax, read_set(%rip)       /* exactly B's read bit */
    jne fail_sets
    cmpq $0, write_set(%rip)       /* W is still full */
    jne fail_sets
#ifdef SET_SIGMASK
    xor %edi, %edi                 /* SIG_BLOCK with no set reads the mask */
    xor %esi, %esi
    lea old_mask(%rip), %rdx
    mov $8, %r10d
    mov $14, %eax                  /* rt_sigprocmask */
    syscall
    test %rax, %rax
    jnz fail_signal
    cmpq $0, old_mask(%rip)        /* the persistent mask is back */
    jne fail_signal
    cmpl $1, usr1_seen(%rip)       /* the blocked signal ran afterwards */
    jne fail_handler
#endif
    xor %edi, %edi
    jmp exit
#endif
#endif

fail_pipe:
    mov $10, %edi
    jmp exit
fail_fork:
    mov $11, %edi
    jmp exit
fail_result:
    mov $12, %edi
    jmp exit
fail_sets:
    mov $13, %edi
    jmp exit
fail_time:
    mov $14, %edi
    jmp exit
fail_wait:
    mov $15, %edi
    jmp exit
fail_write:
    mov $16, %edi
    jmp exit
fail_gate:
    mov $17, %edi
    jmp exit
fail_fill:
    mov $18, %edi
    jmp exit
fail_signal:
    mov $19, %edi
    jmp exit
fail_handler:
    mov $20, %edi
    jmp exit
fail_immediate:
    /* The immediate call's errno (38: ENOSYS) or 21 for a wrong count. */
    test %rax, %rax
    jns 1f
    neg %eax
    mov %eax, %edi
    jmp exit
1:
    mov $21, %edi
    jmp exit
fail_immediate_sets:
    mov $22, %edi
exit:
    mov $231, %eax
    syscall
    ud2
#if defined(SET_EINTR) || defined(SET_SIGMASK)
usr1_handler:
    movl $1, usr1_seen(%rip)
    ret
usr1_restorer:
    mov $15, %eax                  /* rt_sigreturn */
    syscall
    ud2
#endif
.data
.balign 16
delay: .quad 0, 50000000
byte: .byte 'x'
#ifndef NO_GATE
.balign 8
select_gate_peer:
    .short 2, SELECT_GATE_PORT
    .byte 127, 0, 0, 1
    .quad 0
#endif
#if defined(SET_EINTR) || defined(SET_SIGMASK)
.balign 8
usr1_action: .quad usr1_handler, 0x04000000, usr1_restorer, 0 /* SA_RESTORER */
usr1_mask: .quad 0x200
usr1_mask_pair: .quad usr1_mask, 8
#endif
.bss
.balign 4096
chunk: .space 4096
fds_a: .space 8
fds_b: .space 8
fds_w: .space 8
pfd: .space 8
read_set: .space 8
write_set: .space 8
select_time: .space 16
poller_pids: .space 8
status: .space 8
received: .space 1
.balign 8
old_mask: .space 8
usr1_seen: .space 4
