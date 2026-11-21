/* -DUSE_EPOLL waits through an in-ring epoll watching the same pipe.
 * Zone pipe readiness: the parent blocks in poll/ppoll on a not-ready pipe
 * read end; a forked child sleeps, then writes one byte. The parent must
 * return 1 with revents == POLLIN while its pollfd fd/events stay intact.
 * Exit 7 = success; every other code names the failed stage. The native
 * oracle (same source) runs under `timeout 10`. -DUSE_POLL selects poll(7).
 * -DCHILD_POLLS reverses the peers: child polls/reads, parent writes/reaps.
 * -DWAKE_BY_CLOSE: the parent closes its write end and the child closes the
 * last one instead of writing, so the wake is writer-close POLLHUP.
 * -DZERO_TIMEOUT: poll/ppoll uses a zero timeout while the child sleeps 50ms
 * before closing the last writer, so poll/ppoll must return 0 with revents
 * cleared to 0 before the child closes.
 * -DFINITE_TIMEOUT: poll uses 1 ms, ppoll {0, 1ms}; with the child sleeping
 * 50ms the call must time out (0, revents cleared). -DFINITE_TIMEOUT_LONG:
 * the same finite calls with 5 s, so a prompt writer close wins (1, POLLHUP).
 * With -DUSE_PSELECT -DCHILD_POLLS the writer is a sibling that writes only
 * after the host has seen the reader's wait enrolled (SELECT_GATE_PORT).
 * -DPARENT_WRITES: the reader's parent, itself a fork child the root
 * reaps, is that writer. -DEXEC_WRITER: the
 * writer makes the pipe its stdout and execs SUCCESSOR_PATH, which writes
 * "X\n" (apt's method shape). -DSELECT_SIGMASK: the reader catches SIGUSR1
 * and selects with a temporary mask blocking it; the writer sends SIGUSR1
 * before writing. The wait must report the pipe, not EINTR, restore the
 * empty persistent mask, and then run the handler. */
.global _start
.text
_start:
#ifdef SELECT_TIMEOUT_EOF
    mov $57, %eax                  /* child owns the only copies of the pipe */
    syscall
    test %eax, %eax
    js fail_fork
    jz timed_pselect_child
    mov %eax, %r12d
    jmp wait_for_child
#endif
    /* pipe2(fds, O_CLOEXEC) */
    lea fds(%rip), %rdi
    mov $0x80000, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe
#ifdef USE_EPOLL
    xor %edi, %edi
    mov $291, %eax                 /* epoll_create1(0) */
    syscall
    test %eax, %eax
    js fail_pipe
    mov %eax, %r13d
    mov %r13d, %edi
    mov $1, %esi                   /* EPOLL_CTL_ADD */
    mov fds(%rip), %edx
    lea interest(%rip), %r10
    mov $233, %eax
    syscall
    test %eax, %eax
    jnz fail_pipe
#endif
#ifdef USE_PSELECT
    /* First call sees an already readable pipe. */
    mov fds+4(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne fail_pipe
#endif
#ifdef PARENT_WRITES
    mov $57, %eax                  /* the root only reaps the writing parent */
    syscall
    test %eax, %eax
    js fail_fork
    jz 1f
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    movzbl status+1(%rip), %edi    /* the parent's verdict, 7 on success */
    jmp exit
1:
#endif
    mov $57, %eax                  /* fork */
    syscall
    test %eax, %eax
    js fail_fork
#ifdef CHILD_POLLS
    jz poller
    mov %eax, %r12d
#ifdef USE_PSELECT
#ifdef PARENT_WRITES
    jmp child                      /* the reader's parent is the writer */
#else
    mov $57, %eax                  /* fork a sibling writer */
    syscall
    test %eax, %eax
    js fail_fork
    jz child
    mov %eax, %r15d
    jmp wait_for_child
#endif
#else
    jmp child
#endif
poller:
#ifdef USE_PSELECT
    jmp pselect_reader
#endif
#else
    jz child
    mov %eax, %r12d
#endif
#ifdef WAKE_BY_CLOSE
    mov fds+4(%rip), %edi
    mov $3, %eax                   /* close(fds[1]) */
    syscall
    test %rax, %rax
    jnz fail_close
#endif
    /* pollfd = { fd: fds[0], events: POLLIN, revents: 0x5a5a } */
    mov fds(%rip), %eax
    mov %eax, pfd(%rip)
    movw $1, pfd+4(%rip)
    movw $0x5a5a, pfd+6(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
#ifdef USE_EPOLL
    mov %r13d, %edi
    lea epoll_event(%rip), %rsi
    mov $1, %edx
    mov $-1, %r10d                 /* epoll_pwait(ep, events, 1, -1, NULL, 8) */
    xor %r8d, %r8d
    mov $8, %r9d
#ifdef USE_LEGACY_EPOLL
    /* epoll_wait has four args: ignored registers must not become a mask. */
    mov $1, %r8d
    mov $0xdead, %r9d
    mov $232, %eax
#else
    mov $281, %eax
#endif
#elif defined(USE_POLL)
#ifdef ZERO_TIMEOUT
    xor %edx, %edx                 /* poll(pfd, 1, 0) */
#elif defined(FINITE_TIMEOUT)
    mov $1, %edx                   /* poll(pfd, 1, 1ms) */
#elif defined(FINITE_TIMEOUT_LONG)
    mov $5000, %edx                /* poll(pfd, 1, 5000ms) */
#else
    mov $-1, %edx                  /* poll(pfd, 1, -1) */
#endif
    mov $7, %eax
#else
#ifdef ZERO_TIMEOUT
    lea zero_ts(%rip), %rdx        /* ppoll(pfd, 1, &{0, 0}, NULL, 8) */
#elif defined(FINITE_TIMEOUT)
    lea short_ts(%rip), %rdx       /* ppoll(pfd, 1, &{0, 1ms}, NULL, 8) */
#elif defined(FINITE_TIMEOUT_LONG)
    lea long_ts(%rip), %rdx        /* ppoll(pfd, 1, &{5s, 0}, NULL, 8) */
#else
    xor %edx, %edx                 /* ppoll(pfd, 1, NULL, NULL, 8) */
#endif
    xor %r10d, %r10d
    mov $8, %r8d
    mov $271, %eax
#endif
    syscall
    mov %rax, poll_result(%rip)
#if defined(ZERO_TIMEOUT) || defined(FINITE_TIMEOUT)
    test %rax, %rax
    jnz fail_result
    movzwl pfd+6(%rip), %eax
    test %eax, %eax                /* revents cleared to 0 */
    jnz fail_revents
#else
    cmp $1, %rax
    jne fail_result
#ifdef USE_EPOLL
    cmpl $1, epoll_event(%rip)
    jne fail_revents
    cmpq $0x1671, epoll_event+4(%rip)
    jne fail_revents
#else
    movzwl pfd+6(%rip), %eax
#ifdef WAKE_BY_CLOSE
    cmp $0x10, %eax                /* revents == POLLHUP only */
#else
    cmp $1, %eax                   /* revents == POLLIN only */
#endif
    jne fail_revents
#endif
#endif
    mov fds(%rip), %eax
    cmp pfd(%rip), %eax
    jne fail_fields
    cmpw $1, pfd+4(%rip)
    jne fail_fields
#ifdef EPOLL_INPUT_FAULT
    mov %r13d, %edi
    lea epoll_event(%rip), %rsi
    mov $1, %edx
    mov $1, %r10d                  /* unmapped timespec */
    xor %r8d, %r8d
    mov $8, %r9d
    mov $441, %eax                 /* epoll_pwait2 */
    syscall
    cmp $-14, %rax                 /* input owner EFAULT, never rax=441 */
    jne fail_input
#endif
#ifdef CHILD_POLLS
    mov fds(%rip), %edi
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne fail_result
    cmpb $'x', received(%rip)
    jne fail_revents
    xor %edi, %edi
    jmp exit
#endif
wait_for_child:
    /* wait4(child, &status, 0, NULL) */
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fail_wait
    cmpl $0, status(%rip)
#ifdef USE_PSELECT
    je 1f
    movzbl status+1(%rip), %edi
    test %edi, %edi
    jz fail_wait
    jmp exit
1:
#if !defined(SELECT_TIMEOUT_EOF) && !defined(PARENT_WRITES)
    mov %r15d, %edi              /* reap the sibling writer as well */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15d, %eax
    jne fail_wait
    cmpl $0, status(%rip)
    jne fail_wait
#endif
#else
    jne fail_wait
#endif
    mov $7, %edi
    jmp exit
child:
#ifdef USE_PSELECT
    /* The host echoes only once the reader's select has parked. */
    mov $2, %edi                  /* AF_INET */
    mov $2, %esi                  /* SOCK_DGRAM */
    xor %edx, %edx
    mov $41, %eax
    syscall
    test %rax, %rax
    js child_fail
    mov %eax, %r13d
    mov %r13d, %edi
    lea select_gate_peer(%rip), %rsi
    mov $16, %edx
    mov $42, %eax                 /* connect */
    syscall
    test %rax, %rax
    jnz child_fail
    mov %r12d, reader_pid(%rip)
    mov %r13d, %edi
    lea reader_pid(%rip), %rsi
    mov $4, %edx
    mov $1, %eax
    syscall
    cmp $4, %rax
    jne child_fail
    mov %r13d, pfd(%rip)
    movw $1, pfd+4(%rip)
    movw $0, pfd+6(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
    mov $8000, %edx               /* bound fixture cleanup */
    mov $7, %eax
    syscall
    cmp $1, %rax
    jne child_fail
    mov %r13d, %edi
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne child_fail
#ifdef SELECT_SIGMASK
    mov %r12d, %edi
    mov $10, %esi
    mov $62, %eax                 /* kill(reader, SIGUSR1) while it waits */
    syscall
    test %rax, %rax
    jnz child_fail
#endif
#ifdef EXEC_WRITER
    mov fds+4(%rip), %edi
    mov $1, %esi
    xor %edx, %edx
    mov $292, %eax                /* dup3(fds[1], 1, 0): stdout survives exec */
    syscall
    cmp $1, %rax
    jne child_fail
    lea successor(%rip), %rdi
    lea successor_argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax                 /* execve(SUCCESSOR_PATH) */
    syscall
    jmp child_fail
#endif
#elif !defined(NO_CHILD_SLEEP)
    /* nanosleep({0, 50ms}) so the parent is parked before the write. */
    lea delay(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
#endif
    mov fds+4(%rip), %edi
#ifdef WAKE_BY_CLOSE
    mov $3, %eax                   /* close(fds[1]): the last writer */
    syscall
    test %rax, %rax
    jnz child_fail
#else
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax                   /* write(fds[1], "x", 1) */
    syscall
    cmp $1, %rax
    jne child_fail
#endif
#if defined(CHILD_POLLS) && (!defined(USE_PSELECT) || defined(PARENT_WRITES))
    jmp wait_for_child
#else
    xor %edi, %edi
    jmp exit
#endif
#ifdef USE_PSELECT
#ifdef SELECT_TIMEOUT_EOF
timed_pselect_child:
    lea fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax                 /* pipe2 */
    syscall
    test %rax, %rax
    jnz fail_pipe
    movq $20000000, select_time+8(%rip)
    call select_call
    test %rax, %rax
    jnz fail_result
    cmpq $0, read_set(%rip)
    jne fail_revents
    mov select_time(%rip), %rax
    or select_time+8(%rip), %rax
    jnz fail_fields
    mov fds+4(%rip), %edi
    mov $3, %eax                   /* close the last writer */
    syscall
    test %rax, %rax
    jnz fail_close
    call select_call
    cmp $1, %rax
    jne fail_result
    cmp %r14, read_set(%rip)
    jne fail_revents
    xor %edi, %edi
    jmp exit
#endif
pselect_reader:
#ifdef SELECT_SIGMASK
    mov $10, %edi
    lea usr1_action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax                  /* rt_sigaction(SIGUSR1, &action, NULL, 8) */
    syscall
    test %rax, %rax
    jnz fail_signal
#endif
#ifdef USE_SELECT_TIMEVAL
    movq $-1, select_time+8(%rip)
    call select_call
    cmp $-22, %rax
    jne fail_result
#endif
    call pselect_one
    call pselect_one
#ifdef SELECT_SIGMASK
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

pselect_one:
#ifdef USE_SELECT_TIMEVAL
    /* 30 seconds encoded entirely in microseconds; Linux normalizes it. */
    movq $0, select_time(%rip)
    movq $30000000, select_time+8(%rip)
#endif
    call select_call
    test %rax, %rax
    js pselect_errno
    cmp $1, %rax
    jne fail_result
    cmp %r14, read_set(%rip)
    jne fail_revents
#ifdef USE_SELECT_TIMEVAL
    cmpq $0, select_time(%rip)
    jl fail_fields
    cmpq $30, select_time(%rip)
    jge fail_fields
    cmpq $1000000, select_time+8(%rip)
    jae fail_fields
#endif
    mov fds(%rip), %edi
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne fail_result
#ifdef EXEC_WRITER
    movzbl received(%rip), %eax
    or $0x20, %eax                 /* the successor writes 'X' */
    cmp $'x', %eax
#else
    cmpb $'x', received(%rip)
#endif
    jne fail_revents
    ret

select_call:
    mov fds(%rip), %ecx
    mov $1, %r14d
    shl %cl, %r14
    mov %r14, read_set(%rip)
    lea 1(%rcx), %edi
    lea read_set(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
#ifdef USE_SELECT_TIMEVAL
    lea select_time(%rip), %r8
    mov $23, %eax                  /* select(nfds, &set, 0, 0, &timeval) */
#else
#ifdef SELECT_TIMEOUT_EOF
    lea select_time(%rip), %r8
#endif
#ifdef SELECT_SIGMASK
    lea usr1_mask_pair(%rip), %r9  /* {&{SIGUSR1}, 8} */
#endif
    mov $270, %eax                 /* pselect6 */
#endif
    syscall
    ret
pselect_errno:
    neg %eax
    mov %eax, %edi
    jmp exit
#endif
child_fail:
    mov $9, %edi
    jmp exit
fail_pipe:
    mov $10, %edi
    jmp exit
fail_fork:
    mov $11, %edi
    jmp exit
fail_result:
    mov $12, %edi
    jmp exit
fail_revents:
    mov $13, %edi
    jmp exit
fail_fields:
    mov $14, %edi
    jmp exit
fail_wait:
    mov $15, %edi
    jmp exit
fail_close:
    mov $16, %edi
    jmp exit
fail_input:
    mov $18, %edi
    jmp exit
fail_signal:
    mov $19, %edi
    jmp exit
fail_handler:
    mov $20, %edi
exit:
    mov $231, %eax
    syscall
    ud2
#ifdef SELECT_SIGMASK
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
interest: .long 1
          .quad 0x1671
delay: .quad 0, 50000000
zero_ts: .quad 0, 0
short_ts: .quad 0, 1000000
long_ts: .quad 5, 0
byte: .byte 'x'
#ifdef USE_PSELECT
.balign 8
select_gate_peer:
    .short 2, SELECT_GATE_PORT
    .byte 127, 0, 0, 1
    .quad 0
#endif
#ifdef SELECT_SIGMASK
.balign 8
usr1_action: .quad usr1_handler, 0x04000000, usr1_restorer, 0 /* SA_RESTORER */
usr1_mask: .quad 0x200
usr1_mask_pair: .quad usr1_mask, 8
#endif
#ifdef EXEC_WRITER
successor: .asciz SUCCESSOR_PATH
.balign 8
successor_argv: .quad successor, 0
#endif
.bss
.balign 4096
fds: .space 8
pfd: .space 8
read_set: .space 8
select_time: .space 16
reader_pid: .space 4
status: .space 8
poll_result: .space 8
received: .space 1
.balign 8
old_mask: .space 8
usr1_seen: .space 4

.balign 16
epoll_event: .space 12
