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
 * -DSELECT_CAUGHT_SIGNAL: the sibling sends SIGUSR1 after a timed pselect6
 * parks. The reader checks EINTR, the handler count, and the remaining time.
 * -DSELECT_STOP_CONT: the sibling sends SIGSTOP after that same gate. The
 * parent must reap a WUNTRACED stop event before sending SIGCONT and writing
 * the readiness byte. The reader requires a successful timed pselect6. */
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
    mov $57, %eax                  /* fork */
    syscall
    test %eax, %eax
    js fail_fork
#ifdef CHILD_POLLS
    jz poller
    mov %eax, %r12d
#ifdef USE_PSELECT
    mov $57, %eax                  /* fork a sibling writer */
    syscall
    test %eax, %eax
    js fail_fork
    jz child
    mov %eax, %r15d
#ifdef SELECT_CAUGHT_SIGNAL
    /* The signaler has a bounded gate wait even if the reader is suspended. */
    mov %r15d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15d, %eax
    jne fail_wait
    cmpl $0, status(%rip)
    jne child_fail
#endif
#ifdef SELECT_STOP_CONT
    mov %r12d, %edi
    lea status(%rip), %rsi
    mov $2, %edx                  /* WUNTRACED */
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fail_wait
    cmpl $0x137f, status(%rip)     /* WIFSTOPPED with WSTOPSIG == SIGSTOP */
    jne fail_stop

    mov %r12d, %edi
    mov $18, %esi                 /* SIGCONT */
    mov $62, %eax
    syscall
    test %rax, %rax
    jnz fail_continue

    mov fds+4(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne fail_pipe
#endif
    jmp wait_for_child
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
#if !defined(SELECT_TIMEOUT_EOF) && !defined(SELECT_CAUGHT_SIGNAL)
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
    call select_gate_wait
#ifdef SELECT_CAUGHT_SIGNAL
    mov %r12d, %edi
    mov $10, %esi                 /* kill(reader, SIGUSR1) */
    mov $62, %eax
    syscall
    test %rax, %rax
    jnz child_fail
    call select_gate_wait         /* require the reader to retire */
    xor %edi, %edi
    jmp exit
#elif defined(SELECT_STOP_CONT)
    mov %r12d, %edi
    mov $19, %esi                 /* kill(reader, SIGSTOP) */
    mov $62, %eax
    syscall
    test %rax, %rax
    jnz child_fail
    xor %edi, %edi
    jmp exit
#endif
    jmp wake_pipe
select_gate_wait:
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
    cmpb $'w', received(%rip)
    jne child_fail
    ret
#elif !defined(NO_CHILD_SLEEP)
    /* nanosleep({0, 50ms}) so the parent is parked before the write. */
    lea delay(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
#endif
wake_pipe:
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
#if defined(CHILD_POLLS) && !defined(USE_PSELECT)
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
#ifdef SELECT_CAUGHT_SIGNAL
    mov $10, %edi                  /* rt_sigaction(SIGUSR1, &action, NULL, 8) */
    lea signal_action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    jnz fail_sigaction
#endif
#ifdef USE_SELECT_TIMEVAL
    movq $-1, select_time+8(%rip)
    call select_call
    cmp $-22, %rax
    jne fail_result
#endif
    call pselect_one
#ifdef SELECT_CAUGHT_SIGNAL
    movq $8, select_time(%rip)
    call select_call
    cmp $-4, %rax                  /* raw pselect6 returns -EINTR */
    jne fail_result
    cmpl $1, signal_count(%rip)    /* handler returned through rt_sigreturn */
    jne fail_handler
    call check_select_remaining
#elif defined(SELECT_STOP_CONT)
    movq $8, select_time(%rip)
    call pselect_one
    call check_select_remaining
#else
    call pselect_one
#endif
    xor %edi, %edi
    jmp exit

#if defined(SELECT_CAUGHT_SIGNAL) || defined(SELECT_STOP_CONT)
check_select_remaining:
    cmpq $8, select_time(%rip)
    jae fail_fields
    cmpq $1000000000, select_time+8(%rip)
    jae fail_fields
    mov select_time(%rip), %rax
    or select_time+8(%rip), %rax
    jz fail_fields
    ret
#endif

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
    cmpb $'x', received(%rip)
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
#if defined(SELECT_TIMEOUT_EOF) || defined(SELECT_CAUGHT_SIGNAL) || defined(SELECT_STOP_CONT)
    lea select_time(%rip), %r8
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
#ifdef SELECT_CAUGHT_SIGNAL
select_signal_handler:
    incl signal_count(%rip)
    ret
select_signal_restorer:
    mov $15, %eax                  /* rt_sigreturn */
    syscall
    ud2
fail_sigaction:
    mov $19, %edi
    jmp exit
fail_handler:
    mov $20, %edi
    jmp exit
#endif
#ifdef SELECT_STOP_CONT
fail_stop:
    mov $21, %edi
    jmp exit
fail_continue:
    mov $22, %edi
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
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 16
interest: .long 1
          .quad 0x1671
delay: .quad 0, 50000000
zero_ts: .quad 0, 0
short_ts: .quad 0, 1000000
long_ts: .quad 5, 0
byte: .byte 'x'
#ifdef SELECT_CAUGHT_SIGNAL
.balign 8
signal_action:
    .quad select_signal_handler, 0x04000000 /* SA_RESTORER */
    .quad select_signal_restorer, 0
#endif
#ifdef USE_PSELECT
.balign 8
select_gate_peer:
    .short 2, SELECT_GATE_PORT
    .byte 127, 0, 0, 1
    .quad 0
#endif
.bss
.balign 4096
fds: .space 8
pfd: .space 8
read_set: .space 8
select_time: .space 16
reader_pid: .space 4
signal_count: .space 4
status: .space 8
poll_result: .space 8
received: .space 1

.balign 16
epoll_event: .space 12
