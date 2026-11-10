/* Zone pipe readiness: the parent blocks in poll/ppoll on a not-ready pipe
 * read end; a forked child sleeps, then writes one byte. The parent must
 * return 1 with revents == POLLIN while its pollfd fd/events stay intact.
 * Exit 7 = success; every other code names the failed stage. The native
 * oracle (same source) runs under `timeout 10`. -DUSE_POLL selects poll(7).
 * -DWAKE_BY_CLOSE: the parent closes its write end and the child closes the
 * last one instead of writing, so the wake is writer-close POLLHUP.
 * -DZERO_TIMEOUT: poll/ppoll uses a zero timeout while the child sleeps 50ms
 * before closing the last writer, so poll/ppoll must return 0 with revents
 * cleared to 0 before the child closes. */
.global _start
.text
_start:
    /* pipe2(fds, O_CLOEXEC) */
    lea fds(%rip), %rdi
    mov $0x80000, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe
    mov $57, %eax                  /* fork */
    syscall
    test %eax, %eax
    jz child
    js fail_fork
    mov %eax, %r12d
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
#ifdef USE_POLL
#ifdef ZERO_TIMEOUT
    xor %edx, %edx                 /* poll(pfd, 1, 0) */
#else
    mov $-1, %edx                  /* poll(pfd, 1, -1) */
#endif
    mov $7, %eax
#else
#ifdef ZERO_TIMEOUT
    lea zero_ts(%rip), %rdx        /* ppoll(pfd, 1, &{0, 0}, NULL, 8) */
#else
    xor %edx, %edx                 /* ppoll(pfd, 1, NULL, NULL, 8) */
#endif
    xor %r10d, %r10d
    mov $8, %r8d
    mov $271, %eax
#endif
    syscall
    mov %rax, poll_result(%rip)
#ifdef ZERO_TIMEOUT
    test %rax, %rax
    jnz fail_result
    movzwl pfd+6(%rip), %eax
    test %eax, %eax                /* revents cleared to 0 */
    jnz fail_revents
#else
    cmp $1, %rax
    jne fail_result
    movzwl pfd+6(%rip), %eax
#ifdef WAKE_BY_CLOSE
    cmp $0x10, %eax                /* revents == POLLHUP only */
#else
    cmp $1, %eax                   /* revents == POLLIN only */
#endif
    jne fail_revents
#endif
    mov fds(%rip), %eax
    cmp pfd(%rip), %eax
    jne fail_fields
    cmpw $1, pfd+4(%rip)
    jne fail_fields
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
    jne fail_wait
    mov $7, %edi
    jmp exit
child:
#ifndef NO_CHILD_SLEEP
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
    xor %edi, %edi
    jmp exit
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
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 16
delay: .quad 0, 50000000
zero_ts: .quad 0, 0
byte: .byte 'x'
.bss
.balign 4096
fds: .space 8
pfd: .space 8
status: .space 8
poll_result: .space 8
