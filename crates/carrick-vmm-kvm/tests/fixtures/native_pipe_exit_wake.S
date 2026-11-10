/* Exit-drain pipe wakes (#2031): the parent parks on a zone pipe and the
 * forked child's exit retires its descriptor table, closing the last peer.
 * Default: the parent closes its write end and blocks in
 * ppoll(fds[0], POLLIN); the child's exit closes the last writer, so ppoll
 * must return 1 with revents == POLLHUP. -DUSE_POLL selects poll(7).
 * -DREAD_EOF: the parent blocks in read(fds[0]) instead and it must return
 * 0 (EOF).
 * -DLAST_READER: the parent closes its read end, fills the pipe, then
 * blocks in a one-byte write; the child's exit closes the last reader, so
 * the write must fail with EPIPE and SIGPIPE (blocked) must be pending.
 * The child sleeps 50 ms first so the parent is parked before the exit.
 * Exit 7 = success; every other code names the failed stage. The native
 * oracle (same source) runs under `timeout 10`. */
.global _start
.text
_start:
    /* rt_sigprocmask(SIG_BLOCK, {SIGPIPE}, NULL, 8) */
    xor %edi, %edi
    lea pipe_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    jnz fail_mask
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
#ifdef LAST_READER
    mov fds(%rip), %edi
    mov $3, %eax                   /* close(fds[0]) */
    syscall
    test %rax, %rax
    jnz fail_close
    /* write(fds[1], fill, 65536): fills the default pipe capacity. */
    mov fds+4(%rip), %edi
    lea fill(%rip), %rsi
    mov $65536, %edx
    mov $1, %eax
    syscall
    cmp $65536, %rax
    jne fail_fill
    /* write(fds[1], fill, 1): parks until the last reader exits. */
    mov fds+4(%rip), %edi
    lea fill(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    mov %rax, io_result(%rip)
    cmp $-32, %rax                 /* -EPIPE */
    jne fail_result
    /* rt_sigpending(&pending, 8): SIGPIPE (13) must be pending. */
    lea pending(%rip), %rdi
    mov $8, %esi
    mov $127, %eax
    syscall
    test %rax, %rax
    jnz fail_signal
    mov pending(%rip), %rax
    test $0x1000, %rax
    jz fail_signal
#else
    mov fds+4(%rip), %edi
    mov $3, %eax                   /* close(fds[1]) */
    syscall
    test %rax, %rax
    jnz fail_close
#ifndef READ_EOF
    /* pollfd = { fd: fds[0], events: POLLIN, revents: 0x5a5a } */
    mov fds(%rip), %eax
    mov %eax, pfd(%rip)
    movw $1, pfd+4(%rip)
    movw $0x5a5a, pfd+6(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
#ifdef USE_POLL
    mov $-1, %edx                  /* poll(pfd, 1, -1) */
    mov $7, %eax
#else
    xor %edx, %edx                 /* ppoll(pfd, 1, NULL, NULL, 8) */
    xor %r10d, %r10d
    mov $8, %r8d
    mov $271, %eax
#endif
    syscall
    mov %rax, io_result(%rip)
    cmp $1, %rax
    jne fail_result
    movzwl pfd+6(%rip), %eax
    cmp $0x10, %eax                /* revents == POLLHUP only */
    jne fail_revents
#else
    /* read(fds[0], buffer, 1): parks until the last writer exits. */
    mov fds(%rip), %edi
    lea buffer(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    mov %rax, io_result(%rip)
    test %rax, %rax                /* 0 = EOF */
    jnz fail_result
#endif
#endif
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
    /* nanosleep({0, 50ms}), then exit holding the peer end: the exit's
     * table retirement closes it. */
    lea delay(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    xor %edi, %edi
    jmp exit
fail_pipe:
    mov $10, %edi
    jmp exit
fail_fork:
    mov $11, %edi
    jmp exit
fail_result:
#ifdef ERRNO_EXIT
    mov io_result(%rip), %rdi
    neg %rdi
    add $100, %edi
#else
    mov $12, %edi
#endif
    jmp exit
fail_signal:
    mov $13, %edi
    jmp exit
fail_fill:
#ifdef ERRNO_EXIT
    mov %rax, %rdi
    neg %rdi
    add $100, %edi
#else
    mov $14, %edi
#endif
    jmp exit
fail_wait:
    mov $15, %edi
    jmp exit
fail_close:
    mov $16, %edi
    jmp exit
fail_revents:
    mov $18, %edi
    jmp exit
fail_mask:
    mov $17, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 16
delay: .quad 0, 50000000
pipe_mask: .quad 0x1000
.bss
.balign 4096
fds: .space 8
status: .space 8
io_result: .space 8
pending: .space 8
pfd: .space 8
buffer: .space 8
.balign 4096
fill: .space 65536
