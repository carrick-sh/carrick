/* #1671: a forked child's write(2) to an in-ring pipe uses shared
 * IPC execution custody. The parent reaps the child and exits with
 * the child's status. Child exit 0 = the write returned 1; otherwise the
 * child exits with the negated errno its write returned (38 = ENOSYS).
 * 90 pipe2 failed, 91 fork/wait failed. With SOCKETPAIR (#2361) the pair
 * is socketpair(AF_UNIX, SOCK_STREAM, 0) instead: 90 is its failure. With
 * SOCKET_FIOCLEX too, the root first sets and clears fds[0]'s close-on-exec
 * flag with ioctl(FIOCLEX/FIONCLEX), checking F_GETFD: 93 is its failure.
 * With SOCKET_TERMINAL (#2385 review) the root instead checks the pair's
 * terminal states and exits 0 without forking: a pipe's zero-length write
 * is 0, even without a reader; a MSG_WAITALL recvfrom after this end's
 * SHUT_RD returns the buffered "abc" (3), then 0 (94 otherwise); a
 * zero-length sendto(MSG_NOSIGNAL) after the peer closed is EPIPE (95
 * otherwise, as for the pipe's). */
.global _start
.text
_start:
#ifdef SOCKETPAIR
    mov $1, %edi                   /* AF_UNIX */
    mov $1, %esi                   /* SOCK_STREAM */
    xor %edx, %edx
    lea fds(%rip), %r10
    mov $53, %eax                  /* socketpair(AF_UNIX, SOCK_STREAM, 0, fds) */
#else
    lea fds(%rip), %rdi
#ifdef EXEC_STATUS
    mov $0x80000, %esi
#else
    xor %esi, %esi
#endif
    mov $293, %eax                 /* pipe2(fds, 0) */
#endif
    syscall
    test %rax, %rax
    jnz fail_pipe
#ifdef SOCKET_TERMINAL
    lea pfds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax                 /* pipe2(pfds, 0) */
    syscall
    test %rax, %rax
    jnz fail_pipe
    mov pfds+4(%rip), %edi
    lea message(%rip), %rsi
    xor %edx, %edx
    mov $1, %eax                   /* write(pfds[1], buf, 0) */
    syscall
    test %rax, %rax
    jnz fail_zero
    mov pfds(%rip), %edi
    mov $3, %eax                   /* close(pfds[0]) */
    syscall
    test %rax, %rax
    jnz fail_zero
    mov pfds+4(%rip), %edi
    lea message(%rip), %rsi
    xor %edx, %edx
    mov $1, %eax                   /* write(pfds[1], buf, 0): still 0 */
    syscall
    test %rax, %rax
    jnz fail_zero
    mov fds+4(%rip), %edi
    lea abc(%rip), %rsi
    mov $3, %edx
    mov $1, %eax                   /* write(fds[1], "abc", 3) */
    syscall
    cmp $3, %rax
    jne fail_waitall
    mov fds(%rip), %edi
    xor %esi, %esi
    mov $48, %eax                  /* shutdown(fds[0], SHUT_RD) */
    syscall
    test %rax, %rax
    jnz fail_waitall
    mov fds(%rip), %edi
    lea waited(%rip), %rsi
    mov $6, %edx
    mov $0x100, %r10d              /* MSG_WAITALL */
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $45, %eax                  /* recvfrom(fds[0], waited, 6, MSG_WAITALL) */
    syscall
    cmp $3, %rax
    jne fail_waitall
    cmpb $'a', waited(%rip)
    jne fail_waitall
    cmpb $'c', waited+2(%rip)
    jne fail_waitall
    mov fds(%rip), %edi
    lea waited(%rip), %rsi
    mov $6, %edx
    mov $0x100, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $45, %eax                  /* drained and shut: 0 */
    syscall
    test %rax, %rax
    jnz fail_waitall
    mov fds+4(%rip), %edi
    mov $3, %eax                   /* close(fds[1]) */
    syscall
    test %rax, %rax
    jnz fail_zero
    mov fds(%rip), %edi
    lea message(%rip), %rsi
    xor %edx, %edx
    mov $0x4000, %r10d             /* MSG_NOSIGNAL */
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $44, %eax                  /* sendto(fds[0], buf, 0, MSG_NOSIGNAL) */
    syscall
    cmp $-32, %rax                 /* EPIPE */
    jne fail_zero
    xor %edi, %edi
    jmp exit
#endif
#ifdef SOCKET_FIOCLEX
    mov fds(%rip), %edi
    mov $0x5451, %esi
    mov $16, %eax                  /* ioctl(fds[0], FIOCLEX) */
    syscall
    test %rax, %rax
    jnz fail_cloexec
    mov fds(%rip), %edi
    mov $1, %esi
    mov $72, %eax                  /* fcntl(fds[0], F_GETFD) */
    syscall
    cmp $1, %rax                   /* FD_CLOEXEC */
    jne fail_cloexec
    mov fds(%rip), %edi
    mov $0x5450, %esi
    mov $16, %eax                  /* ioctl(fds[0], FIONCLEX) */
    syscall
    test %rax, %rax
    jnz fail_cloexec
    mov fds(%rip), %edi
    mov $1, %esi
    mov $72, %eax                  /* fcntl(fds[0], F_GETFD) */
    syscall
    test %rax, %rax
    jnz fail_cloexec
#endif
    mov $57, %eax                  /* fork */
    syscall
    test %eax, %eax
    js fail_wait
    jz child
#ifdef READ_CHILD
    mov %eax, %r12d
#ifdef EXEC_STATUS
    mov fds+4(%rip), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz fail_read
#endif
    mov fds(%rip), %edi
#ifdef READV_CHILD
    lea vectors(%rip), %rsi
    mov $2, %edx
    mov $19, %eax
#else
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax                 /* read while child is alive */
#endif
    syscall
#ifdef READV_CHILD
    cmp $2, %rax
    jne fail_read
    cmpb $'Q', received_second(%rip)
    jne fail_read
#else
    cmp $1, %rax
    jne fail_read
#endif
    cmpb $'P', received(%rip)
    jne fail_read
#ifdef EXEC_STATUS
    mov fds(%rip), %edi
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    test %rax, %rax                /* last-writer exit supplies EOF */
    jnz fail_read
#endif
    mov %r12d, %eax
#endif
    mov %eax, %edi                 /* wait4(child, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js fail_wait
    movzbl status+1(%rip), %edi    /* WEXITSTATUS */
    jmp exit
child:
#ifdef EXEC_STATUS
    lea missing_path(%rip), %rdi
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax                  /* execve failure reports over CLOEXEC pipe */
    syscall
    test %rax, %rax
    jns fail_read
#endif
    mov fds+4(%rip), %edi          /* write(fds[1], "P", 1) */
    lea message(%rip), %rsi
#ifdef READV_CHILD
    mov $2, %edx
#else
    mov $1, %edx
#endif
    mov $1, %eax
    syscall
#ifdef READV_CHILD
    cmp $2, %rax
#else
    cmp $1, %rax
#endif
    je child_ok
    neg %rax
    mov %eax, %edi
    jmp exit
child_ok:
    xor %edi, %edi
    jmp exit
fail_read:
    mov $92, %edi
    jmp exit
fail_pipe:
    mov $90, %edi
    jmp exit
fail_cloexec:
    mov $93, %edi
    jmp exit
fail_waitall:
    mov $94, %edi
    jmp exit
fail_zero:
    mov $95, %edi
    jmp exit
fail_wait:
    mov $91, %edi
exit:
    mov $231, %eax                 /* exit_group */
    syscall
    ud2

.data
fds: .long -1, -1
pfds: .long -1, -1
abc: .ascii "abc"
waited: .space 6
status: .long 0
received: .byte 0
message: .ascii "PQ"
received_second: .byte 0
.balign 8
vectors: .quad received, 1, received_second, 1

missing_path: .asciz "/carrick-missing-exec-status-target"
.balign 8
argv: .quad missing_path, 0
