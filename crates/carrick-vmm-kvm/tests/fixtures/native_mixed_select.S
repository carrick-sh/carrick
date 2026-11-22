/* #2621: apt's http method shape: a select set that mixes a zone pipe and
 * a HOST socket. The root forks a native parent that makes a pipe P and
 * forks a poller. The poller (like apt's method, whose stdin is a zone
 * pipe) opens a non-blocking AF_INET stream socket S and connects it to the
 * host's TCP_PORT (0 or EINPROGRESS), then:
 *   1. pselect6(nfds, {P reader}, {S}, NULL, {5 s}, NULL): the connect
 *      completes, so the answer is S's write bit alone (P is empty).
 *      -DSINGLE leaves out the read set: pselect6(S + 1, NULL, {S}, ...),
 *      apt's connect wait.
 *      -DCONNECT_DELAYED: the host's listener queue is full, so the connect
 *      stays in progress; the parent gates on the poller's enrolment, then
 *      the host frees the queue and the connect completes after a delay.
 * Then, by variant (S connected; the host peer holds the other end):
 *   -DSOCKET_WAKE: pselect6(nfds, {P, S}, NULL, NULL, NULL, NULL) parks;
 *      once the host saw the poller enrolled it writes to S's peer: the
 *      answer is exactly S's read bit.
 *   -DPIPE_WAKE: the same park; the parent writes P after the gate: the
 *      answer is exactly P's read bit.
 *   -DSET_TIMEOUT: a {0, 20 ms} pselect6 on {P, S} returns 0 with the set
 *      and the timeout cleared.
 *   -DFILE_SET: the poller opens FILE_PATH (a host regular file, created)
 *      as F, then pselect6(nfds, {P, F}, {F}, NULL, {5 s}, NULL): a regular
 *      file is always readable and writable, so the answer is 2 with F's
 *      bit in both sets and P's clear (apt's download target).
 *   -DCLOSE_MEMBER: S, now a member of the poller's host set, is closed;
 *      pselect6(nfds, {P}, {S}, NULL, {0, 20 ms}, NULL) is EBADF (no stale
 *      member answers for it). A new socket S' takes S's number and
 *      connects to the same peer; pselect6(nfds, {P}, {S'}, NULL, {5 s},
 *      NULL) is exactly S''s write bit (it enrols afresh).
 * A select that fails exits with its errno (38: ENOSYS, the refusal);
 * exit 7 = success; every other code names the failed stage. */
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
    lea fds_p(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax                 /* pipe2(P, 0) */
    syscall
    test %rax, %rax
    jnz fail_pipe
    mov $57, %eax                  /* fork the poller */
    syscall
    test %eax, %eax
    js fail_fork
    jz poller
    mov %eax, %r12d
    mov %r12d, poller_pids(%rip)
#if defined(CONNECT_DELAYED) || defined(SOCKET_WAKE) || defined(PIPE_WAKE)
    call gate
#endif
#ifdef PIPE_WAKE
    mov fds_p+4(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax                   /* write(P, "x", 1): the one wake */
    syscall
    cmp $1, %rax
    jne fail_write
#endif
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax                  /* wait4(poller) */
    syscall
    cmp %r12d, %eax
    jne fail_wait
    cmpl $0, status(%rip)
    je 1f
    movzbl status+1(%rip), %edi    /* the poller's stage code */
    test %edi, %edi
    jz fail_wait
    jmp exit
1:
    mov $7, %edi
    jmp exit

/* Hand the poller pid to the host and wait until it has seen the poller
 * enrolled in its wait (and acted, for the host-side variants). */
gate:
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
    mov $1, %eax                   /* send the poller pid */
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

/* nfds = max(P reader, S) + 1 in edi. */
nfds:
    mov fds_p(%rip), %edi
    mov sock(%rip), %eax
    cmp %eax, %edi
    cmovl %eax, %edi
    inc %edi
    ret

/* r14 = P reader's bit, r15 = S's bit. */
bits:
    mov fds_p(%rip), %ecx
    mov $1, %r14d
    shl %cl, %r14
    mov sock(%rip), %ecx
    mov $1, %r15d
    shl %cl, %r15
    ret

poller:
    mov $2, %edi                   /* AF_INET */
    mov $0x801, %esi               /* SOCK_STREAM | SOCK_NONBLOCK */
    xor %edx, %edx
    mov $41, %eax                  /* socket */
    syscall
    test %rax, %rax
    js fail_socket
    mov %eax, sock(%rip)
    mov %eax, %edi
    lea tcp_peer(%rip), %rsi
    mov $16, %edx
    mov $42, %eax                  /* connect: 0 or EINPROGRESS */
    syscall
    test %rax, %rax
    jz 1f
    cmp $-115, %rax
    jne fail_connect
1:
    /* 1. The connect wait: S's write bit alone. */
    call bits
    movq $0, read_set(%rip)
#ifndef SINGLE
    mov %r14, read_set(%rip)
#endif
    mov %r15, write_set(%rip)
    movq $5, select_time(%rip)
    movq $0, select_time+8(%rip)
    call nfds
#ifdef SINGLE
    xor %esi, %esi
#else
    lea read_set(%rip), %rsi
#endif
    lea write_set(%rip), %rdx
    xor %r10d, %r10d
    lea select_time(%rip), %r8
    xor %r9d, %r9d
    mov $270, %eax                 /* pselect6 */
    syscall
    test %rax, %rax
    js fail_errno
    cmp $1, %rax
    jne fail_connect_result
    cmpq $0, read_set(%rip)
    jne fail_connect_sets
    cmp %r15, write_set(%rip)
    jne fail_connect_sets
    mov sock(%rip), %edi
    mov $1, %esi                   /* SOL_SOCKET */
    mov $4, %edx                   /* SO_ERROR */
    lea so_error(%rip), %r10
    lea so_error_len(%rip), %r8
    movl $4, so_error_len(%rip)
    mov $55, %eax                  /* getsockopt */
    syscall
    test %rax, %rax
    jnz fail_connect
    cmpl $0, so_error(%rip)
    jne fail_connect
#ifdef FILE_SET
    /* 2. A host regular file beside the zone pipe. */
    mov $-100, %edi                /* AT_FDCWD */
    lea file_path(%rip), %rsi
    mov $0x42, %edx                /* O_RDWR | O_CREAT */
    mov $0600, %r10d
    mov $257, %eax                 /* openat */
    syscall
    test %rax, %rax
    js fail_open
    mov %eax, file_fd(%rip)
    mov fds_p(%rip), %ecx
    mov $1, %r14d
    shl %cl, %r14
    mov file_fd(%rip), %ecx
    mov $1, %r15d
    shl %cl, %r15
    mov %r14, %rax
    or %r15, %rax
    mov %rax, read_set(%rip)
    mov %r15, write_set(%rip)
    movq $5, select_time(%rip)
    movq $0, select_time+8(%rip)
    mov fds_p(%rip), %edi
    mov file_fd(%rip), %eax
    cmp %eax, %edi
    cmovl %eax, %edi
    inc %edi
    lea read_set(%rip), %rsi
    lea write_set(%rip), %rdx
    xor %r10d, %r10d
    lea select_time(%rip), %r8
    xor %r9d, %r9d
    mov $270, %eax                 /* pselect6 */
    syscall
    test %rax, %rax
    js fail_errno
    cmp $2, %rax
    jne fail_result
    cmp %r15, read_set(%rip)       /* exactly F's read bit */
    jne fail_sets
    cmp %r15, write_set(%rip)      /* and F's write bit */
    jne fail_sets
#endif
#ifdef CLOSE_MEMBER
    /* 2. Close S while it is a host-set member: the closed number is EBADF. */
    mov sock(%rip), %edi
    mov $3, %eax                   /* close(S) */
    syscall
    test %rax, %rax
    jnz fail_close
    call bits
    mov %r14, read_set(%rip)
    mov %r15, write_set(%rip)
    movq $0, select_time(%rip)
    movq $20000000, select_time+8(%rip)
    call nfds
    lea read_set(%rip), %rsi
    lea write_set(%rip), %rdx
    xor %r10d, %r10d
    lea select_time(%rip), %r8
    xor %r9d, %r9d
    mov $270, %eax                 /* pselect6 */
    syscall
    cmp $-9, %rax                  /* EBADF */
    jne fail_closed_member
    /* 3. S' reuses the number, connects, and enrols afresh. */
    mov $2, %edi                   /* AF_INET */
    mov $0x801, %esi               /* SOCK_STREAM | SOCK_NONBLOCK */
    xor %edx, %edx
    mov $41, %eax                  /* socket */
    syscall
    test %rax, %rax
    js fail_socket
    cmp sock(%rip), %eax
    jne fail_reuse
    mov %eax, %edi
    lea tcp_peer(%rip), %rsi
    mov $16, %edx
    mov $42, %eax                  /* connect: 0 or EINPROGRESS */
    syscall
    test %rax, %rax
    jz 1f
    cmp $-115, %rax
    jne fail_connect
1:
    call bits
    mov %r14, read_set(%rip)
    mov %r15, write_set(%rip)
    movq $5, select_time(%rip)
    movq $0, select_time+8(%rip)
    call nfds
    lea read_set(%rip), %rsi
    lea write_set(%rip), %rdx
    xor %r10d, %r10d
    lea select_time(%rip), %r8
    xor %r9d, %r9d
    mov $270, %eax                 /* pselect6 */
    syscall
    test %rax, %rax
    js fail_errno
    cmp $1, %rax
    jne fail_result
    cmpq $0, read_set(%rip)        /* P stays empty */
    jne fail_sets
    cmp %r15, write_set(%rip)      /* exactly S''s write bit */
    jne fail_sets
#endif
#if defined(SOCKET_WAKE) || defined(PIPE_WAKE) || defined(SET_TIMEOUT)
    /* 2. Read interest in both: P empty, nothing sent on S yet. */
    call bits
    mov %r14, %rax
    or %r15, %rax
    mov %rax, read_set(%rip)
    call nfds
    lea read_set(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
#ifdef SET_TIMEOUT
    movq $0, select_time(%rip)
    movq $20000000, select_time+8(%rip)
    lea select_time(%rip), %r8
#else
    xor %r8d, %r8d
#endif
    xor %r9d, %r9d
    mov $270, %eax                 /* pselect6 */
    syscall
    test %rax, %rax
    js fail_errno
#ifdef SET_TIMEOUT
    test %rax, %rax
    jnz fail_result
    cmpq $0, read_set(%rip)
    jne fail_sets
    mov select_time(%rip), %rax
    or select_time+8(%rip), %rax
    jnz fail_time
#else
    cmp $1, %rax
    jne fail_result
#ifdef SOCKET_WAKE
    cmp %r15, read_set(%rip)       /* exactly S's read bit */
#else
    cmp %r14, read_set(%rip)       /* exactly P's read bit */
#endif
    jne fail_sets
#endif
#endif
    xor %edi, %edi
    jmp exit

fail_errno:
    neg %eax
    mov %eax, %edi
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
fail_socket:
    mov $18, %edi
    jmp exit
fail_connect:
    mov $19, %edi
    jmp exit
fail_connect_result:
    mov $21, %edi
    jmp exit
fail_connect_sets:
    mov $22, %edi
    jmp exit
fail_open:
    mov $23, %edi
    jmp exit
fail_close:
    mov $24, %edi
    jmp exit
fail_closed_member:
    mov $25, %edi
    jmp exit
fail_reuse:
    mov $26, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 16
byte: .byte 'x'
.balign 8
select_gate_peer:
    .short 2, SELECT_GATE_PORT
    .byte 127, 0, 0, 1
    .quad 0
tcp_peer:
    .short 2, TCP_PORT
    .byte 127, 0, 0, 1
    .quad 0
#ifdef FILE_SET
file_path: .asciz FILE_PATH
#endif
.bss
.balign 8
fds_p: .space 8
sock: .space 4
so_error: .space 4
so_error_len: .space 4
file_fd: .space 4
pfd: .space 8
read_set: .space 8
write_set: .space 8
select_time: .space 16
poller_pids: .space 8
status: .space 8
received: .space 1
