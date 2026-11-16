/* #231: a forked native child's AF_INET (and, with TCP6_PORT, AF_INET6)
 * sockets are real host network crossings. The test hosts the peers on
 * loopback: a TCP listener on TCP_PORT that reads "ping", answers "pong"
 * and closes after the client's EOF, and a UDP responder on UDP_PORT that
 * answers every datagram with "a". Ports are network byte order.
 *
 * The child, with a blocking socket each time:
 *   TCP: socket, setsockopt(TCP_NODELAY), connect, getsockopt(SO_ERROR),
 *        getpeername, send "ping", recv "pong" (MSG_WAITALL),
 *        shutdown(SHUT_WR), recv EOF, close;
 *   UDP: socket, sendto, poll(POLLIN) until the answer, recvfrom (with
 *        source address), getsockname, then a poll that times out;
 *   non-blocking TCP: socket(SOCK_NONBLOCK), connect (EINPROGRESS),
 *        poll(POLLOUT), getsockopt(SO_ERROR), close, against TCP_NB_PORT;
 *   TCP6: socket, connect [::1], send "ping", recv "pong".
 * The root reaps the child and exits with its status. Child exit 0 = every
 * step returned what Linux returns; a step that returned something else
 * exits with its stage number, or 100 + stage when it returned ENOSYS (38).
 * 91: fork or wait failed. */
#define SYS_CLOSE 3
#define SYS_SOCKET 41
#define SYS_CONNECT 42
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_SHUTDOWN 48
#define SYS_GETSOCKNAME 51
#define SYS_GETPEERNAME 52
#define SYS_SETSOCKOPT 54
#define SYS_GETSOCKOPT 55
#define SYS_FORK 57
#define SYS_WAIT4 61
#define SYS_EXIT_GROUP 231
#define SYS_POLL 7

/* Fail unless %rax == value. */
#define EXPECT(stage, value) \
    mov $stage, %r15d;       \
    cmp $value, %rax;        \
    jne fail

.global _start
.text
_start:
    mov $SYS_FORK, %eax
    syscall
    test %eax, %eax
    js fail_wait
    jz child
    mov %eax, %edi                 /* wait4(child, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $SYS_WAIT4, %eax
    syscall
    test %eax, %eax
    js fail_wait
    movzbl status+1(%rip), %edi    /* WEXITSTATUS */
    jmp exit

child:
    /* TCP over IPv4. */
    mov $2, %edi                   /* socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0) */
    mov $0x80001, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $1, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12

    mov %r12, %rdi                 /* setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, 4) */
    mov $6, %esi
    mov $1, %edx
    lea one(%rip), %r10
    mov $4, %r8d
    mov $SYS_SETSOCKOPT, %eax
    syscall
    EXPECT(2, 0)

    mov %r12, %rdi                 /* connect(s, &tcp_addr, 16) */
    lea tcp_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    EXPECT(3, 0)

    movl $4, optlen(%rip)          /* getsockopt(s, SOL_SOCKET, SO_ERROR, ...) */
    movl $-1, optval(%rip)
    mov %r12, %rdi
    mov $1, %esi
    mov $4, %edx
    lea optval(%rip), %r10
    lea optlen(%rip), %r8
    mov $SYS_GETSOCKOPT, %eax
    syscall
    EXPECT(4, 0)
    movslq optval(%rip), %rax
    EXPECT(5, 0)

    movl $16, addrlen(%rip)        /* getpeername(s, &peer, &len) */
    mov %r12, %rdi
    lea peer(%rip), %rsi
    lea addrlen(%rip), %rdx
    mov $SYS_GETPEERNAME, %eax
    syscall
    EXPECT(6, 0)
    movzwl peer+2(%rip), %eax
    movzwl tcp_addr+2(%rip), %ecx
    cmp %ecx, %eax
    mov $7, %r15d
    jne fail

    mov %r12, %rdi                 /* sendto(s, "ping", 4, 0, NULL, 0) */
    lea ping(%rip), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(8, 4)

    mov %r12, %rdi                 /* recvfrom(s, buf, 4, MSG_WAITALL, NULL, NULL) */
    lea buffer(%rip), %rsi
    mov $4, %edx
    mov $0x100, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    EXPECT(9, 4)
    mov buffer(%rip), %eax
    cmp pong(%rip), %eax
    mov $10, %r15d
    jne fail

    mov %r12, %rdi                 /* shutdown(s, SHUT_WR) */
    mov $1, %esi
    mov $SYS_SHUTDOWN, %eax
    syscall
    EXPECT(11, 0)

    mov %r12, %rdi                 /* recvfrom(s, buf, 4, 0, NULL, NULL): EOF */
    lea buffer(%rip), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    EXPECT(12, 0)

    mov %r12, %rdi
    mov $SYS_CLOSE, %eax
    syscall
    EXPECT(13, 0)

    /* A DNS-style UDP query. */
    mov $2, %edi                   /* socket(AF_INET, SOCK_DGRAM, 0) */
    mov $2, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $14, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r13

    mov %r13, %rdi                 /* sendto(u, "q", 1, 0, &udp_addr, 16) */
    lea query(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    lea udp_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(15, 1)

    /* The resolver's wait: poll(u, POLLIN, 5 s) until the answer arrives. */
    mov %r13d, pollfd(%rip)
    movw $1, pollfd+4(%rip)
    movw $0, pollfd+6(%rip)
    lea pollfd(%rip), %rdi
    mov $1, %esi
    mov $5000, %edx
    mov $SYS_POLL, %eax
    syscall
    EXPECT(26, 1)
    movzwl pollfd+6(%rip), %eax
    cmp $1, %eax                   /* revents == POLLIN */
    mov $27, %r15d
    jne fail

    movl $16, addrlen(%rip)        /* recvfrom(u, buf, 16, 0, &peer, &len) */
    mov %r13, %rdi
    lea buffer(%rip), %rsi
    mov $16, %edx
    xor %r10d, %r10d
    lea peer(%rip), %r8
    lea addrlen(%rip), %r9
    mov $SYS_RECVFROM, %eax
    syscall
    EXPECT(16, 1)
    cmpb $'a', buffer(%rip)
    mov $17, %r15d
    jne fail
    movzwl peer+2(%rip), %eax
    movzwl udp_addr+2(%rip), %ecx
    cmp %ecx, %eax
    mov $18, %r15d
    jne fail

    movl $16, addrlen(%rip)        /* getsockname(u, &peer, &len) */
    mov %r13, %rdi
    lea peer(%rip), %rsi
    lea addrlen(%rip), %rdx
    mov $SYS_GETSOCKNAME, %eax
    syscall
    EXPECT(19, 0)
    movzwl peer(%rip), %eax        /* sin_family == AF_INET, bound port */
    cmp $2, %eax
    mov $20, %r15d
    jne fail
    cmpw $0, peer+2(%rip)
    je fail

    /* Nothing more arrives: poll(u, POLLIN, 50 ms) times out with 0. */
    movw $0, pollfd+6(%rip)
    lea pollfd(%rip), %rdi
    mov $1, %esi
    mov $50, %edx
    mov $SYS_POLL, %eax
    syscall
    EXPECT(28, 0)
    cmpw $0, pollfd+6(%rip)
    mov $29, %r15d
    jne fail

    /* A non-blocking connect completes through poll(POLLOUT) and
     * getsockopt(SO_ERROR), as Python's and Go's dialers do. */
    mov $2, %edi                   /* socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0) */
    mov $0x801, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $30, %r15d
    test %rax, %rax
    js fail
    mov %rax, %rbx
    mov %rbx, %rdi                 /* connect: 0 or EINPROGRESS */
    lea tcp_nb_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    mov $31, %r15d
    test %rax, %rax
    jz 1f
    cmp $-115, %rax
    jne fail
1:
    mov %ebx, pollfd(%rip)         /* poll(s, POLLOUT, 5 s) */
    movw $4, pollfd+4(%rip)
    movw $0, pollfd+6(%rip)
    lea pollfd(%rip), %rdi
    mov $1, %esi
    mov $5000, %edx
    mov $SYS_POLL, %eax
    syscall
    EXPECT(32, 1)
    movl $4, optlen(%rip)          /* getsockopt(s, SOL_SOCKET, SO_ERROR) == 0 */
    movl $-1, optval(%rip)
    mov %rbx, %rdi
    mov $1, %esi
    mov $4, %edx
    lea optval(%rip), %r10
    lea optlen(%rip), %r8
    mov $SYS_GETSOCKOPT, %eax
    syscall
    EXPECT(33, 0)
    movslq optval(%rip), %rax
    EXPECT(34, 0)
    mov %rbx, %rdi
    mov $SYS_CLOSE, %eax
    syscall
    EXPECT(35, 0)

#ifdef TCP6_PORT
    /* TCP over IPv6 loopback. */
    mov $10, %edi                  /* socket(AF_INET6, SOCK_STREAM, 0) */
    mov $1, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $21, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r14

    mov %r14, %rdi                 /* connect(s6, &tcp6_addr, 28) */
    lea tcp6_addr(%rip), %rsi
    mov $28, %edx
    mov $SYS_CONNECT, %eax
    syscall
    EXPECT(22, 0)

    mov %r14, %rdi
    lea ping(%rip), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(23, 4)

    mov %r14, %rdi
    lea buffer(%rip), %rsi
    mov $4, %edx
    mov $0x100, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    EXPECT(24, 4)
    mov buffer(%rip), %eax
    cmp pong(%rip), %eax
    mov $25, %r15d
    jne fail
#endif

    xor %edi, %edi
    jmp exit

fail:
    mov %r15d, %edi
    cmp $-38, %rax
    jne exit
    add $100, %edi
    jmp exit
fail_wait:
    mov $91, %edi
exit:
    mov $SYS_EXIT_GROUP, %eax
    syscall
    ud2

.data
.align 8
tcp_addr:
    .short 2
    .short TCP_PORT
    .byte 127, 0, 0, 1
    .quad 0
udp_addr:
    .short 2
    .short UDP_PORT
    .byte 127, 0, 0, 1
    .quad 0
tcp_nb_addr:
    .short 2
    .short TCP_NB_PORT
    .byte 127, 0, 0, 1
    .quad 0
#ifdef TCP6_PORT
tcp6_addr:
    .short 10
    .short TCP6_PORT
    .long 0                        /* flowinfo */
    .quad 0                        /* ::1 */
    .byte 0, 0, 0, 0, 0, 0, 0, 1
    .long 0                        /* scope id */
#endif
one:
    .long 1
ping:
    .ascii "ping"
pong:
    .ascii "pong"
query:
    .ascii "q"
.align 8
optval:
    .long 0
optlen:
    .long 0
addrlen:
    .long 0
.align 8
peer:
    .zero 32
buffer:
    .zero 32
status:
    .long 0
.align 8
pollfd:
    .zero 8
