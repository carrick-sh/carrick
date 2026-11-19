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
 *
 * With ID_PORT the child instead checks that its socket calls are its own
 * (#231, director ruling D2), against a peer on ID_PORT that sends 70000
 * bytes and then reads to EOF:
 *   SIGPIPE: with a counting handler installed, connect, then
 *        getsockopt(SO_PEERCRED) is Linux's {0, -1, -1} for TCP (the Docker
 *        oracle's answer; never the run root's identity), a recv into a
 *        64 KiB buffer returns data (one record carries it), a 100000-byte
 *        blocking send returns 100000 (the ring continues it across
 *        records), and after
 *        shutdown(SHUT_WR) send raises the child's own SIGPIPE with EPIPE,
 *        send(MSG_NOSIGNAL) returns EPIPE without it, and write raises it;
 *   identity: setresuid(1000, 1000, 1000), then socket(AF_INET, SOCK_RAW,
 *        IPPROTO_ICMP) is EPERM (the child holds no CAP_NET_RAW, whatever
 *        the run root holds), while an unprivileged TCP socket still opens.
 *
 * With XFER_TCP_PORT and XFER_UDP_PORT the child instead checks transfers
 * larger than one host-file record (#2414 review P0-1), against a UDP peer
 * that reads datagrams until a 1-byte marker, then answers a 65000-byte
 * datagram of 'A' and a 3000-byte one, and a TCP peer (small receive
 * window) that drains 409600 bytes, then sends 200000 bytes of 'B' in
 * slices:
 *   bit 0: sendto of a 65000-byte UDP datagram returns 65000;
 *   bit 1: sendto of a 100000-byte UDP datagram is EMSGSIZE (90), and the
 *        peer sees no part of it (it checks the datagrams it read);
 *   bit 2: recvfrom of the 65000-byte datagram into a 65000-byte buffer
 *        returns 65000, its last byte 'A';
 *   bit 3: recvfrom of the 3000-byte datagram into 16 bytes returns 16 and
 *        the rest is discarded (the next MSG_DONTWAIT recv is EAGAIN);
 *   bit 4: a blocking TCP send of 409600 bytes returns 409600;
 *   bit 5: recvfrom(MSG_WAITALL) of 200000 bytes returns 200000, its last
 *        byte 'B'.
 *
 * With REPOLL the child instead checks that a poll issued again after an
 * interrupted one waits its own timeout (#2414 review P0-2), on a UDP
 * socket nothing arrives on:
 *   bit 0: poll(u, POLLIN, 1000), interrupted by SIGUSR1 (a grandchild's
 *        kill after 300 ms; the handler has no SA_RESTART), is EINTR and
 *        the handler ran once;
 *   bit 1: after 800 ms more (the interrupted call's deadline passed), the
 *        same poll waits its own 1000 ms timeout: a datagram a grandchild
 *        sends u after 500 ms ends it (1, POLLIN), where a poll that kept
 *        the interrupted call's spent deadline returns 0 at once;
 *   bit 2: a blocking recvfrom(u) interrupted by SIGUSR2, whose handler has
 *        SA_RESTART, restarts and receives the datagram a grandchild sends
 *        300 ms after the signal (1, and the handler ran).
 *
 * With DNS_PORT (and DNS6_PORT) the child instead makes a resolver's UDP
 * calls against a responder on those ports that answers every datagram
 * with "R" and its payload (#2418), and writes each step's raw result
 * (DNS_STEPS 64-bit words) to stdout, then exits 0; with DNS_ROOT the run
 * root makes them itself, without a fork:
 *   Go: socket(AF_INET6, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC), connect
 *        [::1], write, poll(POLLIN), read; then an AF_INET one connected to
 *        127.0.0.1, added to an epoll set (EPOLLIN|EPOLLOUT|EPOLLRDHUP|
 *        EPOLLET, as Go's netpoller), write, epoll_wait, read;
 *   glibc: socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC), connect,
 *        sendmmsg of two queries (A and AAAA, MSG_NOSIGNAL), poll and
 *        recvfrom of both answers, then sendmsg, poll and recvmsg, then
 *        send and recvmmsg of one; each header is on its own page, which
 *        the call itself writes first (an unbroken copy-on-write share);
 *        then sendmmsg of two whose second entry is on an unmapped page
 *        (Linux sends the first and answers 1), and a sendmsg larger than
 *        any datagram (EMSGSIZE).
 *
 * In both modes every check runs; the child exits 128 + the mask of failed
 * bits (0 when all pass), or the stage number of a step the checks rely on.
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
#define SYS_WRITE 1
#define SYS_RT_SIGACTION 13
#define SYS_RT_SIGRETURN 15
#define SYS_SETRESUID 117
#define SYS_NANOSLEEP 35
#define SYS_KILL 62
#define SYS_GETPPID 110
#define SYS_BIND 49
#define SYS_EXIT 60
#define SYS_READ 0
#define SYS_SENDMSG 46
#define SYS_RECVMSG 47
#define SYS_EPOLL_WAIT 232
#define SYS_EPOLL_CTL 233
#define SYS_EPOLL_CREATE1 291
#define SYS_RECVMMSG 299
#define SYS_SENDMMSG 307
#define SYS_MMAP 9
#define SYS_MUNMAP 11
#define DNS_STEPS 33

/* Record `mask` in xfails unless %rax == value; continue either way. */
#define CHECK(mask, value)   \
    cmp $value, %rax;        \
    je 1f;                   \
    orl $mask, xfails(%rip); \
1:

/* Fail unless %rax == value. */
#define EXPECT(stage, value) \
    mov $stage, %r15d;       \
    cmp $value, %rax;        \
    jne fail

.global _start
.text
_start:
#ifdef DNS_ROOT
    jmp dns
#endif
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
#ifdef EPOLL_HUP_PORT
    jmp epoll_terminal
#endif
#ifdef EPOLL_EXCLUSIVE
    jmp epoll_exclusive
#endif
#ifdef EPOLL_WAIT_PORT
    jmp epoll_waiters
#endif
#ifdef DNS_PORT
    jmp dns
#endif
#ifdef ID_PORT
    jmp identity
#endif
#ifdef XFER_TCP_PORT
    jmp transfer
#endif
#ifdef REPOLL
    jmp repoll
#endif
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

#ifdef ID_PORT
identity:
    mov $13, %edi                  /* rt_sigaction(SIGPIPE, &act, NULL, 8) */
    lea sigpipe_act(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $SYS_RT_SIGACTION, %eax
    syscall
    EXPECT(40, 0)

    mov $2, %edi                   /* socket(AF_INET, SOCK_STREAM, 0) */
    mov $1, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $41, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12

    mov %r12, %rdi                 /* connect(s, &id_addr, 16) */
    lea id_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    EXPECT(42, 0)

    movl $12, optlen(%rip)         /* getsockopt(s, SOL_SOCKET, SO_PEERCRED) */
    movl $7, ucred(%rip)
    movl $7, ucred+4(%rip)
    movl $7, ucred+8(%rip)
    mov %r12, %rdi
    mov $1, %esi
    mov $17, %edx
    lea ucred(%rip), %r10
    lea optlen(%rip), %r8
    mov $SYS_GETSOCKOPT, %eax
    syscall
    EXPECT(43, 0)
    movslq optlen(%rip), %rax
    EXPECT(44, 12)
    movslq ucred(%rip), %rax       /* pid 0 */
    EXPECT(45, 0)
    movslq ucred+4(%rip), %rax     /* uid -1 */
    EXPECT(46, -1)
    movslq ucred+8(%rip), %rax     /* gid -1 */
    EXPECT(47, -1)

    mov %r12, %rdi                 /* recvfrom(s, big, 65536, 0, NULL, NULL) */
    lea big(%rip), %rsi
    mov $65536, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    mov $48, %r15d
    test %rax, %rax
    jle fail

    mov %r12, %rdi                 /* sendto(s, big, 100000, 0, NULL, 0) */
    lea big(%rip), %rsi
    mov $100000, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(49, 100000)             /* the whole buffer (#2414 review P0-1) */

    mov %r12, %rdi                 /* shutdown(s, SHUT_WR) */
    mov $1, %esi
    mov $SYS_SHUTDOWN, %eax
    syscall
    EXPECT(50, 0)

    mov %r12, %rdi                 /* sendto(s, "x", 1, 0): EPIPE + SIGPIPE */
    lea query(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(51, -32)
    movslq pipes(%rip), %rax
    EXPECT(52, 1)

    mov %r12, %rdi                 /* sendto(s, "x", 1, MSG_NOSIGNAL): EPIPE */
    lea query(%rip), %rsi
    mov $1, %edx
    mov $0x4000, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(53, -32)
    movslq pipes(%rip), %rax
    EXPECT(54, 1)

    mov %r12, %rdi                 /* write(s, "x", 1): EPIPE + SIGPIPE */
    lea query(%rip), %rsi
    mov $1, %edx
    mov $SYS_WRITE, %eax
    syscall
    EXPECT(55, -32)
    movslq pipes(%rip), %rax
    EXPECT(56, 2)

    mov %r12, %rdi
    mov $SYS_CLOSE, %eax
    syscall
    EXPECT(57, 0)

    mov $1000, %edi                /* setresuid(1000, 1000, 1000) */
    mov $1000, %esi
    mov $1000, %edx
    mov $SYS_SETRESUID, %eax
    syscall
    EXPECT(58, 0)

    mov $2, %edi                   /* socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) */
    mov $3, %esi
    mov $1, %edx
    mov $SYS_SOCKET, %eax
    syscall
    EXPECT(59, -1)                 /* EPERM: no CAP_NET_RAW */

    mov $2, %edi                   /* socket(AF_INET, SOCK_STREAM, 0) */
    mov $1, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $60, %r15d
    test %rax, %rax
    js fail
    mov %rax, %rdi
    mov $SYS_CLOSE, %eax
    syscall
    EXPECT(61, 0)

    xor %edi, %edi
    jmp exit

sigpipe_handler:
    incl pipes(%rip)
    ret
sigpipe_restorer:
    mov $SYS_RT_SIGRETURN, %eax
    syscall
    ud2
#endif

#ifdef XFER_TCP_PORT
transfer:
    mov $2, %edi                   /* socket(AF_INET, SOCK_DGRAM, 0) */
    mov $2, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $71, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r13

    mov %r13, %rdi                 /* sendto(u, huge, 65000, 0, &peer, 16) */
    lea huge(%rip), %rsi
    mov $65000, %edx
    xor %r10d, %r10d
    lea xfer_udp_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    CHECK(1, 65000)

    mov %r13, %rdi                 /* sendto(u, huge, 100000, ...): EMSGSIZE */
    lea huge(%rip), %rsi
    mov $100000, %edx
    xor %r10d, %r10d
    lea xfer_udp_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    CHECK(2, -90)

    mov %r13, %rdi                 /* sendto(u, "q", 1, ...): the marker */
    lea query(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    lea xfer_udp_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    EXPECT(72, 1)

    mov %r13, %rdi                 /* recvfrom(u, huge, 65000, 0, NULL, NULL) */
    lea huge(%rip), %rsi
    mov $65000, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    CHECK(4, 65000)
    movzbl huge+64999(%rip), %eax
    CHECK(4, 'A')

    mov %r13, %rdi                 /* recvfrom(u, buffer, 16, 0): truncated */
    lea buffer(%rip), %rsi
    mov $16, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    CHECK(8, 16)
    mov %r13, %rdi                 /* recvfrom(u, buffer, 16, MSG_DONTWAIT) */
    lea buffer(%rip), %rsi
    mov $16, %edx
    mov $0x40, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    CHECK(8, -11)

    mov $2, %edi                   /* socket(AF_INET, SOCK_STREAM, 0) */
    mov $1, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $78, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12
    mov %r12, %rdi                 /* connect(s, &xfer_tcp_addr, 16) */
    lea xfer_tcp_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    EXPECT(79, 0)

    mov %r12, %rdi                 /* sendto(s, huge, 409600, 0, NULL, 0) */
    lea huge(%rip), %rsi
    mov $409600, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    CHECK(16, 409600)

    mov %r12, %rdi                 /* recvfrom(s, huge, 200000, MSG_WAITALL) */
    lea huge(%rip), %rsi
    mov $200000, %edx
    mov $0x100, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    CHECK(32, 200000)
    movzbl huge+199999(%rip), %eax
    CHECK(32, 'B')

    mov %r12, %rdi
    mov $SYS_CLOSE, %eax
    syscall
    EXPECT(80, 0)

    movl xfails(%rip), %edi
    test %edi, %edi
    jz exit
    or $128, %edi
    jmp exit

#endif

#ifdef REPOLL
repoll:
    mov $10, %edi                  /* rt_sigaction(SIGUSR1, &act, NULL, 8) */
    lea usr1_act(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $SYS_RT_SIGACTION, %eax
    syscall
    EXPECT(81, 0)
    mov $2, %edi                   /* socket(AF_INET, SOCK_DGRAM, 0): nothing arrives */
    mov $2, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $82, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r13
    mov %r13, %rdi                 /* bind(u, 127.0.0.1:0, 16) */
    lea self_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_BIND, %eax
    syscall
    EXPECT(83, 0)
    movl $16, addrlen(%rip)        /* getsockname(u, &self_addr, &len) */
    mov %r13, %rdi
    lea self_addr(%rip), %rsi
    lea addrlen(%rip), %rdx
    mov $SYS_GETSOCKNAME, %eax
    syscall
    EXPECT(84, 0)

    /* An interrupted poll's deadline is its own: the same poll, issued
     * again after that deadline passed, waits its own full timeout. */
    mov $SYS_FORK, %eax
    syscall
    mov $73, %r15d
    test %rax, %rax
    js fail
    jnz 2f
    lea usr1_delay(%rip), %rdi     /* grandchild: sleep 300 ms, then kill */
    xor %esi, %esi
    mov $SYS_NANOSLEEP, %eax
    syscall
    mov $SYS_GETPPID, %eax
    syscall
    mov %rax, %rdi
    mov $10, %esi
    mov $SYS_KILL, %eax
    syscall
    xor %edi, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
2:
    mov %rax, %rbx
    mov %r13d, pollfd(%rip)        /* poll(u, POLLIN, 1000): EINTR */
    movw $1, pollfd+4(%rip)
    movw $0, pollfd+6(%rip)
    lea pollfd(%rip), %rdi
    mov $1, %esi
    mov $1000, %edx
    mov $SYS_POLL, %eax
    syscall
    CHECK(1, -4)
    movslq usr1_count(%rip), %rax  /* the handler ran once */
    CHECK(1, 1)
    mov %rbx, %rdi                 /* wait4(grandchild, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $SYS_WAIT4, %eax
    syscall
    mov $74, %r15d
    cmp %rbx, %rax
    jne fail
    lea poll_rest(%rip), %rdi      /* nanosleep(800 ms): its deadline passes */
    xor %esi, %esi
    mov $SYS_NANOSLEEP, %eax
    syscall
    EXPECT(75, 0)

    /* The same poll again: a grandchild sends u a datagram after 500 ms,
     * which a poll waiting its own 1000 ms timeout sees (1, POLLIN); one
     * that inherited the interrupted call's spent deadline returns 0 at
     * once. */
    mov $SYS_FORK, %eax
    syscall
    mov $76, %r15d
    test %rax, %rax
    js fail
    jnz 4f
    lea send_delay(%rip), %rdi     /* grandchild: sleep 500 ms, then send */
    xor %esi, %esi
    mov $SYS_NANOSLEEP, %eax
    syscall
    mov %r13, %rdi                 /* sendto(u, "q", 1, 0, &self_addr, 16) */
    lea query(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    lea self_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    xor %edi, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
4:
    mov %rax, %rbx
    movw $0, pollfd+6(%rip)        /* the same poll(u, POLLIN, 1000): 1 */
    lea pollfd(%rip), %rdi
    mov $1, %esi
    mov $1000, %edx
    mov $SYS_POLL, %eax
    syscall
    CHECK(2, 1)
    movzwl pollfd+6(%rip), %eax
    CHECK(2, 1)
    mov %rbx, %rdi                 /* wait4(grandchild, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $SYS_WAIT4, %eax
    syscall
    mov $77, %r15d
    cmp %rbx, %rax
    jne fail

    /* A blocking recv interrupted by a handler with SA_RESTART restarts:
     * drain the poll's datagram, then a grandchild raises SIGUSR2 after
     * 300 ms and sends u a datagram 300 ms later, which the restarted recv
     * receives. */
    mov %r13, %rdi                 /* recvfrom(u, buf, 16, MSG_DONTWAIT): the poll's */
    lea buffer(%rip), %rsi
    mov $16, %edx
    mov $0x40, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    EXPECT(78, 1)
    mov $12, %edi                  /* rt_sigaction(SIGUSR2, &restart_act, NULL, 8) */
    lea restart_act(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $SYS_RT_SIGACTION, %eax
    syscall
    EXPECT(79, 0)
    mov $SYS_FORK, %eax
    syscall
    mov $80, %r15d
    test %rax, %rax
    js fail
    jnz 5f
    lea usr1_delay(%rip), %rdi     /* grandchild: 300 ms, SIGUSR2, 300 ms, send */
    xor %esi, %esi
    mov $SYS_NANOSLEEP, %eax
    syscall
    mov $SYS_GETPPID, %eax
    syscall
    mov %rax, %rdi
    mov $12, %esi
    mov $SYS_KILL, %eax
    syscall
    lea usr1_delay(%rip), %rdi
    xor %esi, %esi
    mov $SYS_NANOSLEEP, %eax
    syscall
    mov %r13, %rdi
    lea query(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    lea self_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    xor %edi, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
5:
    mov %rax, %rbx
    mov %r13, %rdi                 /* recvfrom(u, buf, 16, 0): restarted, 1 */
    lea buffer(%rip), %rsi
    mov $16, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    CHECK(4, 1)
    movslq usr1_count(%rip), %rax  /* the SIGUSR2 handler ran */
    CHECK(4, 2)
    mov %rbx, %rdi                 /* wait4(grandchild, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $SYS_WAIT4, %eax
    syscall
    mov $85, %r15d
    cmp %rbx, %rax
    jne fail

    movl xfails(%rip), %edi
    test %edi, %edi
    jz exit
    or $128, %edi
    jmp exit
#endif

#if defined(XFER_TCP_PORT) || defined(REPOLL)
usr1_handler:
    incl usr1_count(%rip)
    ret
usr1_restorer:
    mov $SYS_RT_SIGRETURN, %eax
    syscall
    ud2
#endif

#ifdef DNS_PORT
/* Record %rax as the result of step `i`. */
#define STEP(i) mov %rax, dns_results+8*(i)(%rip)

/* poll(fd, POLLIN, 5 s) into step `i`. */
#define POLLIN_STEP(fd, i)          \
    mov fd, %edi;                   \
    mov %edi, pollfd(%rip);         \
    movl $1, pollfd+4(%rip);        \
    lea pollfd(%rip), %rdi;         \
    mov $1, %esi;                   \
    mov $5000, %edx;                \
    mov $SYS_POLL, %eax;            \
    syscall;                        \
    STEP(i)

dns:
    /* Go: an AF_INET6 datagram socket connected to [::1]. */
    mov $10, %edi                  /* socket(AF_INET6, SOCK_DGRAM|NONBLOCK|CLOEXEC) */
    mov $0x80802, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    STEP(0)
    mov %rax, %r12
    mov %r12, %rdi                 /* connect(s6, &dns6_addr, 28) */
    lea dns6_addr(%rip), %rsi
    mov $28, %edx
    mov $SYS_CONNECT, %eax
    syscall
    STEP(1)
    mov %r12, %rdi                 /* write(s6, "go6", 3) */
    lea go6(%rip), %rsi
    mov $3, %edx
    mov $SYS_WRITE, %eax
    syscall
    STEP(2)
    POLLIN_STEP(%r12d, 3)
    mov %r12, %rdi                 /* read(s6, buffer, 32) */
    lea buffer(%rip), %rsi
    mov $32, %edx
    mov $SYS_READ, %eax
    syscall
    STEP(4)

    /* Go's netpoller: an AF_INET one in an epoll set. */
    mov $0x80000, %edi             /* epoll_create1(EPOLL_CLOEXEC) */
    mov $SYS_EPOLL_CREATE1, %eax
    syscall
    STEP(5)
    mov %rax, %r14
    mov $2, %edi                   /* socket(AF_INET, SOCK_DGRAM|NONBLOCK|CLOEXEC) */
    mov $0x80802, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    STEP(6)
    mov %rax, %r13
    mov %r13, %rdi                 /* connect(s4, &dns_addr, 16) */
    lea dns_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    STEP(7)
    mov %r13d, epoll_event+4(%rip) /* data: the descriptor */
    mov %r14, %rdi                 /* epoll_ctl(e, EPOLL_CTL_ADD, s4, &event) */
    mov $1, %esi
    mov %r13, %rdx
    lea epoll_event(%rip), %r10
    mov $SYS_EPOLL_CTL, %eax
    syscall
    STEP(8)
    mov %r13, %rdi                 /* write(s4, "go4", 3) */
    lea go4(%rip), %rsi
    mov $3, %edx
    mov $SYS_WRITE, %eax
    syscall
    STEP(9)
    /* epoll_wait until EPOLLIN: the first event may be EPOLLOUT alone. */
    mov $3, %ebx
1:
    mov %r14, %rdi                 /* epoll_wait(e, events, 4, 5 s) */
    lea epoll_events(%rip), %rsi
    mov $4, %edx
    mov $5000, %r10d
    mov $SYS_EPOLL_WAIT, %eax
    syscall
    STEP(10)
    test %rax, %rax
    jle 2f
    movl epoll_events(%rip), %eax
    mov %rax, dns_results+8*11(%rip)
    test $1, %eax
    jnz 2f
    dec %ebx
    jnz 1b
2:
    mov %r13, %rdi                 /* read(s4, buffer, 32) */
    lea buffer(%rip), %rsi
    mov $32, %edx
    mov $SYS_READ, %eax
    syscall
    STEP(12)

    /* glibc: a connected socket, sendmmsg of A and AAAA, recvfrom each. */
    mov $2, %edi                   /* socket(AF_INET, SOCK_DGRAM|NONBLOCK|CLOEXEC) */
    mov $0x80802, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    STEP(13)
    mov %rax, %rbx
    mov %rbx, %rdi                 /* connect(g, &dns_addr, 16) */
    lea dns_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    STEP(14)
    mov %rbx, %rdi                 /* sendmmsg(g, mmsgs, 2, MSG_NOSIGNAL) */
    lea mmsgs(%rip), %rsi
    mov $2, %edx
    mov $0x4000, %r10d
    mov $SYS_SENDMMSG, %eax
    syscall
    STEP(15)
    movl mmsgs+56(%rip), %eax      /* msg_len of each */
    STEP(16)
    movl mmsgs+64+56(%rip), %eax
    STEP(17)
    POLLIN_STEP(%ebx, 18)
    movl $16, addrlen(%rip)        /* recvfrom(g, buffer, 32, 0, &peer, &len) */
    mov %rbx, %rdi
    lea buffer(%rip), %rsi
    mov $32, %edx
    xor %r10d, %r10d
    lea peer(%rip), %r8
    lea addrlen(%rip), %r9
    mov $SYS_RECVFROM, %eax
    syscall
    STEP(19)
    POLLIN_STEP(%ebx, 20)
    mov %rbx, %rdi                 /* recvfrom(g, buffer, 32, 0, NULL, NULL) */
    lea buffer(%rip), %rsi
    mov $32, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    STEP(21)
    mov %rbx, %rdi                 /* sendmsg(g, &msg (A query), MSG_NOSIGNAL) */
    lea mmsgs(%rip), %rsi
    mov $0x4000, %edx
    mov $SYS_SENDMSG, %eax
    syscall
    STEP(22)
    POLLIN_STEP(%ebx, 23)
    mov %rbx, %rdi                 /* recvmsg(g, &rmsg, 0) */
    lea rmsg(%rip), %rsi
    xor %edx, %edx
    mov $SYS_RECVMSG, %eax
    syscall
    STEP(24)
    mov rmsg+8(%rip), %eax         /* msg_namelen the call wrote back */
    STEP(25)
    mov %rbx, %rdi                 /* sendto(g, "q", 1, 0, NULL, 0) */
    lea query(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    STEP(26)
    POLLIN_STEP(%ebx, 27)
    mov %rbx, %rdi                 /* recvmmsg(g, rmmsg, 1, 0, NULL) */
    lea rmsg(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $SYS_RECVMMSG, %eax
    syscall
    STEP(28)
    movl rmsg+56(%rip), %eax       /* its msg_len */
    STEP(29)
    xor %edi, %edi                 /* mmap(NULL, 8192, RW, PRIVATE|ANON, -1, 0) */
    mov $8192, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $SYS_MMAP, %eax
    syscall
    mov %rax, %r12
    lea 4096(%r12), %rdi           /* munmap(its second page) */
    mov $4096, %esi
    mov $SYS_MUNMAP, %eax
    syscall
    lea mmsgs(%rip), %rsi          /* the A query's header, last on page 0 */
    lea 4096-64(%r12), %rdi
    mov $64, %ecx
    rep movsb
    movl $0, 4096-64+56(%r12)      /* its msg_len */
    mov %rbx, %rdi                 /* sendmmsg(g, tail, 2, MSG_NOSIGNAL) */
    lea 4096-64(%r12), %rsi
    mov $2, %edx
    mov $0x4000, %r10d
    mov $SYS_SENDMMSG, %eax
    syscall
    STEP(30)
    movl 4096-64+56(%r12), %eax    /* msg_len of the one sent */
    STEP(31)
    mov %rbx, %rdi                 /* sendmsg(g, &bigmsg, MSG_NOSIGNAL) */
    lea bigmsg(%rip), %rsi
    mov $0x4000, %edx
    mov $SYS_SENDMSG, %eax
    syscall
    STEP(32)

    mov $1, %edi                   /* write(1, dns_results, 8 * DNS_STEPS) */
    lea dns_results(%rip), %rsi
    mov $8*DNS_STEPS, %edx
    mov $SYS_WRITE, %eax
    syscall
    xor %edi, %edi
    jmp exit
#endif


#ifdef EPOLL_HUP_PORT
/* The real host peer closes with SO_LINGER(1, 0). HUP and ERR must be
 * reported even though the guest requested neither bit. */
epoll_terminal:
    /* Force the copyout page into this child before the wait parks. */
    movl $0, epoll_reset_output(%rip)
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $1, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12
    mov %r12, %rdi
    lea epoll_reset_peer(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    EXPECT(2, 0)
    xor %edi, %edi
    mov $SYS_EPOLL_CREATE1, %eax
    syscall
    mov $3, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r13
    mov %r13, %rdi
    mov $1, %esi
    mov %r12, %rdx
    lea epoll_err_event(%rip), %r10
    mov $SYS_EPOLL_CTL, %eax
    syscall
    EXPECT(4, 0)
    mov %r12, %rdi
    lea epoll_ping_reset(%rip), %rsi
    mov $1, %edx
    mov $SYS_WRITE, %eax
    syscall
    EXPECT(5, 1)
    mov %r13, %rdi
    lea epoll_reset_output(%rip), %rsi
    mov $1, %edx
    mov $5000, %r10d
    mov $SYS_EPOLL_WAIT, %eax
    syscall
    EXPECT(6, 1)
    mov epoll_reset_output(%rip), %eax
    EXPECT(7, 0x18)             /* EPOLLERR | EPOLLHUP */
    mov epoll_reset_output+4(%rip), %rax
    EXPECT(8, 0x2419)
    xor %edi, %edi
    jmp exit
#endif

#ifdef EPOLL_WAIT_PORT
/* The host peer holds the reply until both fork related threads are
 * enrolled in the same inherited epoll's Readable queue. A level-triggered event must reach both
 * waiters without consuming the datagram. DEL must remove it even while
 * the socket is still readable. */
epoll_waiters:
    mov $2, %edi
    mov $2, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $1, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12
    mov %r12, %rdi
    lea epoll_peer(%rip), %rsi
    mov $16, %edx
    mov $SYS_CONNECT, %eax
    syscall
    EXPECT(2, 0)
    xor %edi, %edi
    mov $SYS_EPOLL_CREATE1, %eax
    syscall
    mov $3, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r13
    mov %r13, %rdi
    mov $1, %esi                 /* EPOLL_CTL_ADD */
    mov %r12, %rdx
    lea epoll_in(%rip), %r10
    mov $SYS_EPOLL_CTL, %eax
    syscall
    EXPECT(4, 0)
    mov %r12, %rdi
    lea epoll_ping(%rip), %rsi
    mov $1, %edx
    mov $SYS_WRITE, %eax
    syscall
    EXPECT(5, 1)

    mov $SYS_FORK, %eax
    syscall
    mov $10, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r14
    movl $0, epoll_wait_output(%rip)
    mov %r13, %rdi
    lea epoll_wait_output(%rip), %rsi
    mov $1, %edx
    mov $-1, %r10d
    mov $SYS_EPOLL_WAIT, %eax
    syscall
    EXPECT(11, 1)
    mov epoll_wait_output(%rip), %eax
    EXPECT(12, 1)
    mov epoll_wait_output+4(%rip), %rax
    EXPECT(13, 0x2418)
    test %r14, %r14
    jz epoll_waiter_exit
    mov %r14, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $SYS_WAIT4, %eax
    syscall
    mov $6, %r15d
    cmp %r14, %rax
    jne fail
    mov status(%rip), %eax
    EXPECT(14, 0)
epoll_delete:
    mov %r13, %rdi
    mov $2, %esi                 /* EPOLL_CTL_DEL */
    mov %r12, %rdx
    xor %r10d, %r10d
    mov $SYS_EPOLL_CTL, %eax
    syscall
    EXPECT(7, 0)
    mov %r13, %rdi
    lea buffer(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    mov $SYS_EPOLL_WAIT, %eax
    syscall
    EXPECT(8, 0)
    mov %r12, %rdi
    lea buffer(%rip), %rsi
    mov $1, %edx
    mov $SYS_READ, %eax
    syscall
    EXPECT(9, 1)
    xor %edi, %edi
    jmp exit

epoll_waiter_exit:
    xor %edi, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
#endif

#ifdef EPOLL_EXCLUSIVE
epoll_exclusive:
    mov $2, %edi                 /* AF_INET */
    mov $2, %esi                 /* SOCK_DGRAM */
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    mov $1, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12
    xor %edi, %edi
    mov $SYS_EPOLL_CREATE1, %eax
    syscall
    mov $2, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r13
    movl $0x10000004, buffer(%rip) /* EXCLUSIVE|OUT */
    mov $1, %esi                  /* ADD */
    call exclusive_ctl
    EXPECT(3, 0)
    mov $3, %esi                  /* MOD */
    call exclusive_ctl
    EXPECT(4, -22)
    movl $4, buffer(%rip)         /* MOD cannot change an exclusive item */
    mov $3, %esi
    call exclusive_ctl
    EXPECT(7, -22)
    mov $2, %esi                  /* DEL */
    call exclusive_ctl
    EXPECT(5, 0)
    movl $0x50000004, buffer(%rip) /* EXCLUSIVE|ONESHOT|OUT */
    mov $1, %esi
    call exclusive_ctl
    EXPECT(6, -22)
    xor %edi, %edi
    mov $SYS_EPOLL_CREATE1, %eax
    syscall
    mov $8, %r15d
    test %rax, %rax
    js fail
    mov %rax, %r12
    movl $0x10000004, buffer(%rip) /* EXCLUSIVE with an epoll target */
    mov $1, %esi
    call exclusive_ctl
    EXPECT(9, -22)
    xor %edi, %edi
    jmp exit

exclusive_ctl:
    mov %r13, %rdi
    mov %r12, %rdx
    lea buffer(%rip), %r10
    mov $SYS_EPOLL_CTL, %eax
    syscall
    ret
#endif

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
#ifdef EPOLL_HUP_PORT
epoll_reset_peer:
    .short 2
    .short EPOLL_HUP_PORT
    .byte 127, 0, 0, 1
    .quad 0
epoll_err_event:
    .long 0x80000000             /* EPOLLET */
    .quad 0x2419
epoll_reset_output:
    .zero 12
epoll_ping_reset:
    .byte 1
#endif
#ifdef EPOLL_WAIT_PORT
epoll_peer:
    .short 2
    .short EPOLL_WAIT_PORT
    .byte 127, 0, 0, 1
    .quad 0
epoll_in:
    .long 1
    .quad 0x2418
epoll_ping:
    .byte 1
epoll_wait_output:
    .zero 12
#endif
.align 8
#ifdef DNS_PORT
dns_results:
    .fill DNS_STEPS, 8, 0x7eadbeef
dns_addr:
    .short 2
    .short DNS_PORT
    .byte 127, 0, 0, 1
    .quad 0
dns6_addr:
    .short 10
    .short DNS6_PORT
    .long 0                        /* flowinfo */
    .quad 0                        /* ::1 */
    .byte 0, 0, 0, 0, 0, 0, 0, 1
    .long 0                        /* scope id */
.align 8
epoll_event:
    .long 0x80002005               /* EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET */
    .long 0
    .quad 0
epoll_events:
    .zero 48
go6:
    .ascii "go6"
go4:
    .ascii "go4"
qa:
    .ascii "A-query"
qaaaa:
    .ascii "AAAA-query"
.align 8
iov_a:
    .quad qa, 7
iov_aaaa:
    .quad qaaaa, 10
riov:
    .quad rbuf, 64
/* A msghdr whose one iovec is larger than any datagram. */
bigmsg:
    .quad 0, 0, bigiov, 1, 0, 0, 0
bigiov:
    .quad bigbuf, 70000
/* Two struct mmsghdr (64 bytes each): msghdr, then msg_len. Each header
 * page is first written by the call that writes the header back. */
.balign 4096
mmsgs:
    .quad 0, 0, iov_a, 1, 0, 0, 0, 0
    .quad 0, 0, iov_aaaa, 1, 0, 0, 0, 0
/* One receive struct mmsghdr: a name buffer and one iovec. */
.balign 4096
rmsg:
    .quad rname
    .long 28, 0
    .quad riov, 1, 0, 0, 0, 0
rname:
    .zero 32
rbuf:
    .zero 64
.balign 4096
#endif
#ifdef ID_PORT
id_addr:
    .short 2
    .short ID_PORT
    .byte 127, 0, 0, 1
    .quad 0
sigpipe_act:
    .quad sigpipe_handler          /* sa_handler */
    .quad 0x04000000               /* sa_flags: SA_RESTORER */
    .quad sigpipe_restorer         /* sa_restorer */
    .quad 0                        /* sa_mask */
ucred:
    .zero 12
.align 8
pipes:
    .long 0
.align 8
big:
    .zero 100000
#endif
#ifdef XFER_TCP_PORT
xfer_tcp_addr:
    .short 2
    .short XFER_TCP_PORT
    .byte 127, 0, 0, 1
    .quad 0
xfer_udp_addr:
    .short 2
    .short XFER_UDP_PORT
    .byte 127, 0, 0, 1
    .quad 0
#endif
#if defined(XFER_TCP_PORT) || defined(REPOLL)
usr1_act:
    .quad usr1_handler             /* sa_handler */
    .quad 0x04000000               /* sa_flags: SA_RESTORER, no SA_RESTART */
    .quad usr1_restorer            /* sa_restorer */
    .quad 0                        /* sa_mask */
restart_act:
    .quad usr1_handler             /* sa_handler */
    .quad 0x14000000               /* sa_flags: SA_RESTORER | SA_RESTART */
    .quad usr1_restorer            /* sa_restorer */
    .quad 0                        /* sa_mask */
usr1_delay:
    .quad 0, 300000000             /* 300 ms */
poll_rest:
    .quad 0, 800000000             /* 800 ms */
send_delay:
    .quad 0, 500000000             /* 500 ms */
self_addr:
    .short 2
    .short 0
    .byte 127, 0, 0, 1
    .quad 0
usr1_count:
    .long 0
xfails:
    .long 0
#endif
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
#ifdef XFER_TCP_PORT
.bss
.align 4096
huge:
    .zero 409600
#endif
#ifdef DNS_PORT
.bss
bigbuf:
    .zero 70000
#endif
