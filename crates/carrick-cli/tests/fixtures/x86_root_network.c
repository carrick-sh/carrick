// The run root's host network family on x86_64 (#1906): a TCP connection
// to a loopback listener and a UDP exchange, every call issued by number so
// each call is the one named, then a fork child using the root's sockets. Every line is `name result`, where an fd
// prints as `fd` and a failure as `-errno`; the native run is the oracle.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long call(long ret) { return ret < 0 ? -errno : ret; }

static void value(const char *name, long ret) { printf("%s %ld\n", name, call(ret)); }

static int fd(const char *name, long ret) {
    ret = call(ret);
    if (ret >= 0) {
        printf("%s fd\n", name);
    } else {
        printf("%s %ld\n", name, ret);
    }
    return (int)ret;
}

// A page nothing has touched yet: a receive must fill it like Linux does.
static char *fresh_page(void) {
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return page == MAP_FAILED ? NULL : page;
}

static void loopback(struct sockaddr_in *addr) {
    memset(addr, 0, sizeof *addr);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int one = 1;
    struct sockaddr_in addr;
    socklen_t len;

    // TCP: listener, client, accepted peer.
    int ls = fd("socket", syscall(SYS_socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    value("setsockopt", syscall(SYS_setsockopt, ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one));
    loopback(&addr);
    value("bind", syscall(SYS_bind, ls, &addr, sizeof addr));
    value("listen", syscall(SYS_listen, ls, 4));
    len = sizeof addr;
    value("getsockname", syscall(SYS_getsockname, ls, &addr, &len));
    printf("getsockname.len %u family %d port_set %d\n", len, addr.sin_family, addr.sin_port != 0);

    int client = fd("socket.client", syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    value("connect", syscall(SYS_connect, client, &addr, sizeof addr));
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof peer;
    int accepted = fd("accept4", syscall(SYS_accept4, ls, &peer, &peer_len, SOCK_CLOEXEC));
    printf("accept4.len %u family %d\n", peer_len, peer.sin_family);
    int second = fd("socket.second", syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    value("connect.second", syscall(SYS_connect, second, &addr, sizeof addr));
    int accepted2 = fd("accept", syscall(SYS_accept, ls, NULL, NULL));

    int error = -1;
    socklen_t error_len = sizeof error;
    value("getsockopt", syscall(SYS_getsockopt, client, SOL_SOCKET, SO_ERROR, &error, &error_len));
    printf("getsockopt.so_error %d len %u\n", error, error_len);
    peer_len = sizeof peer;
    value("getpeername", syscall(SYS_getpeername, accepted, &peer, &peer_len));
    printf("getpeername.len %u family %d\n", peer_len, peer.sin_family);

    value("sendto.tcp", syscall(SYS_sendto, client, "ping", 4, 0, NULL, 0));
    struct pollfd readable = {.fd = accepted, .events = POLLIN};
    value("poll", poll(&readable, 1, 1000));
    printf("poll.revents %d\n", readable.revents);
    fd_set set;
    FD_ZERO(&set);
    FD_SET(accepted, &set);
    struct timespec zero = {0, 0};
    value("pselect6", syscall(SYS_pselect6, accepted + 1, &set, NULL, NULL, &zero, NULL));
    int epfd = fd("epoll_create1", syscall(SYS_epoll_create1, EPOLL_CLOEXEC));
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 7};
    value("epoll_ctl", syscall(SYS_epoll_ctl, epfd, EPOLL_CTL_ADD, accepted, &event));
    struct epoll_event got = {0};
    value("epoll_wait", syscall(SYS_epoll_wait, epfd, &got, 1, 1000));
    printf("epoll_wait.data %llu\n", (unsigned long long)got.data.u64);

    char *page = fresh_page();
    value("recvfrom.tcp", syscall(SYS_recvfrom, accepted, page, 4096, 0, NULL, NULL));
    printf("recvfrom.tcp.data %.4s\n", page ? page : "");

    struct iovec out[2] = {{"he", 2}, {"llo", 3}};
    struct msghdr message = {.msg_iov = out, .msg_iovlen = 2};
    // A blocking stream sendmsg has no venue yet (#2418): this one may not
    // wait, and the receive runs once its bytes are readable.
    value("sendmsg", syscall(SYS_sendmsg, accepted, &message, MSG_DONTWAIT));
    struct pollfd reply = {.fd = client, .events = POLLIN};
    value("poll.reply", poll(&reply, 1, 1000));
    char head[2], tail[8];
    struct iovec in[2] = {{head, sizeof head}, {tail, sizeof tail}};
    struct msghdr received = {.msg_iov = in, .msg_iovlen = 2};
    value("recvmsg", syscall(SYS_recvmsg, client, &received, 0));
    printf("recvmsg.data %.2s%.3s flags %d\n", head, tail, received.msg_flags);

    value("shutdown", syscall(SYS_shutdown, client, SHUT_WR));
    char eof[4];
    value("recvfrom.eof", syscall(SYS_recvfrom, accepted, eof, sizeof eof, 0, NULL, NULL));

    // UDP: a bound receiver and an unbound sender.
    int receiver = fd("socket.udp", syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0));
    int sender = fd("socket.udp.sender", syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0));
    loopback(&addr);
    value("bind.udp", syscall(SYS_bind, receiver, &addr, sizeof addr));
    len = sizeof addr;
    value("getsockname.udp", syscall(SYS_getsockname, receiver, &addr, &len));
    value("sendto.udp", syscall(SYS_sendto, sender, "dgram", 5, 0, &addr, sizeof addr));
    struct sockaddr_in source;
    socklen_t source_len = sizeof source;
    char *dgram = fresh_page();
    value("recvfrom.udp",
          syscall(SYS_recvfrom, receiver, dgram, 4096, 0, &source, &source_len));
    printf("recvfrom.udp.data %.5s len %u family %d\n", dgram ? dgram : "", source_len,
           source.sin_family);

    struct iovec batch_out[2] = {{"one", 3}, {"two", 3}};
    struct mmsghdr batch[2];
    memset(batch, 0, sizeof batch);
    for (int i = 0; i < 2; i++) {
        batch[i].msg_hdr.msg_name = &addr;
        batch[i].msg_hdr.msg_namelen = sizeof addr;
        batch[i].msg_hdr.msg_iov = &batch_out[i];
        batch[i].msg_hdr.msg_iovlen = 1;
    }
    value("sendmmsg", syscall(SYS_sendmmsg, sender, batch, 2, 0));
    char first[8], next[8];
    struct iovec batch_in[2] = {{first, sizeof first}, {next, sizeof next}};
    struct mmsghdr inbox[2];
    memset(inbox, 0, sizeof inbox);
    for (int i = 0; i < 2; i++) {
        inbox[i].msg_hdr.msg_iov = &batch_in[i];
        inbox[i].msg_hdr.msg_iovlen = 1;
    }
    struct pollfd queued = {.fd = receiver, .events = POLLIN};
    value("poll.udp", poll(&queued, 1, 1000));
    value("recvmmsg", syscall(SYS_recvmmsg, receiver, inbox, 2, MSG_WAITFORONE, NULL));
    printf("recvmmsg.data %.3s %u %.3s %u\n", first, inbox[0].msg_len, next, inbox[1].msg_len);

    // A fork child holds the root's sockets: it selects on the receiver,
    // reads the datagram the root queued, and answers on the sender.
    value("sendto.child", syscall(SYS_sendto, sender, "dad", 3, 0, &addr, sizeof addr));
    pid_t child = fork();
    if (child == 0) {
        fd_set inherited;
        FD_ZERO(&inherited);
        FD_SET(receiver, &inherited);
        struct timespec second = {1, 0};
        value("child.pselect6",
              syscall(SYS_pselect6, receiver + 1, &inherited, NULL, NULL, &second, NULL));
        printf("child.pselect6.set %d\n", FD_ISSET(receiver, &inherited) != 0);
        char got3[4] = {0};
        value("child.recvfrom", syscall(SYS_recvfrom, receiver, got3, 3, 0, NULL, NULL));
        printf("child.recvfrom.data %s\n", got3);
        value("child.sendto", syscall(SYS_sendto, sender, "kid", 3, 0, &addr, sizeof addr));
        _exit(7);
    }
    int status = 0;
    value("waitpid", waitpid(child, &status, 0) == child ? 0 : -1);
    printf("waitpid.status %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    char kid[4] = {0};
    value("recvfrom.child", syscall(SYS_recvfrom, receiver, kid, 3, 0, NULL, NULL));
    printf("recvfrom.child.data %s\n", kid);

    // An AF_UNIX stream pair is the ring's. A datagram pair has no venue
    // yet (#2361): it stays a counted ENOSYS, outside this witness.
    int stream[2] = {-1, -1};
    value("socketpair.stream", syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, stream));

    int fds[] = {ls, client, accepted, second, accepted2, epfd, receiver, sender,
                 stream[0], stream[1]};
    int closed = 0;
    for (unsigned i = 0; i < sizeof fds / sizeof fds[0]; i++) {
        closed += close(fds[i]) == 0;
    }
    printf("close %d\n", closed);
    return 0;
}
