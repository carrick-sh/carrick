// Blocking waits across a run root and its fork child, with no select, on
// x86_64 (#1051's gap 2). The root holds a loopback listener and a pipe's
// write end; the child holds a connected TCP socket and the pipe's read
// end. Six rows, with no interval timer (x86 setitimer is a gap of its
// own, #2876); each wait is bounded by a receive timeout, a poll timeout
// or a later write of the other process:
//   accept: the root blocks in accept4 before the child connects;
//   b: the child writes the socket, then the root receives with a
//      receive timeout (is the child's write delivered at all);
//   a: the root blocks reading its accepted socket under a receive
//      timeout, then the child writes (does the root's socket read wake);
//   c: the child blocks in poll on the pipe (bounded by poll's timeout),
//      then the root writes it (does a zone pipe write wake a parked
//      descendant), and reads the byte;
//   d: the root sets O_NONBLOCK on a socket both processes hold after the
//      fork. The child's receive must see it (EAGAIN, not a block until
//      the root's later write), and the child's call must leave it set for
//      the root (EAGAIN, not a block until the child's later write): the
//      flag belongs to the open description, which the fork shares;
//   e: socket timeouts that must wait (#2878): the child's receive under a
//      short SO_RCVTIMEO answers EAGAIN when nothing arrives, and the
//      root's receive under a longer one is woken by the child's write.
// Every line is `who.name result`, where a failure prints as `-errno`; the
// native run is the oracle. The root prints after the child exits, so the
// processes' lines never interleave.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *who;

static long call(long ret) { return ret < 0 ? -errno : ret; }

static void value(const char *name, long ret) { printf("%s.%s %ld\n", who, name, call(ret)); }

static struct {
    const char *name;
    long ret;
} later[32];
static int nlater;

static void record(const char *name, long ret) {
    if (nlater < 32) {
        later[nlater].name = name;
        later[nlater].ret = call(ret);
        nlater++;
    }
}

static void pause_ms(long ms) {
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000L};
    (void)syscall(SYS_nanosleep, &delay, NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    who = "root";
    int listener = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof address;
    value("bind", syscall(SYS_bind, listener, &address, sizeof address));
    value("listen", syscall(SYS_listen, listener, 1));
    value("getsockname", syscall(SYS_getsockname, listener, &address, &size));
    int pipe_fds[2];
    value("pipe", syscall(SYS_pipe2, pipe_fds, 0));
    // Row d: a connected pair both processes inherit.
    int other = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    struct sockaddr_in other_address;
    memset(&other_address, 0, sizeof other_address);
    other_address.sin_family = AF_INET;
    other_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t other_size = sizeof other_address;
    value("d.bind", syscall(SYS_bind, other, &other_address, sizeof other_address));
    value("d.listen", syscall(SYS_listen, other, 1));
    value("d.getsockname", syscall(SYS_getsockname, other, &other_address, &other_size));
    int shared = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    value("d.connect", syscall(SYS_connect, shared, &other_address, sizeof other_address));
    int shared_peer = (int)call(syscall(SYS_accept4, other, NULL, NULL, 0));
    value("d.accept", shared_peer >= 0 ? 0 : shared_peer);
    close(other);

    pid_t pid = fork();
    if (pid == 0) {
        who = "child";
        close(listener);
        close(pipe_fds[1]);
        int sock = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
        // Row accept: connect only once the root is parked in accept4.
        pause_ms(200);
        value("connect", syscall(SYS_connect, sock, &address, sizeof address));
        char byte = 'b';
        // Row b: written before the root receives.
        value("b.write", syscall(SYS_write, sock, &byte, 1));
        // Row a: written after the root is parked in its read.
        pause_ms(200);
        byte = 'a';
        value("a.write", syscall(SYS_write, sock, &byte, 1));
        // Row c: parked in poll on the pipe before the root writes it.
        struct pollfd ready = {pipe_fds[0], POLLIN, 0};
        value("c.poll", syscall(SYS_poll, &ready, 1, 3000));
        value("c.revents", ready.revents);
        value("c.read", syscall(SYS_read, pipe_fds[0], &byte, 1));
        printf("child.c.byte %c\n", byte);
        // Row d: the root has set O_NONBLOCK on `shared` once its byte
        // arrives on the pipe.
        ready.revents = 0;
        value("d.poll", syscall(SYS_poll, &ready, 1, 3000));
        value("d.sync", syscall(SYS_read, pipe_fds[0], &byte, 1));
        long flags = syscall(SYS_fcntl, shared, F_GETFL);
        value("d.nonblock", flags < 0 ? flags : (flags & O_NONBLOCK) != 0);
        byte = 0;
        value("d.recv", syscall(SYS_recvfrom, shared, &byte, 1, 0, NULL, NULL));
        // Bounds the root's read if the child's call cleared its flag.
        pause_ms(800);
        byte = 'z';
        value("d.write", syscall(SYS_write, shared_peer, &byte, 1));
        // Row e: nothing arrives within the receive timeout.
        struct timeval brief = {0, 300000};
        value("e.rcvtimeo", syscall(SYS_setsockopt, sock, SOL_SOCKET, SO_RCVTIMEO, &brief, sizeof brief));
        byte = 0;
        value("e.recv", syscall(SYS_recvfrom, sock, &byte, 1, 0, NULL, NULL));
        // Wakes the root's receive under its longer timeout.
        pause_ms(200);
        byte = 'e';
        value("e.write", syscall(SYS_write, sock, &byte, 1));
        // Keep the connection open until the root's short timeout passed.
        ready.revents = 0;
        value("e.poll", syscall(SYS_poll, &ready, 1, 3000));
        value("e.done", syscall(SYS_read, pipe_fds[0], &byte, 1));
        _exit(0);
    }
    close(pipe_fds[0]);
    // Row accept: a blocking accept4 parked before the child connects. On
    // a failure, retry once the connection is surely queued, so the later
    // rows still run; native never prints the retry line.
    int peer = (int)call(syscall(SYS_accept4, listener, NULL, NULL, 0));
    record("accept", peer >= 0 ? 0 : peer);
    if (peer < 0) {
        pause_ms(400);
        peer = (int)call(syscall(SYS_accept4, listener, NULL, NULL, 0));
        record("accept.retry", peer >= 0 ? 0 : peer);
    }
    char byte = 0;

    // Row b: the child's byte is already sent; receive it with a timeout.
    pause_ms(100);
    struct timeval wait = {2, 0}, none = {0, 0};
    record("b.rcvtimeo", syscall(SYS_setsockopt, peer, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait));
    record("b.recv", syscall(SYS_recvfrom, peer, &byte, 1, 0, NULL, NULL));
    record("b.byte", byte);
    record("b.clear", syscall(SYS_setsockopt, peer, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none));

    // Row a: a plain blocking read the child's later write must wake. It is
    // unbounded: a receive timeout's wait is a venue gap of its own (#2878),
    // and the test's own timeout ends a lost wake.
    // Bounded by a receive timeout: a timed poll of this socket (the root's
    // half of the child's in-zone loopback connection) is the venue's
    // refusal of a mixed readiness set (#1051).
    byte = 0;
    struct timeval bound = {3, 0};
    record("a.rcvtimeo", syscall(SYS_setsockopt, peer, SOL_SOCKET, SO_RCVTIMEO, &bound, sizeof bound));
    record("a.read", syscall(SYS_read, peer, &byte, 1));
    record("a.byte", byte);

    // Row c: the child is parked in its pipe read by now.
    pause_ms(200);
    byte = 'c';
    record("c.write", syscall(SYS_write, pipe_fds[1], &byte, 1));

    // Row d: set O_NONBLOCK on the shared socket, then tell the child.
    pause_ms(200);
    long flags = syscall(SYS_fcntl, shared, F_GETFL);
    record("d.setfl", syscall(SYS_fcntl, shared, F_SETFL, flags | O_NONBLOCK));
    byte = 'd';
    record("d.sync", syscall(SYS_write, pipe_fds[1], &byte, 1));
    // Bounds the child's receive if it blocks; native has it answered
    // EAGAIN already, so the byte stays queued for the root's first read.
    pause_ms(300);
    byte = 'x';
    record("d.peer.write", syscall(SYS_write, shared_peer, &byte, 1));
    pause_ms(200);
    byte = 0;
    record("d.read1", syscall(SYS_read, shared, &byte, 1));
    record("d.byte1", byte);
    record("d.read2", syscall(SYS_read, shared, &byte, 1));

    // Row e: the child's byte arrives within this timeout; then a short one
    // passes with nothing.
    struct timeval longer = {3, 0}, brief = {0, 300000};
    record("e.rcvtimeo", syscall(SYS_setsockopt, peer, SOL_SOCKET, SO_RCVTIMEO, &longer, sizeof longer));
    byte = 0;
    record("e.recv", syscall(SYS_recvfrom, peer, &byte, 1, 0, NULL, NULL));
    record("e.byte", byte);
    record("e.brief", syscall(SYS_setsockopt, peer, SOL_SOCKET, SO_RCVTIMEO, &brief, sizeof brief));
    record("e.timeout", syscall(SYS_recvfrom, peer, &byte, 1, 0, NULL, NULL));
    byte = 'f';
    record("e.done", syscall(SYS_write, pipe_fds[1], &byte, 1));

    int status = 0;
    long reaped = waitpid(pid, &status, 0) == pid ? 0 : -1;
    for (int i = 0; i < nlater; i++) printf("root.%s %ld\n", later[i].name, later[i].ret);
    value("waitpid", reaped);
    printf("root.child.status %d\n", status);
    return 0;
}
