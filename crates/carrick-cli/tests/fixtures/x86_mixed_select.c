// A mixed readiness wait, on x86_64 (#1051): a fork child selects over an
// in-zone pipe (fd 0) and a host TCP socket (fd 3) together, the shape of
// apt's `http` method under `apt-get update`. The run root holds the
// pipe's write end and the socket's peer, and makes each side ready while
// the child waits; it prints its own results after the child exits.
// Every line is `who.name result [r=… w=…]`, where a
// failure prints as `-errno`; the native run is the oracle. Each wait is
// bounded (5 s), and the child tells the root when it is about to wait by
// a byte on the socket, which never makes the child's own end readable.
//
// The root and the child also select over host descriptors of other kinds
// (#1051 P0-1): a regular file (fd 10, always readable and writable) and
// the run's stdio, alone and beside the in-zone pipe and the socket. A
// readiness set serves every kind a select can name, with Linux's answer
// per kind.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *who;

static long call(long ret) { return ret < 0 ? -errno : ret; }

static void value(const char *name, long ret) { printf("%s.%s %ld\n", who, name, call(ret)); }

// The root's results while the child runs, printed after it exits, so the
// two processes' lines never interleave.
static struct {
    const char *name;
    long ret;
} later[16];
static int nlater;

static void record(const char *name, long ret) {
    if (nlater < 16) {
        later[nlater].name = name;
        later[nlater].ret = call(ret);
        nlater++;
    }
}

static volatile sig_atomic_t delivered;

static void on_usr1(int signal) {
    (void)signal;
    delivered = 1;
}

// One raw select(2) with a zero timeval over `nfds` descriptors: prints
// the result and the descriptors left in each set.
static void poll_sets(const char *name, int nfds, const int *reads, int nreads, const int *writes,
                      int nwrites) {
    fd_set r, w;
    FD_ZERO(&r);
    FD_ZERO(&w);
    for (int i = 0; i < nreads; i++) FD_SET(reads[i], &r);
    for (int i = 0; i < nwrites; i++) FD_SET(writes[i], &w);
    struct timeval zero = {0, 0};
    long ret = call(syscall(SYS_select, nfds, &r, &w, NULL, &zero));
    printf("%s.%s %ld r=", who, name, ret);
    for (int fd = 0; fd < nfds; fd++)
        if (ret >= 0 && FD_ISSET(fd, &r)) printf("%d,", fd);
    printf(" w=");
    for (int fd = 0; fd < nfds; fd++)
        if (ret >= 0 && FD_ISSET(fd, &w)) printf("%d,", fd);
    printf("\n");
}

// One raw pselect6 over `nfds` descriptors with a read set, a write set,
// a timeout in milliseconds (-1: none) and an optional signal mask. Prints
// the result and the descriptors left in each set.
static void wait_sets(const char *name, int nfds, const int *reads, int nreads, const int *writes,
                      int nwrites, long ms, const sigset_t *mask) {
    fd_set r, w;
    FD_ZERO(&r);
    FD_ZERO(&w);
    for (int i = 0; i < nreads; i++) FD_SET(reads[i], &r);
    for (int i = 0; i < nwrites; i++) FD_SET(writes[i], &w);
    struct timespec timeout = {ms / 1000, (ms % 1000) * 1000000L};
    struct {
        const sigset_t *set;
        size_t size;
    } sigmask = {mask, 8};
    long ret = call(syscall(SYS_pselect6, nfds, &r, &w, NULL, ms < 0 ? NULL : &timeout,
                            mask ? &sigmask : NULL));
    printf("%s.%s %ld r=", who, name, ret);
    for (int fd = 0; fd < nfds; fd++)
        if (ret >= 0 && FD_ISSET(fd, &r)) printf("%d,", fd);
    printf(" w=");
    for (int fd = 0; fd < nfds; fd++)
        if (ret >= 0 && FD_ISSET(fd, &w)) printf("%d,", fd);
    printf("\n");
    if (ms >= 0 && ret == 0)
        printf("%s.%s.remaining %ld %ld\n", who, name, (long)timeout.tv_sec, timeout.tv_nsec);
}

static void drain(int fd, const char *name) {
    char byte;
    value(name, syscall(SYS_read, fd, &byte, 1));
}

static void tell(int sock, char step) { (void)syscall(SYS_write, sock, &step, 1); }

// Whether `pid` is asleep (state S in `/proc/<pid>/stat`), read until it
// is; 1 once seen. The state is the child's own: it changes when the child
// parks, so each read observes an event, not the passage of time. Bounded
// so a broken stat fails the row (0) instead of hanging it.
static long asleep(pid_t pid) {
    char path[64], buf[256];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    for (long i = 0; i < 10000000; i++) {
        int fd = (int)syscall(SYS_open, path, O_RDONLY);
        if (fd < 0) return -errno;
        long n = syscall(SYS_read, fd, buf, sizeof buf - 1);
        close(fd);
        if (n <= 0) return -1;
        buf[n] = 0;
        const char *paren = strrchr(buf, ')');
        if (paren && paren[1] == ' ' && paren[2] == 'S') return 1;
        sched_yield();
    }
    return 0;
}

// Connections the forty-socket row adds beside fd 3.
#define MANY 39
static const struct sockaddr_in *peer_address;

static void child(void) {
    static const int both[] = {0, 3}, sock[] = {3};
    // apt's own call: nothing to read, the connected socket is writable.
    wait_sets("apt", 4, both, 2, sock, 1, 30000, NULL);

    // A blocking read set over both: the root writes the pipe.
    tell(3, 'p');
    wait_sets("pipe", 4, both, 2, NULL, 0, 5000, NULL);
    drain(0, "pipe.read");

    // The same set: the root sends on the socket.
    tell(3, 's');
    wait_sets("socket", 4, both, 2, NULL, 0, 5000, NULL);
    drain(3, "socket.read");

    // Both ready before the call: the root writes the pipe, then sends on
    // the socket; once the socket is readable the pipe already is.
    tell(3, 'b');
    wait_sets("both.ready", 4, sock, 1, NULL, 0, 5000, NULL);
    wait_sets("both", 4, both, 2, NULL, 0, 5000, NULL);
    drain(0, "both.read.pipe");
    drain(3, "both.read.socket");

    // Nothing written: the timeout expires with every set clear and no
    // time left.
    wait_sets("timeout", 4, both, 2, NULL, 0, 50, NULL);

    // The inherited regular file beside the pipe and the socket, neither
    // ready: only the file answers, readable and writable.
    const int with_file[] = {0, 3, 10};
    poll_sets("file.mixed", 11, with_file, 3, with_file + 2, 1);

    // A pselect6 mask that blocks SIGUSR1, which the thread's own mask
    // does not: the root signals the child during the wait, then writes
    // the pipe. Only the call's mask keeps the wait from being interrupted
    // (EINTR, had it been ignored); the signal is delivered as the call
    // returns, once the thread's mask is back. The root signals only once
    // it has seen this child asleep (`/proc/<pid>/stat` state S) after the
    // 'm' byte: nothing between that byte and the wait can sleep, so the
    // signal arrives inside pselect6, never before it.
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    value("sigaction", sigaction(SIGUSR1, &action, NULL));
    tell(3, 'm');
    wait_sets("masked", 4, both, 2, NULL, 0, 5000, &block);
    printf("%s.masked.delivered %d\n", who, (int)delivered);
    drain(0, "masked.read");

    // Forty carrier sockets in one set (#1051): fd 3 and MANY more
    // connections, every one writable at once; then, once the root has
    // sent one byte on each of the MANY and said so on fd 3, every one of
    // them is readable at once. Each answer is the whole set, never a
    // partial wake, because each is asked only after its event.
    int many[MANY + 1];
    many[0] = 3;
    tell(3, 'n');
    for (int i = 1; i <= MANY; i++) {
        many[i] = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
        if (syscall(SYS_connect, many[i], peer_address, sizeof *peer_address) != 0) {
            value("many.connect", -1);
            return;
        }
    }
    int nmany = many[MANY] + 1;
    poll_sets("many.write", nmany, NULL, 0, many, MANY + 1);
    char done;
    value("many.done", syscall(SYS_read, 3, &done, 1));
    poll_sets("many.read", nmany, many + 1, MANY, NULL, 0);
}

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IONBF, 0);
    who = "root";
    // A regular file at fd 10 (this program's own image), and the run's
    // stdio: the root's select over host descriptors alone.
    int file = (int)call(syscall(SYS_open, argv[0], O_RDONLY));
    value("file.open", file >= 0 ? 0 : file);
    value("file.dup", syscall(SYS_dup2, file, 10) == 10 ? 0 : -1);
    if (file != 10) close(file);
    const int file_fd[] = {10};
    poll_sets("file", 11, file_fd, 1, file_fd, 1);
    const int out[] = {1};
    poll_sets("stdout", 2, NULL, 0, out, 1);
    poll_sets("file.stdout", 11, file_fd, 1, (const int[]){1, 10}, 2);
    int listener = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof address;
    value("bind", syscall(SYS_bind, listener, &address, sizeof address));
    value("listen", syscall(SYS_listen, listener, MANY + 1));
    value("getsockname", syscall(SYS_getsockname, listener, &address, &size));
    int pipe_fds[2];
    value("pipe", syscall(SYS_pipe2, pipe_fds, 0));

    pid_t pid = fork();
    if (pid == 0) {
        who = "child";
        close(listener);
        close(pipe_fds[1]);
        value("dup.stdin", syscall(SYS_dup2, pipe_fds[0], 0));
        close(pipe_fds[0]);
        // The socket is fd 3, as apt's is. dup2 makes it so even when the
        // oracle's parent left fd 3 open in this process.
        int sock = (int)call(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
        value("connect", syscall(SYS_connect, sock, &address, sizeof address));
        if (sock != 3) {
            value("dup.socket", syscall(SYS_dup2, sock, 3) == 3 ? 0 : -1);
            close(sock);
        } else {
            value("dup.socket", 0);
        }
        peer_address = &address;
        child();
        _exit(0);
    }
    close(pipe_fds[0]);
    int peer = (int)call(syscall(SYS_accept4, listener, NULL, NULL, 0));
    record("accept", peer >= 0 ? 0 : peer);
    char step = 0, byte = 'x';
    while (syscall(SYS_read, peer, &step, 1) == 1) {
        switch (step) {
        case 'p':
            record("write.pipe", syscall(SYS_write, pipe_fds[1], &byte, 1));
            break;
        case 's':
            record("write.socket", syscall(SYS_write, peer, &byte, 1));
            break;
        case 'b':
            record("both.pipe", syscall(SYS_write, pipe_fds[1], &byte, 1));
            record("both.socket", syscall(SYS_write, peer, &byte, 1));
            break;
        case 'm':
            record("masked.asleep", asleep(pid));
            record("kill", syscall(SYS_kill, pid, SIGUSR1));
            record("masked.pipe", syscall(SYS_write, pipe_fds[1], &byte, 1));
            break;
        case 'n': {
            long sent = 0;
            for (int i = 0; i < MANY; i++) {
                int conn = (int)syscall(SYS_accept4, listener, NULL, NULL, 0);
                if (conn >= 0 && syscall(SYS_write, conn, &byte, 1) == 1) sent++;
            }
            record("many.sent", sent);
            record("many.done", syscall(SYS_write, peer, &byte, 1));
            break;
        }
        }
    }
    int status = 0;
    long reaped = waitpid(pid, &status, 0) == pid ? 0 : -1;
    for (int i = 0; i < nlater; i++) printf("root.%s %ld\n", later[i].name, later[i].ret);
    value("waitpid", reaped);
    printf("root.child.status %d\n", status);
    return 0;
}
