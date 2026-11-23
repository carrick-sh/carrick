// A mixed readiness wait, on x86_64 (#1051): a fork child selects over an
// in-zone pipe (fd 0) and a host TCP socket (fd 3) together, the shape of
// apt's `http` method under `apt-get update`. The run root holds the
// pipe's write end and the socket's peer, and makes each side ready while
// the child waits; it prints its own results after the child exits.
// Every line is `who.name result [r=… w=…]`, where a
// failure prints as `-errno`; the native run is the oracle. Each wait is
// bounded (5 s), and the child tells the root when it is about to wait by
// a byte on the socket, which never makes the child's own end readable.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
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
    struct pollfd ready = {3, POLLIN, 0};
    value("both.poll", syscall(SYS_poll, &ready, 1, 5000));
    wait_sets("both", 4, both, 2, NULL, 0, 5000, NULL);
    drain(0, "both.read.pipe");
    drain(3, "both.read.socket");

    // Nothing written: the timeout expires with every set clear and no
    // time left.
    wait_sets("timeout", 4, both, 2, NULL, 0, 50, NULL);

    // A pselect6 mask that blocks SIGUSR1: the root signals the child
    // during the wait, then writes the pipe. The wait is not interrupted,
    // and the signal is delivered once the old mask is back.
    sigset_t block, none;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigemptyset(&none);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    value("sigaction", sigaction(SIGUSR1, &action, NULL));
    value("block", sigprocmask(SIG_BLOCK, &block, NULL));
    tell(3, 'm');
    wait_sets("masked", 4, both, 2, NULL, 0, 5000, &block);
    drain(0, "masked.read");
    printf("%s.masked.delivered.before %d\n", who, (int)delivered);
    value("unblock", sigprocmask(SIG_SETMASK, &none, NULL));
    printf("%s.masked.delivered.after %d\n", who, (int)delivered);
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
            record("kill", syscall(SYS_kill, pid, SIGUSR1));
            record("masked.pipe", syscall(SYS_write, pipe_fds[1], &byte, 1));
            break;
        }
    }
    int status = 0;
    long reaped = waitpid(pid, &status, 0) == pid ? 0 : -1;
    for (int i = 0; i < nlater; i++) printf("root.%s %ld\n", later[i].name, later[i].ret);
    value("waitpid", reaped);
    printf("root.child.status %d\n", status);
    return 0;
}
