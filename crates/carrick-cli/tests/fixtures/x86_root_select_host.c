// The run root's select(2) and pselect6(2) over host descriptors on x86_64
// (#2909): a host regular file (the mounted binary), stdin, stdout, a host
// UDP socket and a ring pipe, each already ready or idle, then woken later
// by a fork child. Every call is issued by
// number; every line is `name result set-bits`, a failure prints `-errno`,
// and the native run is the oracle.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long call(long ret) { return ret < 0 ? -errno : ret; }

// Which of `fds` are set in each of the three sets, as r/w/e digit strings.
static void report(const char *name, long ret, const int *fds, int n, fd_set *r, fd_set *w) {
    printf("%s %ld r=", name, call(ret));
    for (int i = 0; i < n; i++) printf("%d", r && FD_ISSET(fds[i], r) ? 1 : 0);
    printf(" w=");
    for (int i = 0; i < n; i++) printf("%d", w && FD_ISSET(fds[i], w) ? 1 : 0);
    printf("\n");
}

static int max_fd(const int *fds, int n) {
    int m = -1;
    for (int i = 0; i < n; i++) m = fds[i] > m ? fds[i] : m;
    return m;
}

// One select and one pselect6 over the same interest. `reads`/`writes` say
// which of `fds` go in each set; `usec` is the timeout.
static void both(const char *name, const int *fds, const int *reads, const int *writes, int n,
                 long usec) {
    char label[96];
    for (int which = 0; which < 2; which++) {
        fd_set r, w;
        FD_ZERO(&r);
        FD_ZERO(&w);
        for (int i = 0; i < n; i++) {
            if (reads[i]) FD_SET(fds[i], &r);
            if (writes[i]) FD_SET(fds[i], &w);
        }
        long ret;
        if (which == 0) {
            struct timeval tv = {.tv_sec = usec / 1000000, .tv_usec = usec % 1000000};
            ret = syscall(SYS_select, max_fd(fds, n) + 1, &r, &w, NULL, &tv);
            snprintf(label, sizeof label, "%s.select", name);
        } else {
            struct timespec ts = {.tv_sec = usec / 1000000, .tv_nsec = (usec % 1000000) * 1000};
            ret = syscall(SYS_pselect6, max_fd(fds, n) + 1, &r, &w, NULL, &ts, NULL);
            snprintf(label, sizeof label, "%s.pselect6", name);
        }
        report(label, ret, fds, n, &r, &w);
    }
}

static void loopback(struct sockaddr_in *addr) {
    memset(addr, 0, sizeof *addr);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static void sleep_ms(long ms) {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = ms * 1000000L};
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IONBF, 0);

    // (a) A host regular file (this binary, by its argv[0] path): always
    // readable.
    int file = (int)call(syscall(SYS_openat, AT_FDCWD, argv[0], O_RDONLY | O_CLOEXEC));
    printf("open.file %s\n", file >= 0 ? "fd" : "err");
    {
        int fds[] = {file}, r[] = {1}, w[] = {0};
        both("file", fds, r, w, 1, 0);
    }

    // (b) stdin and stdout. stdin is /dev/null for both runs (readable at
    // EOF); stdout is the harness pipe (writable).
    {
        int fds[] = {0, 1}, r[] = {1, 0}, w[] = {0, 1};
        both("stdio", fds, r, w, 2, 0);
    }

    // (c) A host UDP socket: idle with a 10 ms timeout, then readable with a
    // queued datagram, and always writable.
    int rx = (int)call(syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    int tx = (int)call(syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    printf("socket %s %s\n", rx >= 0 ? "fd" : "err", tx >= 0 ? "fd" : "err");
    struct sockaddr_in addr;
    loopback(&addr);
    printf("bind %ld\n", call(syscall(SYS_bind, rx, &addr, sizeof addr)));
    socklen_t len = sizeof addr;
    printf("getsockname %ld\n", call(syscall(SYS_getsockname, rx, &addr, &len)));
    {
        int fds[] = {rx}, r[] = {1}, w[] = {0};
        both("socket.idle", fds, r, w, 1, 10000);
    }
    {
        int fds[] = {rx}, r[] = {0}, w[] = {1};
        both("socket.writable", fds, r, w, 1, 0);
    }
    printf("sendto %ld\n",
           call(syscall(SYS_sendto, tx, "datagram", 8, 0, &addr, sizeof addr)));
    {
        int fds[] = {rx}, r[] = {1}, w[] = {0};
        both("socket.ready", fds, r, w, 1, 1000000);
    }

    // (d) A ring pipe alone: idle, then holding data. (A set that mixes a
    // ring member with a host descriptor has no owner yet for any caller,
    // the root included: #1051.)
    int pipefd[2];
    printf("pipe2 %ld\n", call(syscall(SYS_pipe2, pipefd, O_CLOEXEC)));
    char buf[16];
    printf("recvfrom %ld\n", call(syscall(SYS_recvfrom, rx, buf, sizeof buf, 0, NULL, NULL)));
    {
        int fds[] = {pipefd[0]}, r[] = {1}, w[] = {0};
        both("pipe.idle", fds, r, w, 1, 10000);
    }
    {
        int fds[] = {pipefd[1]}, r[] = {0}, w[] = {1};
        both("pipe.writable", fds, r, w, 1, 0);
    }
    printf("write.pipe %ld\n", call(syscall(SYS_write, pipefd[1], "x", 1)));
    {
        int fds[] = {pipefd[0]}, r[] = {1}, w[] = {0};
        both("pipe.ready", fds, r, w, 1, 0);
    }
    printf("read.pipe %ld\n", call(syscall(SYS_read, pipefd[0], buf, 1)));

    // (e) The root blocks while a fork child makes the one member ready:
    // first the ring pipe (select), then the host socket (pselect6).
    for (int round = 0; round < 2; round++) {
        long child = syscall(SYS_fork);
        if (child == 0) {
            sleep_ms(30);
            if (round == 0) {
                syscall(SYS_write, pipefd[1], "y", 1);
            } else {
                syscall(SYS_sendto, tx, "late", 4, 0, &addr, sizeof addr);
            }
            syscall(SYS_exit_group, 0);
        }
        fd_set r;
        FD_ZERO(&r);
        int fds[] = {round == 0 ? pipefd[0] : rx};
        FD_SET(fds[0], &r);
        long ret;
        if (round == 0) {
            struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
            ret = syscall(SYS_select, fds[0] + 1, &r, NULL, NULL, &tv);
            report("wake.pipe.select", ret, fds, 1, &r, NULL);
        } else {
            struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};
            ret = syscall(SYS_pselect6, fds[0] + 1, &r, NULL, NULL, &ts, NULL);
            report("wake.socket.pselect6", ret, fds, 1, &r, NULL);
        }
        int status = 0;
        printf("wait4 %d status %d\n", syscall(SYS_wait4, child, &status, 0, NULL) == child,
               status);
        if (round == 0) {
            printf("drain.pipe %ld\n", call(syscall(SYS_read, pipefd[0], buf, 1)));
        } else {
            printf("drain.socket %ld\n",
                   call(syscall(SYS_recvfrom, rx, buf, sizeof buf, 0, NULL, NULL)));
        }
    }
    printf("done\n");
    return 0;
}
