/* venue-probe (#1906): the known-answer probe for `carrick debug venue-gaps`.
 *
 * It makes each call shape the parity rows make (the venue-gaps table) once
 * as the run root and once in a forked native child, by raw syscall (no
 * vDSO, no libc fallback), and prints one line per call and caller:
 *   VENUE <root|child> <name> <shape> ret=<r> errno=<e> <served|ENOSYS>
 * then `VENUE-SUMMARY root_enosys=<n> child_enosys=<n>`. Only ENOSYS is a
 * venue gap; any other errno (EINVAL, EPERM, EAGAIN, ...) means the call
 * reached an owner. The exit status is the child's ENOSYS count (capped).
 *
 * Known answer: on the native Docker oracle both counts are 0 (x86_64,
 * ubuntu:24.04, docker 26.1.5). Build it against the image's glibc:
 *   cc -O1 -o venue-probe scripts/conformance/venue-probe.c
 * mount it into the image and run it as `sh -c 'exec /probe/venue-probe'`
 * so the probe is the root. (A static glibc build dies with SIGSEGV before
 * main under carrick x86 at main 3c0ae50a1, as a static hello does too.) */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/openat2.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

static const char *who = "root";
static int enosys;

static void report(const char *name, const char *shape, long ret)
{
    int e = ret < 0 ? errno : 0;
    if (ret < 0 && e == ENOSYS)
        enosys++;
    printf("VENUE %s %s %s ret=%ld errno=%d %s\n", who, name, shape, ret, e,
           ret < 0 && e == ENOSYS ? "ENOSYS" : "served");
}

#define CALL(name, shape, ...) report(name, shape, syscall(__VA_ARGS__))

static void *anon(size_t len)
{
    return (void *)syscall(SYS_mmap, 0, len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void probe(void)
{
    struct timespec ts;
    struct timeval tv;
    unsigned char cpus[128];
    char path[] = "/tmp/venue-probe-XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) {
        if (write(fd, "venue-probe-data", 16) != 16)
            fd = -1;
        unlink(path);
    }

    /* Time, by raw syscall (#2618). */
    CALL("clock_gettime", "REALTIME", SYS_clock_gettime, CLOCK_REALTIME, &ts);
    CALL("clock_gettime", "MONOTONIC", SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    CALL("clock_gettime", "BOOTTIME", SYS_clock_gettime, CLOCK_BOOTTIME, &ts);
    CALL("clock_getres", "MONOTONIC", SYS_clock_getres, CLOCK_MONOTONIC, &ts);
    CALL("gettimeofday", "-", SYS_gettimeofday, &tv, 0);
#ifdef SYS_time
    CALL("time", "-", SYS_time, 0);
#endif
#ifdef SYS_alarm
    CALL("alarm", "0", SYS_alarm, 0);
#endif

    /* Scheduler and process. */
    CALL("sched_getaffinity", "-", SYS_sched_getaffinity, 0, sizeof cpus, cpus);
    long pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    report("pidfd_open", "self", pidfd);
    if (pidfd >= 0) {
        CALL("pidfd_send_signal", "sig0", SYS_pidfd_send_signal, pidfd, 0, 0, 0);
        close(pidfd);
    }
    CALL("prlimit64", "NOFILE", SYS_prlimit64, 0, RLIMIT_NOFILE, 0, &cpus);

    /* Memory (C2's family; listed here so the table is whole). */
    char *m = anon(1 << 16);
    m[0] = 1;
    CALL("madvise", "DONTNEED", SYS_madvise, m, 4096, MADV_DONTNEED);
    CALL("madvise", "DONTFORK", SYS_madvise, m, 4096, MADV_DONTFORK);
    CALL("madvise", "DOFORK", SYS_madvise, m, 4096, MADV_DOFORK);
    CALL("madvise", "FREE", SYS_madvise, m, 4096, MADV_FREE);
    CALL("madvise", "HUGEPAGE", SYS_madvise, m, 1 << 16, MADV_HUGEPAGE);
    CALL("mprotect", "R", SYS_mprotect, m, 4096, PROT_READ);
    CALL("mremap", "MAYMOVE", SYS_mremap, m, 1 << 16, 1 << 17, MREMAP_MAYMOVE);
    CALL("mmap", "SHARED|ANON", SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CALL("mmap", "PRIVATE|ANON|POPULATE", SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    CALL("mmap", "PRIVATE|ANON|GROWSDOWN", SYS_mmap, 0, 1 << 16, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    CALL("mmap", "SHARED file", SYS_mmap, 0, 4096, PROT_READ, MAP_SHARED, fd, 0);
    char *n = anon(4096);
    n[0] = 1;
    CALL("msync", "ASYNC", SYS_msync, n, 4096, MS_ASYNC);
    CALL("mincore", "-", SYS_mincore, n, 4096, cpus);
    CALL("mlock", "-", SYS_mlock, n, 4096);
    CALL("munlock", "-", SYS_munlock, n, 4096);

    /* Sockets (#2418 and the AF_UNIX / AF_NETLINK refusals). */
    long s;
    s = syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    report("socket", "AF_UNIX STREAM", s);
    if (s >= 0) close(s);
    s = syscall(SYS_socket, AF_UNIX, SOCK_DGRAM, 0);
    report("socket", "AF_UNIX DGRAM", s);
    if (s >= 0) close(s);
    s = syscall(SYS_socket, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    report("socket", "AF_NETLINK RAW", s);
    if (s >= 0) close(s);
    int sv[2];
    CALL("socketpair", "AF_UNIX DGRAM", SYS_socketpair, AF_UNIX, SOCK_DGRAM, 0, sv);
    s = syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    report("socket", "AF_INET DGRAM", s);
    if (s >= 0) {
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        char byte = 'x';
        struct iovec iov = {&byte, 1};
        struct mmsghdr msg = {.msg_hdr = {.msg_name = &to, .msg_namelen = sizeof to,
                                          .msg_iov = &iov, .msg_iovlen = 1}};
        CALL("sendmmsg", "AF_INET DGRAM", SYS_sendmmsg, s, &msg, 1, MSG_DONTWAIT);
        close(s);
    }

    /* Descriptors and readiness. */
    struct pollfd none;
    struct timespec zero = {0, 0};
    CALL("ppoll", "nfds=0 t=0", SYS_ppoll, &none, 0, &zero, 0, 8);
    CALL("pselect6", "nfds=0 t=0", SYS_pselect6, 0, 0, 0, 0, &zero, 0);
#ifdef SYS_poll
    CALL("poll", "nfds=0 t=0", SYS_poll, &none, 0, 0);
#endif
    if (fd >= 0) {
        CALL("fcntl", "F_GETFL", SYS_fcntl, fd, F_GETFL);
        struct flock lk = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        CALL("fcntl", "F_SETLK", SYS_fcntl, fd, F_SETLK, &lk);
        CALL("flock", "EX|NB", SYS_flock, fd, LOCK_EX | LOCK_NB);
        CALL("fadvise64", "DONTNEED", SYS_fadvise64, fd, 0, 0, POSIX_FADV_DONTNEED);
        CALL("readahead", "-", SYS_readahead, fd, 0, 16);
        char buf[16];
        struct iovec iov = {buf, sizeof buf};
        CALL("preadv2", "-", SYS_preadv2, fd, &iov, 1, 0, 0, 0);
        int fd2 = open("/tmp", O_TMPFILE | O_RDWR, 0600);
        if (fd2 >= 0) {
            loff_t in = 0;
            CALL("copy_file_range", "-", SYS_copy_file_range, fd, &in, fd2, 0, 16, 0);
            CALL("sendfile", "-", SYS_sendfile, fd2, fd, &in, 1);
            close(fd2);
        }
    }
    CALL("close_range", "1000-1010", SYS_close_range, 1000, 1010, 0);
    int p[2], q[2];
    if (pipe(p) == 0 && pipe(q) == 0)
        CALL("tee", "NONBLOCK", SYS_tee, p[0], q[1], 1, SPLICE_F_NONBLOCK);
    CALL("eventfd2", "CLOEXEC", SYS_eventfd2, 0, EFD_CLOEXEC);
    CALL("timerfd_create", "MONOTONIC", SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    CALL("inotify_init1", "-", SYS_inotify_init1, 0);
    sigset_t set;
    sigemptyset(&set);
    CALL("signalfd4", "-", SYS_signalfd4, -1, &set, 8, 0);
    CALL("getrandom", "NONBLOCK", SYS_getrandom, cpus, 16, GRND_NONBLOCK);
    long t = syscall(SYS_openat, AT_FDCWD, "/proc/self/task", O_RDONLY | O_DIRECTORY);
    report("openat", "/proc/self/task", t);
    if (t >= 0) {
        CALL("getdents64", "/proc/self/task", SYS_getdents64, t, cpus, sizeof cpus);
        close(t);
    }
    struct open_how how = {.flags = O_RDONLY};
    CALL("openat2", "/", SYS_openat2, AT_FDCWD, "/", &how, sizeof how);
    CALL("removexattr", "user.none", SYS_removexattr, "/tmp", "user.venue-probe");
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    probe();
    int root = enosys;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        who = "child";
        enosys = 0;
        probe();
        fflush(stdout);
        _exit(enosys > 100 ? 100 : enosys);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int child = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
    printf("VENUE-SUMMARY root_enosys=%d child_enosys=%d\n", root, child);
    return child;
}
