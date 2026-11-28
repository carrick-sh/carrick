// #3012: fork live children until a fork is refused, then name the refusal.
//
// Raw Linux x86_64 syscalls, no libc. The root opens a pipe and forks up to
// CHILDREN children. Each child closes the write end and blocks reading the
// pipe, so every child stays live while the root forks the next. The root
// stops at the first fork that fails and keeps its errno. It then closes the
// write end, so every child reads EOF and exits 0, reaps them all (a child
// that did not exit 0 exits 95), writes `forked=<n> errno=<e>\n` to stdout and
// exits 7. Linux forks all of them: `forked=64 errno=0`.
static long sc(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return ret;
}

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_pipe2 293

#define EINTR_NEG (-4)
#define CHILDREN 64

static void die(long code) {
    sc(SYS_exit, code, 0, 0, 0);
    __builtin_unreachable();
}

static char *put_num(char *out, long value) {
    char digits[20];
    int count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count != 0) *out++ = digits[--count];
    return out;
}

static char *put_str(char *out, const char *text) {
    while (*text) *out++ = *text++;
    return out;
}

void _start(void) {
    int fds[2];
    if (sc(SYS_pipe2, (long)fds, 0, 0, 0) != 0) die(90);
    long forked = 0;
    long refused = 0;
    while (forked < CHILDREN) {
        long pid = sc(SYS_fork, 0, 0, 0, 0);
        if (pid == 0) {
            char byte;
            sc(SYS_close, fds[1], 0, 0, 0);
            long n;
            do {
                n = sc(SYS_read, fds[0], (long)&byte, 1, 0);
            } while (n == EINTR_NEG);
            die(n == 0 ? 0 : 94);
        }
        if (pid < 0) {
            refused = -pid;
            break;
        }
        forked++;
    }
    if (sc(SYS_close, fds[1], 0, 0, 0) != 0) die(91);
    for (long reaped = 0; reaped < forked; reaped++) {
        int status = 0;
        long pid;
        do {
            pid = sc(SYS_wait4, -1, (long)&status, 0, 0);
        } while (pid == EINTR_NEG);
        if (pid <= 0) die(92);
        if ((status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0) die(95);
    }
    char line[64];
    char *end = put_str(line, "forked=");
    end = put_num(end, forked);
    end = put_str(end, " errno=");
    end = put_num(end, refused);
    *end++ = '\n';
    if (sc(SYS_write, 1, (long)line, end - line, 0) != end - line) die(93);
    die(7);
}
