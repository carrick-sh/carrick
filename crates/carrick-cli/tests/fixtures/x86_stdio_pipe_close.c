// Part of #2820: live fork children observe inherited stdio, replace stdout
// with a pipe, write across the carrier's CPUs, close the pipe while staying
// alive until the root observes EOF, and stay closed across rescheduling.
//
// Protocol (raw Linux x86_64 syscalls, no libc):
// 1. Root writes "r" to stderr (2), proving boot stdio admission, then opens
//    four pipes (`data`, `ready`, `go`, `hold`; all > 2) and forks CHILDREN
//    (3) live children, more than the carrier's two physical CPUs.
// 2. Each child writes "c" to inherited stderr (2), dup2(2)s `data[1]` onto
//    stdout (1) (dropping its reference to boot stdout), closes its extra pipe
//    ends, writes 1 byte to `ready[1]`, closes `ready[1]`, and blocks reading
//    1 byte from `go[0]`.
// 3. Root closes its write ends of `data` and `ready` and reads `ready[0]`
//    until true EOF (`read == 0`) after CHILDREN bytes. At this barrier every
//    child has removed stdout from its fd map and parked, and Root occupies
//    one physical CPU's cache while at most one child can occupy the other's,
//    so at least two children must run on a CPU that last served another
//    table when woken.
// 4. Root writes CHILDREN bytes to `go[1]` and closes `go[1]`. Each child
//    runs ROUNDS rounds of `write(1, "x", 1)`, `sched_yield`, `getpid`, calls
//    `close(1) == 0`, checks `write(1) == -EBADF` and `close(1) == -EBADF`,
//    and blocks on `hold[0]` so all children stay alive while Root reads EOF.
// 5. Root reads `data[0]` until true EOF (`read == 0`; any negative errno
//    except -EINTR fails immediately) while all children remain parked on
//    `hold[0]`, proving EOF came from `close(1)` and not process exit.
// 6. Root writes CHILDREN bytes to `hold[1]` and closes `hold[1]`. Each child
//    wakes (crossing CPUs after Root ran), checks again that `write(1)` and
//    `close(1)` answer -EBADF, and exits 0.
// 7. Root reaps all children via `wait4` (requiring normal exit, never
//    confusing signal death with exit 0), writes `eof=1 n=120 c=0,0,0\n` to
//    stdout (1), closes stdout (`close(1) == 0`, releasing the zone's last
//    reference to boot stdout on the production crossing, then `close(1) ==
//    -EBADF`), and exits 7.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_sched_yield 24
#define SYS_dup2 33
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_pipe2 293

#define EINTR_NEG (-4)
#define EBADF_NEG (-9)

#define CHILDREN 3
#define ROUNDS 40

static void die(long code) {
    sc(SYS_exit, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static long write_all(int fd, const char *buf, long len) {
    long off = 0;
    while (off < len) {
        long n = sc(SYS_write, fd, (long)(buf + off), len - off, 0, 0, 0);
        if (n == EINTR_NEG) continue;
        if (n <= 0) return -1;
        off += n;
    }
    return 0;
}

static long read_one(int fd, char *out) {
    for (;;) {
        long n = sc(SYS_read, fd, (long)out, 1, 0, 0, 0);
        if (n == EINTR_NEG) continue;
        return n;
    }
}

static void open_pipe_above_stdio(int pair[2]) {
    if (sc(SYS_pipe2, (long)pair, 0, 0, 0, 0, 0) != 0) die(1);
    if (pair[0] <= 2 || pair[1] <= 2) die(11);
}

static void put_str(char **at, const char *s) {
    while (*s) *(*at)++ = *s++;
}

static void put_num(char **at, long value) {
    char digits[24];
    int n = 0;
    unsigned long v = value < 0 ? -(unsigned long)value : (unsigned long)value;
    if (value < 0) *(*at)++ = '-';
    do {
        digits[n++] = '0' + v % 10;
        v /= 10;
    } while (v);
    while (n) *(*at)++ = digits[--n];
}

static void child(
    int data_read,
    int data_write,
    int ready_read,
    int ready_write,
    int go_read,
    int go_write,
    int hold_read,
    int hold_write
) {
    if (sc(SYS_close, data_read, 0, 0, 0, 0, 0) != 0) die(100);
    if (sc(SYS_close, ready_read, 0, 0, 0, 0, 0) != 0) die(100);
    if (sc(SYS_close, go_write, 0, 0, 0, 0, 0) != 0) die(100);
    if (sc(SYS_close, hold_write, 0, 0, 0, 0, 0) != 0) die(100);

    // Observe boot-admitted stderr inherited across fork.
    if (write_all(2, "c", 1) != 0) die(104);

    if (sc(SYS_dup2, data_write, 1, 0, 0, 0, 0) != 1) die(100);
    if (sc(SYS_close, data_write, 0, 0, 0, 0, 0) != 0) die(105);
    if (sc(SYS_close, data_write, 0, 0, 0, 0, 0) != EBADF_NEG) die(105);

    // Signal Root that stdout's host row has been replaced, then park on `go`
    // until every sibling has done the same and Root runs on a CPU.
    if (write_all(ready_write, "r", 1) != 0) die(103);
    if (sc(SYS_close, ready_write, 0, 0, 0, 0, 0) != 0) die(103);

    char ch;
    if (read_one(go_read, &ch) != 1) die(106);
    if (sc(SYS_close, go_read, 0, 0, 0, 0, 0) != 0) die(106);

    for (int round = 0; round < ROUNDS; round++) {
        if (write_all(1, "x", 1) != 0) die(101);
        sc(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
        sc(SYS_getpid, 0, 0, 0, 0, 0, 0);
    }

    if (sc(SYS_close, 1, 0, 0, 0, 0, 0) != 0) die(102);
    if (sc(SYS_write, 1, (long)"z", 1, 0, 0, 0) != EBADF_NEG) die(107);
    if (sc(SYS_close, 1, 0, 0, 0, 0, 0) != EBADF_NEG) die(108);

    // Stay alive until Root has observed EOF on `data[0]`, so process exit
    // cannot mask a `close(1)` that failed to retire the pipe write end.
    if (read_one(hold_read, &ch) != 1) die(109);
    if (sc(SYS_close, hold_read, 0, 0, 0, 0, 0) != 0) die(109);

    // After waking behind Root on a physical CPU, fd 1 must still be closed.
    if (sc(SYS_write, 1, (long)"z", 1, 0, 0, 0) != EBADF_NEG) die(110);
    if (sc(SYS_close, 1, 0, 0, 0, 0, 0) != EBADF_NEG) die(111);
    die(0);
}

void _start(void) {
    if (write_all(2, "r", 1) != 0) die(10);

    int data[2];
    int ready[2];
    int go[2];
    int hold[2];
    open_pipe_above_stdio(data);
    open_pipe_above_stdio(ready);
    open_pipe_above_stdio(go);
    open_pipe_above_stdio(hold);

    for (int i = 0; i < CHILDREN; i++) {
        long pid = sc(SYS_fork, 0, 0, 0, 0, 0, 0);
        if (pid == 0) {
            child(
                data[0], data[1], ready[0], ready[1], go[0], go[1], hold[0],
                hold[1]
            );
        }
        if (pid < 0) die(20 - pid);
    }

    if (sc(SYS_close, data[1], 0, 0, 0, 0, 0) != 0) die(12);
    if (sc(SYS_close, ready[1], 0, 0, 0, 0, 0) != 0) die(12);
    if (sc(SYS_close, go[0], 0, 0, 0, 0, 0) != 0) die(12);
    if (sc(SYS_close, hold[0], 0, 0, 0, 0, 0) != 0) die(12);

    long ready_bytes = 0;
    int ready_eof = 0;
    char buffer[64];
    for (;;) {
        long got = sc(SYS_read, ready[0], (long)buffer, sizeof buffer, 0, 0, 0);
        if (got == 0) {
            ready_eof = 1;
            break;
        }
        if (got == EINTR_NEG) continue;
        if (got < 0) die(13);
        ready_bytes += got;
    }
    if (!ready_eof || ready_bytes != CHILDREN) die(14);
    if (sc(SYS_close, ready[0], 0, 0, 0, 0, 0) != 0) die(14);

    if (write_all(go[1], "ggg", CHILDREN) != 0) die(3);
    if (sc(SYS_close, go[1], 0, 0, 0, 0, 0) != 0) die(3);

    long bytes = 0;
    int data_eof = 0;
    for (;;) {
        long got = sc(SYS_read, data[0], (long)buffer, sizeof buffer, 0, 0, 0);
        if (got == 0) {
            data_eof = 1;
            break;
        }
        if (got == EINTR_NEG) continue;
        if (got < 0) die(15);
        bytes += got;
    }
    if (!data_eof || bytes != CHILDREN * ROUNDS) die(16);
    if (sc(SYS_close, data[0], 0, 0, 0, 0, 0) != 0) die(16);

    if (write_all(hold[1], "hhh", CHILDREN) != 0) die(17);
    if (sc(SYS_close, hold[1], 0, 0, 0, 0, 0) != 0) die(17);

    char line[128];
    char *at = line;
    put_str(&at, "eof=");
    put_num(&at, data_eof);
    put_str(&at, " n=");
    put_num(&at, bytes);
    put_str(&at, " c=");
    for (int i = 0; i < CHILDREN; i++) {
        int status = -1;
        long waited;
        do {
            waited = sc(SYS_wait4, -1, (long)&status, 0, 0, 0, 0);
        } while (waited == EINTR_NEG);
        long code;
        if (waited <= 0) {
            code = -1;
        } else if ((status & 0x7f) != 0) {
            code = -(status & 0x7f);
        } else {
            code = (status >> 8) & 0xff;
        }
        if (i) *at++ = ',';
        put_num(&at, code);
    }
    *at++ = '\n';
    if (write_all(1, line, at - line) != 0) die(18);

    // Release the zone's last reference to boot stdout on the production path.
    if (sc(SYS_close, 1, 0, 0, 0, 0, 0) != 0) die(19);
    if (sc(SYS_close, 1, 0, 0, 0, 0, 0) != EBADF_NEG) die(30);
    die(7);
}
