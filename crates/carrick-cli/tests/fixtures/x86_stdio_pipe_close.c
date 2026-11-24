// #2820: live fork children replace stdout with a pipe, then close it.
//
// The root makes one pipe and forks CHILDREN children, more live processes
// than the carrier has CPUs, so their tables share CPUs. Each child:
// - dup2(2)s the pipe's write end onto 1 (stdout's last reference in this
//   table goes; the description lives on in the root's table) and closes
//   both pipe numbers;
// - parks reading one byte from a second "go" pipe until the root has
//   forked every child, so every CPU serves other tables meanwhile;
// - runs ROUNDS rounds of write(1, "x") and sched_yield(2) beside its
//   siblings, so its table is seen again by a CPU that served another table;
// - closes 1, reports the close's raw return value as its exit status
//   (0 is Linux's answer), and exits.
// The root closes its write end, counts the bytes until EOF, reaps every
// child, prints one line `n=<bytes> c=<child statuses>` and exits 7.
// Linux: n is CHILDREN * ROUNDS, every child status is 0. A resurrected
// stdout in a child's table shadows the pipe; its close then releases a
// second stdout description. A failed fork exits 20 + errno at once. No
// libc: raw syscalls only.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
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

#define CHILDREN 3
#define ROUNDS 40

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

static void child(int pipe_read, int pipe_write, int go_read, int go_write) {
    if (sc(SYS_dup2, pipe_write, 1, 0, 0, 0, 0) != 1) sc(SYS_exit, 100, 0, 0, 0, 0, 0);
    sc(SYS_close, pipe_read, 0, 0, 0, 0, 0);
    sc(SYS_close, pipe_write, 0, 0, 0, 0, 0);
    sc(SYS_close, go_write, 0, 0, 0, 0, 0);
    char go;
    if (sc(SYS_read, go_read, (long)&go, 1, 0, 0, 0) != 1) sc(SYS_exit, 103, 0, 0, 0, 0, 0);
    sc(SYS_close, go_read, 0, 0, 0, 0, 0);
    for (int round = 0; round < ROUNDS; round++) {
        if (sc(SYS_write, 1, (long)"x", 1, 0, 0, 0) != 1) sc(SYS_exit, 101, 0, 0, 0, 0, 0);
        sc(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
        sc(SYS_getpid, 0, 0, 0, 0, 0, 0);
    }
    long closed = sc(SYS_close, 1, 0, 0, 0, 0, 0);
    sc(SYS_exit, closed == 0 ? 0 : 102, 0, 0, 0, 0, 0);
}

void _start(void) {
    int fds[2];
    int go[2];
    if (sc(SYS_pipe2, (long)fds, 0, 0, 0, 0, 0) != 0) sc(SYS_exit, 1, 0, 0, 0, 0, 0);
    if (sc(SYS_pipe2, (long)go, 0, 0, 0, 0, 0) != 0) sc(SYS_exit, 1, 0, 0, 0, 0, 0);
    for (int i = 0; i < CHILDREN; i++) {
        long pid = sc(SYS_fork, 0, 0, 0, 0, 0, 0);
        if (pid == 0) child(fds[0], fds[1], go[0], go[1]);
        if (pid < 0) sc(SYS_exit, 20 - pid, 0, 0, 0, 0, 0);
    }
    sc(SYS_close, fds[1], 0, 0, 0, 0, 0);
    sc(SYS_close, go[0], 0, 0, 0, 0, 0);
    if (sc(SYS_write, go[1], (long)"ggg", CHILDREN, 0, 0, 0) != CHILDREN) sc(SYS_exit, 3, 0, 0, 0, 0, 0);
    sc(SYS_close, go[1], 0, 0, 0, 0, 0);
    long bytes = 0;
    char buffer[64];
    for (;;) {
        long got = sc(SYS_read, fds[0], (long)buffer, sizeof buffer, 0, 0, 0);
        if (got <= 0) break;
        bytes += got;
    }
    char line[128];
    char *at = line;
    *at++ = 'n';
    *at++ = '=';
    put_num(&at, bytes);
    *at++ = ' ';
    *at++ = 'c';
    *at++ = '=';
    for (int i = 0; i < CHILDREN; i++) {
        int status = 0;
        if (sc(SYS_wait4, -1, (long)&status, 0, 0, 0, 0) <= 0) status = -1;
        else status = (status >> 8) & 0xff;
        if (i) *at++ = ',';
        put_num(&at, status);
    }
    *at++ = '\n';
    sc(SYS_write, 1, (long)line, at - line, 0, 0, 0);
    sc(SYS_exit, 7, 0, 0, 0, 0, 0);
}
