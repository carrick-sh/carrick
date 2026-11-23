// close_range(2) in the run root and in a fork child, compared with Linux.
//
// Each process opens two pipes (four consecutive numbers b..b+3, the lowest
// free ones; a test harness may hold a lower one open) and prints one line
// per call with its raw return value and the F_GETFD answer of b..b+3 after
// it (-9 is EBADF, 1 is FD_CLOEXEC):
// - the invalid shapes first (first > last, an unknown flag): EINVAL, and
//   nothing is closed;
// - CLOSE_RANGE_CLOEXEC on b..b: b stays open with FD_CLOEXEC;
// - a range past the table (b+2..~0U): b+2 and b+3 close;
// - CLOSE_RANGE_UNSHARE on b+1..b+1: b+1 closes;
// - a range with nothing open (b+100..b+200): 0.
// The child runs first and exits 0; the root waits for it, runs the same
// sequence and exits 7. No libc: raw syscalls only.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

#define CLOSE_RANGE_UNSHARE 2
#define CLOSE_RANGE_CLOEXEC 4

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

static long base;

static void report(char who, const char *what, long ret) {
    char line[128];
    char *at = line;
    *at++ = who;
    *at++ = ' ';
    while (*what) *at++ = *what++;
    *at++ = '=';
    put_num(&at, ret);
    for (long fd = base; fd <= base + 3; fd++) {
        *at++ = ' ';
        put_num(&at, sc(72, fd, 1, 0, 0, 0, 0)); // fcntl(fd, F_GETFD)
    }
    *at++ = '\n';
    sc(1, 1, (long)line, at - line, 0, 0, 0);
}

static void sequence(char who) {
    int fds[4];
    if (sc(293, (long)fds, 0, 0, 0, 0, 0) != 0 || sc(293, (long)(fds + 2), 0, 0, 0, 0, 0) != 0)
        sc(231, 96, 0, 0, 0, 0, 0);
    base = fds[0];
    report(who, "open", fds[3] - fds[0]);
    report(who, "reversed", sc(436, base + 2, base + 1, 0, 0, 0, 0));
    report(who, "badflag", sc(436, base, base + 3, 8, 0, 0, 0));
    report(who, "cloexec", sc(436, base, base, CLOSE_RANGE_CLOEXEC, 0, 0, 0));
    report(who, "tail", sc(436, base + 2, ~0U, 0, 0, 0, 0));
    report(who, "unshare", sc(436, base + 1, base + 1, CLOSE_RANGE_UNSHARE, 0, 0, 0));
    report(who, "empty", sc(436, base + 100, base + 200, 0, 0, 0, 0));
    sc(3, base, 0, 0, 0, 0, 0);
}

void start_c(long *sp) {
    (void)sp;
    long pid = sc(57, 0, 0, 0, 0, 0, 0); // fork
    if (pid == 0) {
        sequence('c');
        sc(231, 0, 0, 0, 0, 0, 0);
    }
    if (pid < 0) sc(231, 95, 0, 0, 0, 0, 0);
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) sc(231, 94, 0, 0, 0, 0, 0);
    sequence('r');
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
