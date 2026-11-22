// The first syscall an exec'd image makes, aarch64 (#2731 discovery probe).
//
// With no argument the root forks one child per table row; each child execs
// this image with the row's index, and the root then execs itself for row 0.
// With an index, `_start` makes that call twice with the same arguments, as
// the image's very first syscall and again, and prints both raw results. A
// first result of -38 (ENOSYS) with a different second result is a call
// refused only because it was first: `FIRST-ONLY-ENOSYS`. A child that does
// not exit 0 gets a `row N child-status=` line and the run goes on.
// Exit 7 from the root's own row. No libc and no startup code.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
static char scratch[4096] __attribute__((aligned(4096)));
static char page[8192] __attribute__((aligned(4096)));
struct call { const char *name; long nr, a, b, c, d, e, f; };
#define S ((long)scratch)
static const struct call calls[] = {
    {"brk0", 214, 0},
    {"mmap_anon", 222, 0, 4096, 3, 0x22, -1, 0},
    {"munmap", 215, (long)page, 4096},
    {"mprotect", 226, (long)page, 4096, 3},
    {"madvise_normal", 233, (long)page, 4096, 0},
    {"madvise_dontneed", 233, (long)page, 4096, 4},
    {"getpid", 172},
    {"gettid", 178},
    {"getppid", 173},
    {"getuid", 174},
    {"getpgid", 155, 0},
    {"clock_gettime", 113, 1, S},
    {"gettimeofday", 169, S, 0},
    {"uname", 160, S},
    {"rt_sigaction", 134, 10, 0, S, 8},
    {"rt_sigprocmask", 135, 0, 0, S, 8},
    {"sigaltstack", 132, 0, S},
    {"set_tid_address", 96, S},
    {"set_robust_list", 99, S, 24},
    {"prlimit_stack", 261, 0, 3, 0, S},
    {"getrlimit", 163, 3, S},
    {"getrandom", 278, S, 8, 0},
    {"write0", 64, 1, S, 0},
    {"fstat1", 80, 1, S},
    {"newfstatat", 79, -100, (long)"/", S, 0},
    {"ioctl_tcgets", 29, 1, 0x5401, S},
    {"futex_wake", 98, S, 1, 1},
    {"sched_yield", 124},
    {"sched_getaffinity", 123, 0, 128, S},
    {"pipe2", 59, S, 0},
    {"dup", 23, 1},
    {"close_bad", 57, 100},
    {"fcntl_getfd", 25, 1, 1},
    {"lseek", 62, 1, 0, 1},
    {"getcwd", 17, S, 4096},
    {"readlinkat_exe", 78, -100, (long)"/proc/self/exe", S, 4096},
    {"openat_root", 56, -100, (long)"/", 0},
    {"faccessat", 48, -100, (long)"/", 0},
    {"ppoll0", 73, 0, 0, S + 2048, 0},
    {"nanosleep0", 101, S + 2048, 0},
    {"sysinfo", 179, S},
    {"umask", 166, 022},
    {"kill0", 129, 0, 0},
    {"wait4_none", 260, -1, 0, 1, 0},
    {"epoll_create1", 20, 0},
    {"eventfd2", 19, 0, 0},
    {"socket_unix", 198, 1, 1, 0},
    {"prctl_get_name", 167, 16, S},
    {"rseq", 293, S, 32, 0, 0x53053053},
    {"getdents_bad", 61, 100, S, 4096},
    {"membarrier_q", 283, 0, 0},
};
static int fmt(char *out, const char *s, long v) {
    int n = 0;
    while (*s) out[n++] = *s++;
    out[n++] = '=';
    unsigned long u = (unsigned long)v;
    for (int i = 60; i >= 0; i -= 4) out[n++] = "0123456789abcdef"[(u >> i) & 15];
    out[n++] = ' ';
    return n;
}
static long parse(const char *p) {
    long value = 0;
    for (; *p >= '0' && *p <= '9'; p++) value = value * 10 + (*p - '0');
    return value;
}
static void probe(long which) {
    const struct call *c = &calls[which];
    long first = sc(c->nr, c->a, c->b, c->c, c->d, c->e, c->f);
    long second = sc(c->nr, c->a, c->b, c->c, c->d, c->e, c->f);
    char out[256];
    int n = 0;
    for (const char *s = c->name; *s; s++) out[n++] = *s;
    out[n++] = ' ';
    n += fmt(out + n, "first", first);
    n += fmt(out + n, "second", second);
    const char *verdict = (first == -38 && second != -38) ? "FIRST-ONLY-ENOSYS\n" : "same\n";
    for (const char *s = verdict; *s; s++) out[n++] = *s;
    sc(64, 1, (long)out, n, 0, 0, 0);
}
static void exec_row(char **argv, char **envp, long which, int root) {
    char index[8];
    int n = 0;
    if (which >= 10) index[n++] = '0' + which / 10;
    index[n++] = '0' + which % 10;
    index[n] = 0;
    char *args[] = {argv[0], index, root ? "root" : 0, 0};
    sc(221, (long)argv[0], (long)args, (long)envp, 0, 0, 0);
    sc(221, (long)"/proc/self/exe", (long)args, (long)envp, 0, 0, 0);
    sc(94, 93, 0, 0, 0, 0, 0);
}
void start_c(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    long count = sizeof calls / sizeof calls[0];
    if (argc > 1) {
        long which = parse(argv[1]);
        if (which >= count) sc(94, 94, 0, 0, 0, 0, 0);
        probe(which);
        sc(94, argc > 2 ? 7 : 0, 0, 0, 0, 0, 0);
    }
    for (long which = 0; which < count; which++) {
        long pid = sc(220, 17, 0, 0, 0, 0, 0);
        if (pid == 0) exec_row(argv, envp, which, 0);
        int status = -1;
        long got = pid < 0 ? pid : sc(260, pid, (long)&status, 0, 0, 0, 0);
        if (pid < 0 || got != pid || status != 0) {
            char out[96];
            int n = fmt(out, "row", which);
            n += fmt(out + n, "child-status", status);
            n += fmt(out + n, "fork-or-wait", got);
            out[n++] = '\n';
            sc(64, 1, (long)out, n, 0, 0, 0);
        }
    }
    exec_row(argv, envp, 0, 1);
}
__asm__(".globl _start\n_start:\n mov x0, sp\n bl start_c\n brk #1\n");
