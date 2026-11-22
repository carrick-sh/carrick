// The first syscall an exec'd image makes (#2731).
//
// With no argument the root forks one child per table row; each child execs
// this image with the row's index, and the root then execs itself for row 0.
// With an index, `_start` makes that call twice with the same arguments, as
// the image's very first syscall and again, and prints both raw results. A
// first result of -38 (ENOSYS) with a different second result is a call
// refused only because it was first: `FIRST-ONLY-ENOSYS`.
//
// No libc and no startup code, so nothing runs before the probed call.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
static char scratch[4096] __attribute__((aligned(4096)));
static char page[8192] __attribute__((aligned(4096)));
struct call { const char *name; long nr, a, b, c, d, e, f; };
#define S ((long)scratch)
static const struct call calls[] = {
    {"brk0", 12, 0},
    {"mmap_anon", 9, 0, 4096, 3, 0x22, -1, 0},
    {"munmap", 11, (long)page, 4096},
    {"mprotect", 10, (long)page, 4096, 3},
    {"madvise_normal", 28, (long)page, 4096, 0},
    {"getpid", 39},
    {"gettid", 186},
    {"uname", 63, S},
    {"rt_sigaction", 13, 10, 0, S, 8},
    {"rt_sigprocmask", 14, 0, 0, S, 8},
    {"set_tid_address", 218, S},
    {"write0", 1, 1, S, 0},
    {"futex_wake", 202, S, 1, 1},
    {"nanosleep0", 35, S + 2048, 0},
    {"kill0", 62, 0, 0},
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
    sc(1, 1, (long)out, n, 0, 0, 0);
}
static void exec_row(char **argv, char **envp, long which, int root) {
    char index[8];
    int n = 0;
    if (which >= 10) index[n++] = '0' + which / 10;
    index[n++] = '0' + which % 10;
    index[n] = 0;
    char *args[] = {argv[0], index, root ? "root" : 0, 0};
    sc(59, (long)argv[0], (long)args, (long)envp, 0, 0, 0);
    sc(59, (long)"/proc/self/exe", (long)args, (long)envp, 0, 0, 0);
    sc(231, 93, 0, 0, 0, 0, 0);
}
void start_c(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    long count = sizeof calls / sizeof calls[0];
    if (argc > 1) {
        long which = parse(argv[1]);
        if (which >= count) sc(231, 94, 0, 0, 0, 0, 0);
        probe(which);
        // The root's own exec ends the run with the fixture's success code.
        sc(231, argc > 2 ? 7 : 0, 0, 0, 0, 0, 0);
    }
    for (long which = 0; which < count; which++) {
        long pid = sc(57, 0, 0, 0, 0, 0, 0);
        if (pid == 0) exec_row(argv, envp, which, 0);
        int status = -1;
        if (pid < 0 || sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0)
            sc(231, 95, 0, 0, 0, 0, 0);
    }
    exec_row(argv, envp, 0, 1);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
