// System-information calls whose output buffer is a page the guest has
// mapped but never touched (git's first `getcwd` into a fresh allocation).
//
// Linux fills such a page in during the copy and the call succeeds. Each row
// prints the raw result and whether the bytes arrived; the test compares the
// rows with a native run. The root runs every row, then a forked child runs
// them again, with one more row for a page the parent touched before the
// fork (a copy-on-write page), and the parent writes that page after it.
//
// No libc and no startup code: nothing touches the buffers before the call.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
#define PG 4096L
enum { GETCWD = 79, UNAME = 63, GETRLIMIT = 97, GETRUSAGE = 98, SYSINFO = 99, PRLIMIT64 = 302 };
static char *fresh(long pages) {
    long p = sc(9, 0, pages * PG, 3, 0x22, -1, 0);
    if (p < 0 && p > -4096) sc(231, 90, 0, 0, 0, 0, 0);
    return (char *)p;
}
static int put(char *out, const char *s) {
    int n = 0;
    while (*s) out[n++] = *s++;
    return n;
}
static void row(const char *who, const char *name, long ret, int arrived) {
    char out[160];
    int n = put(out, who);
    out[n++] = ' ';
    n += put(out + n, name);
    n += put(out + n, " ret=");
    unsigned long u = (unsigned long)ret;
    for (int i = 60; i >= 0; i -= 4) out[n++] = "0123456789abcdef"[(u >> i) & 15];
    n += put(out + n, arrived ? " arrived\n" : " MISSING\n");
    sc(1, 1, (long)out, n, 0, 0, 0);
}
static void cwd_row(const char *who, const char *name, char *buffer) {
    long ret = sc(GETCWD, (long)buffer, PG, 0, 0, 0, 0);
    row(who, name, ret, ret == 5 && buffer[0] == '/' && buffer[1] == 't' && buffer[3] == 'p' && buffer[4] == 0);
}
static void rows(const char *who, char *touched, char *cow) {
    cwd_row(who, "getcwd_untouched", fresh(1));
    // "/t" at the end of one fresh page, "mp" and the NUL in the next.
    cwd_row(who, "getcwd_two_untouched_pages", fresh(2) + PG - 2);
    cwd_row(who, "getcwd_touched", touched);
    if (cow) cwd_row(who, "getcwd_cow_after_fork", cow);

    char *uts = fresh(1);
    long ret = sc(UNAME, (long)uts, 0, 0, 0, 0, 0);
    row(who, "uname_untouched", ret, ret == 0 && uts[0] == 'L');
    uts = fresh(2) + PG - 100;
    ret = sc(UNAME, (long)uts, 0, 0, 0, 0, 0);
    row(who, "uname_two_untouched_pages", ret, ret == 0 && uts[0] == 'L' && uts[130] != 0);

    unsigned long *limit = (unsigned long *)fresh(1);
    ret = sc(GETRLIMIT, 7, (long)limit, 0, 0, 0, 0);
    row(who, "getrlimit_untouched", ret, ret == 0 && limit[1] != 0);
    limit = (unsigned long *)fresh(1);
    ret = sc(PRLIMIT64, 0, 7, 0, (long)limit, 0, 0);
    row(who, "prlimit64_old_untouched", ret, ret == 0 && limit[1] != 0);

    char *usage = fresh(1);
    ret = sc(GETRUSAGE, 0, (long)usage, 0, 0, 0, 0);
    row(who, "getrusage_untouched", ret, ret == 0);
    unsigned long *info = (unsigned long *)fresh(1);
    ret = sc(SYSINFO, (long)info, 0, 0, 0, 0, 0);
    row(who, "sysinfo_untouched", ret, ret == 0 && info[4] != 0);
}
void start_c(void) {
    // A cwd that is not the root directory; the image may not have it yet.
    sc(83, (long)"/tmp", 0777, 0, 0, 0, 0);
    if (sc(80, (long)"/tmp", 0, 0, 0, 0, 0) != 0) sc(231, 91, 0, 0, 0, 0, 0);
    char *touched = fresh(1);
    touched[0] = 1;
    char *cow = fresh(1);
    cow[0] = 2;
    rows("root", touched, 0);
    long pid = sc(57, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        rows("child", touched, cow);
        sc(231, 0, 0, 0, 0, 0, 0);
    }
    int status = -1;
    if (pid < 0 || sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0)
        sc(231, 95, 0, 0, 0, 0, 0);
    char *parent_cow = fresh(1);
    parent_cow[0] = 3;
    pid = sc(57, 0, 0, 0, 0, 0, 0);
    if (pid == 0) sc(231, 0, 0, 0, 0, 0, 0);
    cwd_row("parent", "getcwd_cow_after_fork", parent_cow);
    if (pid < 0 || sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0)
        sc(231, 96, 0, 0, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
