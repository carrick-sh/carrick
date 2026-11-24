// A non-private futex on a writable MAP_SHARED file mapping (#1338 v3 C5).
//
// The root maps a file shared and writable, forks a child, and WAITs on a
// word of the mapping with a one-second relative timeout; the child stores
// to the word and WAKEs it. Each prints one row: its futex result in hex.
// Until shared futex keys for file pages land (#1338 B), Carrick fences
// both calls as a counted ENOSYS, which must never hang either process.
// Exit 7 when the child exited 0.
//
// Files are created in the working directory. No libc and no startup code.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
enum { WRITE = 1, CLOSE = 3, MMAP = 9, MUNMAP = 11, FORK = 57, EXIT = 60, WAIT4 = 61, FTRUNCATE = 77,
       FUTEX = 202, OPENAT = 257 };
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define PROT_RW 3
#define MAP_SHARED 1
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
static void row(const char *name, long ret) {
    char out[64];
    int n = 0;
    while (*name) out[n++] = *name++;
    out[n++] = '=';
    unsigned long u = (unsigned long)ret;
    for (int i = 60; i >= 0; i -= 4) out[n++] = "0123456789abcdef"[(u >> i) & 15];
    out[n++] = '\n';
    sc(WRITE, 1, (long)out, n, 0, 0, 0);
}
void _start(void) {
    long fd = sc(OPENAT, AT_FDCWD, (long)"futex-window", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, 4096, 0, 0, 0, 0) : fd;
    long p = r == 0 ? sc(MMAP, 0, 4096, PROT_RW, MAP_SHARED, fd, 0) : r;
    if (p < 0 && p > -4096) {
        row("setup", p);
        sc(EXIT, 90, 0, 0, 0, 0, 0);
    }
    volatile int *word = (volatile int *)(p + 64);
    *word = 0;
    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        *word = 1;
        long woke = sc(FUTEX, (long)word, FUTEX_WAKE, 1, 0, 0, 0);
        row("child_wake", woke);
        sc(EXIT, 0, 0, 0, 0, 0, 0);
    }
    struct { long sec, nsec; } timeout = {1, 0};
    long waited = sc(FUTEX, (long)word, FUTEX_WAIT, 0, (long)&timeout, 0, 0);
    // Native: 0 (woken), -EAGAIN (the store came first) or -ETIMEDOUT.
    row("root_wait", waited);
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);
    sc(MUNMAP, p, 4096, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
    sc(EXIT, w == pid && status == 0 ? 7 : 95, 0, 0, 0, 0, 0);
}
