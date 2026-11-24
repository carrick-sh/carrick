// A shrink by name, through a bind mount, of a file a live writable
// MAP_SHARED mapping still maps (#1338 A1, #2977).
//
// The root maps two pages of `data/win` shared and writable, stores a byte
// to the second page, and forks a child. `data` is a bind mount of a host
// directory, so both names reach the host file itself. The child shrinks
// the file by name: truncate(2), then an O_TRUNC open. Until a shrink
// revokes the window leaves first (#1338 A3), Carrick fences both as a
// counted ENOSYS before the host applies them, so the child still reads its
// byte on the second page. On native Linux the child's touch of that page
// after its truncate is SIGBUS. Before the fence keyed on the bind mount's
// host inode, the mount's own open and truncate shrank the host file under
// the carrier's live window leaf. Each step prints one row: its result in
// hex. Exit 7 once the child is reaped.
//
// No libc and no startup code.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
enum { WRITE = 1, CLOSE = 3, MMAP = 9, MUNMAP = 11, FORK = 57, EXIT = 60, WAIT4 = 61, TRUNCATE = 76,
       FTRUNCATE = 77, OPENAT = 257 };
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define PROT_RW 3
#define MAP_SHARED 1
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
    static const char path[] = "data/win";
    long fd = sc(OPENAT, AT_FDCWD, (long)path, O_RDWR | O_CREAT | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, 8192, 0, 0, 0, 0) : fd;
    long p = r == 0 ? sc(MMAP, 0, 8192, PROT_RW, MAP_SHARED, fd, 0) : r;
    if (p < 0 && p > -4096) {
        row("setup", p);
        sc(EXIT, 90, 0, 0, 0, 0, 0);
    }
    volatile unsigned char *bytes = (volatile unsigned char *)p;
    bytes[4096] = 0x42;
    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        row("child_truncate", sc(TRUNCATE, (long)path, 4096, 0, 0, 0, 0));
        long t = sc(OPENAT, AT_FDCWD, (long)path, O_RDWR | O_TRUNC | O_CLOEXEC, 0, 0, 0);
        if (t >= 0) {
            sc(CLOSE, t, 0, 0, 0, 0, 0);
            t = 0;
        }
        row("child_otrunc", t);
        // Native: SIGBUS (the page is past the new end of the file).
        row("child_touch", bytes[4096]);
        sc(EXIT, 0, 0, 0, 0, 0, 0);
    }
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);
    // Native: 7, killed by SIGBUS. Fenced: 0, a clean exit.
    row("child_status", status);
    sc(MUNMAP, p, 8192, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
    sc(EXIT, w == pid ? 7 : 95, 0, 0, 0, 0, 0);
}
