// A shrink of a file a live writable MAP_SHARED mapping still maps (#1338 A1).
//
// The root maps two pages of a file shared and writable, stores a byte to
// each, and forks a child. The child shrinks the file through its inherited
// descriptor (ftruncate, a fallocate hole punch, a fallocate collapse); the
// root then shrinks it by name (truncate, an O_TRUNC open). Until a shrink
// revokes the window leaves first (#1338 A3), Carrick fences every one as a
// counted ENOSYS before the host applies it, so the file keeps its size and
// both processes still read their byte on the second page. On native Linux
// the child's touch of that page after its ftruncate is SIGBUS; before the
// fence the host shrink pulled the page out from under the carrier's live
// window leaf, and the run hung on that touch until the KVM deadline. A
// shrink of a file no window maps, and a growth of the mapped one, are
// served. Each step prints one row: its result in hex. Exit 7 once the
// child is reaped.
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
enum { WRITE = 1, CLOSE = 3, MMAP = 9, MUNMAP = 11, FORK = 57, EXIT = 60, WAIT4 = 61, TRUNCATE = 76,
       FTRUNCATE = 77, OPENAT = 257, FALLOCATE = 285 };
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define PROT_RW 3
#define MAP_SHARED 1
#define FALLOC_FL_KEEP_SIZE 1
#define FALLOC_FL_PUNCH_HOLE 2
#define FALLOC_FL_COLLAPSE_RANGE 8
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
static long reopen(const char *path, long flags) {
    long fd = sc(OPENAT, AT_FDCWD, (long)path, flags, 0644, 0, 0);
    if (fd >= 0) {
        sc(CLOSE, fd, 0, 0, 0, 0, 0);
        return 0;
    }
    return fd;
}
void _start(void) {
    long fd = sc(OPENAT, AT_FDCWD, (long)"shrink-window", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, 8192, 0, 0, 0, 0) : fd;
    long p = r == 0 ? sc(MMAP, 0, 8192, PROT_RW, MAP_SHARED, fd, 0) : r;
    if (p < 0 && p > -4096) {
        row("setup", p);
        sc(EXIT, 90, 0, 0, 0, 0, 0);
    }
    volatile unsigned char *bytes = (volatile unsigned char *)p;
    bytes[0] = 0x41;
    bytes[4096] = 0x42;
    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        row("child_ftruncate", sc(FTRUNCATE, fd, 4096, 0, 0, 0, 0));
        // Native: SIGBUS (the page is past the new end of the file).
        row("child_touch", bytes[4096]);
        row("child_punch", sc(FALLOCATE, fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 4096, 4096, 0, 0));
        row("child_collapse", sc(FALLOCATE, fd, FALLOC_FL_COLLAPSE_RANGE, 0, 4096, 0, 0));
        sc(EXIT, 0, 0, 0, 0, 0, 0);
    }
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);
    // Native: 7, killed by SIGBUS. Fenced: 0, a clean exit.
    row("child_status", status);
    row("root_truncate", sc(TRUNCATE, (long)"shrink-window", 4096, 0, 0, 0, 0));
    row("root_otrunc", reopen("shrink-window", O_RDWR | O_TRUNC | O_CLOEXEC));
    // Growth never pulls a page out from under a mapping: served.
    row("root_grow", sc(FTRUNCATE, fd, 12288, 0, 0, 0, 0));
    // Carrick fenced every shrink, so the byte is still there. Native Linux
    // applied them and the growth above zero-filled the page again.
    row("root_page2", bytes[4096]);
    // A file no window maps shrinks as before.
    long plain = sc(OPENAT, AT_FDCWD, (long)"shrink-plain", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long grown = plain >= 0 ? sc(FTRUNCATE, plain, 8192, 0, 0, 0, 0) : plain;
    row("plain_shrink", grown == 0 ? sc(FTRUNCATE, plain, 0, 0, 0, 0, 0) : grown);
    sc(MUNMAP, p, 8192, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
    sc(EXIT, w == pid ? 7 : 95, 0, 0, 0, 0, 0);
}
