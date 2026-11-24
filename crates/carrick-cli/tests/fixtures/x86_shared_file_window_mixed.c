// Range edits that meet a shared file window page and a private page in one
// call, and PROT_NONE over a window page (#1338 A1, the served surface).
//
// Each pair is a private anonymous page followed by a MAP_SHARED|MAP_FIXED
// window page of `mixed-window`. A munmap of the pair is served when at most
// one of the two kinds holds a faulted page; when both do, no one edit step
// covers both, so the call is a counted ENOSYS and both pages stay mapped
// (they are unmapped one page at a time after). PROT_NONE over a faulted
// window page is a counted ENOSYS (x86 has no present inaccessible user
// leaf, as for a private page); over an unfaulted one it is served. Native
// Linux serves every row. Each step prints one row: its result in hex.
// Exit 7.
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
enum { WRITE = 1, CLOSE = 3, MMAP = 9, MPROTECT = 10, MUNMAP = 11, EXIT = 60, FTRUNCATE = 77, OPENAT = 257 };
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define PROT_NONE 0
#define PROT_RW 3
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
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
static void fail(const char *name, long ret) {
    row(name, ret);
    sc(EXIT, 90, 0, 0, 0, 0, 0);
}
// A private anonymous page at `base`, a window page of `fd` at base + 4096.
static volatile unsigned char *pair(long fd) {
    long p = sc(MMAP, 0, 8192, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p < 0 && p > -4096) fail("pair_anon", p);
    long w = sc(MMAP, p + 4096, 4096, PROT_RW, MAP_SHARED | MAP_FIXED, fd, 0);
    if (w != p + 4096) fail("pair_window", w);
    return (volatile unsigned char *)p;
}
static volatile unsigned char *window(long fd) {
    long w = sc(MMAP, 0, 4096, PROT_RW, MAP_SHARED, fd, 0);
    if (w < 0 && w > -4096) fail("window", w);
    return (volatile unsigned char *)w;
}
void _start(void) {
    long fd = sc(OPENAT, AT_FDCWD, (long)"mixed-window", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, 4096, 0, 0, 0, 0) : fd;
    if (r != 0) fail("setup", r);

    volatile unsigned char *a = pair(fd);
    a[0] = 1;
    a[4096] = 0x41;
    long m = sc(MUNMAP, (long)a, 8192, 0, 0, 0, 0);
    row("mixed_both_faulted_munmap", m);
    if (m != 0) {
        // Refused: both pages are still there, and each kind unmaps alone.
        row("mixed_both_faulted_kept", a[0] == 1 && a[4096] == 0x41);
        long first = sc(MUNMAP, (long)a, 4096, 0, 0, 0, 0);
        long second = sc(MUNMAP, (long)a + 4096, 4096, 0, 0, 0, 0);
        row("mixed_both_faulted_split", first | second);
    }

    volatile unsigned char *b = pair(fd);
    b[4096] = 0x42;
    row("mixed_window_faulted_munmap", sc(MUNMAP, (long)b, 8192, 0, 0, 0, 0));

    volatile unsigned char *c = pair(fd);
    c[0] = 1;
    row("mixed_private_faulted_munmap", sc(MUNMAP, (long)c, 8192, 0, 0, 0, 0));

    volatile unsigned char *d = window(fd);
    d[0] = 0x43;
    long n = sc(MPROTECT, (long)d, 4096, PROT_NONE, 0, 0, 0);
    row("protnone_faulted", n);
    sc(MUNMAP, (long)d, 4096, 0, 0, 0, 0);

    volatile unsigned char *e = window(fd);
    row("protnone_unfaulted", sc(MPROTECT, (long)e, 4096, PROT_NONE, 0, 0, 0));
    row("protnone_unfaulted_restore", sc(MPROTECT, (long)e, 4096, PROT_RW, 0, 0, 0));
    row("protnone_unfaulted_reads", e[0]);
    sc(MUNMAP, (long)e, 4096, 0, 0, 0, 0);

    sc(CLOSE, fd, 0, 0, 0, 0, 0);
    sc(EXIT, 7, 0, 0, 0, 0, 0);
}
