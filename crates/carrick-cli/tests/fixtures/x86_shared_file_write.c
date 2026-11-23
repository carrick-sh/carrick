// Writable MAP_SHARED file mappings (#1338 step 2): the Go linker's shape.
//
// The linker opens its output O_RDWR|O_CREAT|O_TRUNC, sizes it with fallocate
// and ftruncate, maps it PROT_READ|PROT_WRITE MAP_SHARED, writes through the
// mapping, unmaps it with no msync, grows the file and maps it again. Another
// process then opens the file by path and reads it. On Linux every byte
// written through the mapping is in the file at once.
//
// Rows (each prints its raw result and ok or BAD; the test compares with a
// native run):
//   linker_*   the linker's sequence, then a fresh open + read of the file;
//   shared_*   a parent and a forked child map one file shared and writable;
//              the child writes, the parent reads the bytes through its own
//              live mapping and with pread, with no msync (two live
//              processes);
//   fixed_*    MAP_SHARED|MAP_POPULATE|MAP_FIXED over a reservation, a write,
//              msync(MS_SYNC), then a read by path;
//   double_map_* one page mapped twice; after the first munmap the second
//              mapping still writes the file;
//   dev_zero_* a MAP_SHARED /dev/zero page shared with a forked child.
// The root runs every row, then a forked child runs them all again (the Go
// linker is a forked child of `go build`). Exit 7 when every row ran.
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
enum { READ = 0, WRITE = 1, CLOSE = 3, MMAP = 9, MUNMAP = 11, PREAD64 = 17, PIPE = 22, MSYNC = 26, FORK = 57,
       EXIT = 60, WAIT4 = 61, FTRUNCATE = 77, OPENAT = 257, FALLOCATE = 285 };
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE 0x8000
#define MS_SYNC 4
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define PROT_RW 3
#define MAP_SHARED 1
#define PG 4096L
static int put(char *out, const char *s) {
    int n = 0;
    while (*s) out[n++] = *s++;
    return n;
}
static void row(const char *who, const char *name, long ret, int ok) {
    char out[160];
    int n = put(out, who);
    out[n++] = ' ';
    n += put(out + n, name);
    n += put(out + n, " ret=");
    unsigned long u = (unsigned long)ret;
    for (int i = 60; i >= 0; i -= 4) out[n++] = "0123456789abcdef"[(u >> i) & 15];
    n += put(out + n, ok ? " ok\n" : " BAD\n");
    sc(WRITE, 1, (long)out, n, 0, 0, 0);
}
static unsigned char pattern(long i, int round) { return (unsigned char)(i * 7 + round * 13 + (i >> 12)); }
// The page buffer for read-back: static, so the check reads a touched page.
static unsigned char back[8 * PG];

// The linker's sequence on `path`, then a read-back through a new description.
static void linker_rows(const char *who, const char *path) {
    const long n1 = 3 * PG + 123, n2 = 5 * PG + 77;
    long fd = sc(OPENAT, AT_FDCWD, (long)path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0755, 0, 0);
    row(who, "linker_open", fd >= 0 ? 0 : fd, fd >= 0);
    if (fd < 0) return;
    long r = sc(FALLOCATE, fd, 0, 0, n1, 0, 0);
    row(who, "linker_fallocate", r, r == 0);
    r = sc(FTRUNCATE, fd, n1, 0, 0, 0, 0);
    row(who, "linker_ftruncate", r, r == 0);
    long p = sc(MMAP, 0, n1, PROT_RW, MAP_SHARED, fd, 0);
    int mapped = !(p < 0 && p > -4096);
    row(who, "linker_mmap_rw_shared", mapped ? 0 : p, mapped);
    if (mapped) {
        for (long i = 0; i < n1; i++) ((unsigned char *)p)[i] = pattern(i, 1);
        r = sc(MUNMAP, p, n1, 0, 0, 0, 0);
        row(who, "linker_munmap", r, r == 0);
    }
    r = sc(FALLOCATE, fd, 0, 0, n2, 0, 0);
    row(who, "linker_fallocate_grow", r, r == 0);
    r = sc(FTRUNCATE, fd, n2, 0, 0, 0, 0);
    row(who, "linker_ftruncate_grow", r, r == 0);
    p = sc(MMAP, 0, n2, PROT_RW, MAP_SHARED, fd, 0);
    mapped = !(p < 0 && p > -4096);
    row(who, "linker_mmap_grown", mapped ? 0 : p, mapped);
    int kept = mapped;
    if (mapped) {
        // The first round's bytes are in the grown mapping; write the rest.
        for (long i = 0; i < n1; i++) kept &= ((unsigned char *)p)[i] == pattern(i, 1);
        for (long i = n1; i < n2; i++) ((unsigned char *)p)[i] = pattern(i, 2);
        r = sc(MUNMAP, p, n2, 0, 0, 0, 0);
        row(who, "linker_munmap_grown", r, r == 0);
    }
    row(who, "linker_first_round_in_grown_map", 0, kept);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
    // Another description, opened by path, as `go build`'s next step does.
    fd = sc(OPENAT, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    long got = fd >= 0 ? sc(READ, fd, (long)back, sizeof back, 0, 0, 0) : fd;
    int same = got == n2;
    for (long i = 0; same && i < n2; i++) same = back[i] == pattern(i, i < n1 ? 1 : 2);
    row(who, "linker_read_back", got, same);
    if (fd >= 0) sc(CLOSE, fd, 0, 0, 0, 0, 0);
}

static void shared_rows(const char *who, const char *path) {
    long fd = sc(OPENAT, AT_FDCWD, (long)path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = sc(FTRUNCATE, fd, 2 * PG, 0, 0, 0, 0);
    row(who, "shared_setup", fd < 0 ? fd : r, fd >= 0 && r == 0);
    if (fd < 0 || r != 0) return;
    long p = sc(MMAP, 0, 2 * PG, PROT_RW, MAP_SHARED, fd, 0);
    int mapped = !(p < 0 && p > -4096);
    row(who, "shared_mmap", mapped ? 0 : p, mapped);
    if (!mapped) return;
    volatile unsigned char *m = (volatile unsigned char *)p;
    m[0] = 'P'; // the parent touches the first page before the fork
    int go[2], done[2];
    sc(PIPE, (long)go, 0, 0, 0, 0, 0);
    sc(PIPE, (long)done, 0, 0, 0, 0, 0);
    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        char c;
        sc(READ, go[0], (long)&c, 1, 0, 0, 0);
        int saw = m[0] == 'P';
        m[100] = 'c';
        m[PG + 5] = 'C'; // a page nobody touched before
        sc(WRITE, done[1], (long)"x", 1, 0, 0, 0);
        sc(READ, go[0], (long)&c, 1, 0, 0, 0); // stay alive until the parent read
        sc(EXIT, saw ? 0 : 3, 0, 0, 0, 0, 0);
    }
    char c;
    sc(WRITE, go[1], (long)"g", 1, 0, 0, 0);
    sc(READ, done[0], (long)&c, 1, 0, 0, 0);
    row(who, "shared_child_write_in_parent_map", 0, m[100] == 'c' && m[PG + 5] == 'C');
    unsigned char two[2] = {0, 0};
    long a = sc(PREAD64, fd, (long)&two[0], 1, 100, 0, 0);
    long b = sc(PREAD64, fd, (long)&two[1], 1, PG + 5, 0, 0);
    row(who, "shared_child_write_in_pread", a + b, a == 1 && b == 1 && two[0] == 'c' && two[1] == 'C');
    sc(WRITE, go[1], (long)"g", 1, 0, 0, 0);
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);
    row(who, "shared_child_saw_parent_byte", w == pid ? status : w, w == pid && status == 0);
    sc(MUNMAP, p, 2 * PG, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
}

// MAP_SHARED|MAP_POPULATE|MAP_FIXED over a reservation, a write, msync, then a
// read by path through a new description (#1338 v3 condition C1).
static void populate_fixed_rows(const char *who, const char *path) {
    long res = sc(MMAP, 0, 2 * PG, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int reserved = !(res < 0 && res > -4096);
    row(who, "fixed_reserve", reserved ? 0 : res, reserved);
    long fd = sc(OPENAT, AT_FDCWD, (long)path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, 2 * PG, 0, 0, 0, 0) : fd;
    if (!reserved || fd < 0 || r != 0) return;
    long p = sc(MMAP, res, 2 * PG, PROT_RW, MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd, 0);
    row(who, "fixed_populate_mmap", p == res ? 0 : p, p == res);
    if (p != res) {
        sc(CLOSE, fd, 0, 0, 0, 0, 0);
        return;
    }
    for (long i = 0; i < 2 * PG; i++) ((unsigned char *)p)[i] = pattern(i, 3);
    r = sc(MSYNC, p, 2 * PG, MS_SYNC, 0, 0, 0);
    row(who, "fixed_populate_msync", r, r == 0);
    long rd = sc(OPENAT, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    long got = rd >= 0 ? sc(READ, rd, (long)back, 2 * PG, 0, 0, 0) : rd;
    int same = got == 2 * PG;
    for (long i = 0; same && i < 2 * PG; i++) same = back[i] == pattern(i, 3);
    row(who, "fixed_populate_read_back", got, same);
    if (rd >= 0) sc(CLOSE, rd, 0, 0, 0, 0, 0);
    sc(MUNMAP, p, 2 * PG, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
}

// One page of a file mapped twice in one process; unmapping the first must
// leave the second writing the file (#1338 v3 condition C3).
static void double_map_rows(const char *who, const char *path) {
    long fd = sc(OPENAT, AT_FDCWD, (long)path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, PG, 0, 0, 0, 0) : fd;
    if (fd < 0 || r != 0) {
        row(who, "double_map_setup", r, 0);
        return;
    }
    long a = sc(MMAP, 0, PG, PROT_RW, MAP_SHARED, fd, 0);
    long b = sc(MMAP, 0, PG, PROT_RW, MAP_SHARED, fd, 0);
    int mapped = !(a < 0 && a > -4096) && !(b < 0 && b > -4096);
    row(who, "double_map_mmap", mapped ? 0 : (a < 0 && a > -4096 ? a : b), mapped);
    if (!mapped) {
        sc(CLOSE, fd, 0, 0, 0, 0, 0);
        return;
    }
    ((volatile unsigned char *)a)[3] = 'A';
    r = sc(MUNMAP, a, PG, 0, 0, 0, 0);
    row(who, "double_map_munmap_first", r, r == 0);
    ((volatile unsigned char *)b)[7] = 'B';
    unsigned char two[2] = {0, 0};
    long x = sc(PREAD64, fd, (long)&two[0], 1, 3, 0, 0);
    long y = sc(PREAD64, fd, (long)&two[1], 1, 7, 0, 0);
    row(who, "double_map_second_still_writes", x + y, x == 1 && y == 1 && two[0] == 'A' && two[1] == 'B');
    sc(MUNMAP, b, PG, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
}

// A /dev/zero MAP_SHARED map is shared anonymous memory: a forked child sees
// the parent's write and the parent sees the child's (unchanged by #1338).
static void dev_zero_rows(const char *who) {
    long fd = sc(OPENAT, AT_FDCWD, (long)"/dev/zero", O_RDWR | O_CLOEXEC, 0, 0, 0);
    long p = fd >= 0 ? sc(MMAP, 0, PG, PROT_RW, MAP_SHARED, fd, 0) : fd;
    int mapped = !(p < 0 && p > -4096);
    row(who, "dev_zero_mmap", mapped ? 0 : p, mapped);
    if (fd >= 0) sc(CLOSE, fd, 0, 0, 0, 0, 0);
    if (!mapped) return;
    volatile unsigned char *m = (volatile unsigned char *)p;
    m[0] = 'Z';
    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        int saw = m[0] == 'Z';
        m[1] = 'Y';
        sc(EXIT, saw ? 0 : 3, 0, 0, 0, 0, 0);
    }
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);
    row(who, "dev_zero_shared_with_child", w == pid ? status : w, w == pid && status == 0 && m[1] == 'Y');
    sc(MUNMAP, p, PG, 0, 0, 0, 0);
}

static void all_rows(const char *who, const char *link, const char *shared, const char *fixed, const char *dbl) {
    linker_rows(who, link);
    shared_rows(who, shared);
    populate_fixed_rows(who, fixed);
    double_map_rows(who, dbl);
    dev_zero_rows(who);
}

void _start(void) {
    all_rows("root", "link-root.out", "shared-root", "fixed-root", "double-root");
    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        all_rows("child", "link-child.out", "shared-child", "fixed-child", "double-child");
        sc(EXIT, 0, 0, 0, 0, 0, 0);
    }
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);
    sc(EXIT, w == pid && status == 0 ? 7 : 95, 0, 0, 0, 0, 0);
}
