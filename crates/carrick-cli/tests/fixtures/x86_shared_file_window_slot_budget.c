// Exhausting the carrier shared-window slot budget across successive mappings
// (#1338 A1, #2975 P0 3).
//
// Maps, touches, and unmaps successive 2 MiB file chunks while keeping only one
// mapping live at a time. Before WindowSlotBudget moved slot admission and
// installation to mmap time, mmap always succeeded and touching the first chunk
// past the carrier slot limit crashed the run with a TrapError.
//
// After mmap refuses with counted ENOSYS, verifies:
// - an already-installed chunk (chunk 0) still maps and keeps its byte;
// - a fresh file refused at mmap is not pinned in the host shrink registry;
// - the already-windowed file remains fenced against shrink;
// - non-window headroom still serves anonymous faults and fork.
//
// Files are created in the working directory. No libc and no startup code.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
enum {
    WRITE = 1,
    CLOSE = 3,
    MMAP = 9,
    MUNMAP = 11,
    FORK = 57,
    EXIT = 60,
    WAIT4 = 61,
    FTRUNCATE = 77,
    OPENAT = 257
};
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define PROT_RW 3
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define CHUNK (2ULL << 20)
#define BATCH_CHUNKS 4ULL
#define BATCH_BYTES (BATCH_CHUNKS * CHUNK)
#define FILE_SIZE (72ULL << 30)
#define ENOSYS (-38L)

static void row(const char *name, long ret) {
    char out[64];
    int n = 0;
    while (*name)
        out[n++] = *name++;
    out[n++] = '=';
    unsigned long u = (unsigned long)ret;
    for (int i = 60; i >= 0; i -= 4)
        out[n++] = "0123456789abcdef"[(u >> i) & 15];
    out[n++] = '\n';
    sc(WRITE, 1, (long)out, n, 0, 0, 0);
}

static int is_err(long p) {
    return p < 0 && p > -4096;
}

void _start(void) {
    long fd = sc(OPENAT, AT_FDCWD, (long)"window-budget",
                 O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long r = fd >= 0 ? sc(FTRUNCATE, fd, FILE_SIZE, 0, 0, 0, 0) : fd;
    if (r != 0) {
        row("setup_ftruncate", r);
        sc(EXIT, 90, 0, 0, 0, 0, 0);
    }
    long p0 = sc(MMAP, 0, CHUNK, PROT_RW, MAP_SHARED, fd, 0);
    if (is_err(p0)) {
        row("setup_chunk0", p0);
        sc(EXIT, 90, 0, 0, 0, 0, 0);
    }
    volatile unsigned char *b0 = (volatile unsigned char *)p0;
    b0[0] = 0x42;
    sc(MUNMAP, p0, CHUNK, 0, 0, 0, 0);

    unsigned long off = CHUNK;
    unsigned long total_chunks = 1;
    long coarse_err = 0;
    while (off + BATCH_BYTES <= FILE_SIZE) {
        long p = sc(MMAP, 0, BATCH_BYTES, PROT_RW, MAP_SHARED, fd, (long)off);
        if (is_err(p)) {
            coarse_err = p;
            break;
        }
        volatile unsigned char *bytes = (volatile unsigned char *)p;
        for (unsigned long i = 0; i < BATCH_CHUNKS; i++) {
            bytes[i * CHUNK] = (unsigned char)(0x10 + (i & 0x3f));
        }
        sc(MUNMAP, p, BATCH_BYTES, 0, 0, 0, 0);
        off += BATCH_BYTES;
        total_chunks += BATCH_CHUNKS;
    }
    if (coarse_err != ENOSYS) {
        row("coarse_err", coarse_err);
        sc(EXIT, 91, 0, 0, 0, 0, 0);
    }

    long fine_err = 0;
    while (off + CHUNK <= FILE_SIZE) {
        long p = sc(MMAP, 0, CHUNK, PROT_RW, MAP_SHARED, fd, (long)off);
        if (is_err(p)) {
            fine_err = p;
            break;
        }
        volatile unsigned char *bytes = (volatile unsigned char *)p;
        bytes[0] = 0x77;
        sc(MUNMAP, p, CHUNK, 0, 0, 0, 0);
        off += CHUNK;
        total_chunks += 1;
    }

    long reuse = sc(MMAP, 0, CHUNK, PROT_RW, MAP_SHARED, fd, 0);
    long chunk0_val = -1;
    if (!is_err(reuse)) {
        volatile unsigned char *rbytes = (volatile unsigned char *)reuse;
        chunk0_val = rbytes[0];
        sc(MUNMAP, reuse, CHUNK, 0, 0, 0, 0);
    }

    long other_fd = sc(OPENAT, AT_FDCWD, (long)"window-budget-other",
                       O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644, 0, 0);
    long other_mmap = -1;
    long other_truncate = -1;
    if (other_fd >= 0 && sc(FTRUNCATE, other_fd, 4096, 0, 0, 0, 0) == 0) {
        other_mmap = sc(MMAP, 0, CHUNK, PROT_RW, MAP_SHARED, other_fd, 0);
        if (!is_err(other_mmap)) {
            sc(MUNMAP, other_mmap, CHUNK, 0, 0, 0, 0);
            other_mmap = 0;
        }
        other_truncate = sc(FTRUNCATE, other_fd, 0, 0, 0, 0, 0);
    }

    long window_shrink = sc(FTRUNCATE, fd, 0, 0, 0, 0, 0);

    long anon = sc(MMAP, 0, 4096, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    long anon_val = -1;
    if (!is_err(anon)) {
        volatile unsigned char *ap = (volatile unsigned char *)anon;
        ap[0] = 0x55;
        anon_val = ap[0];
        sc(MUNMAP, anon, 4096, 0, 0, 0, 0);
    }

    long pid = sc(FORK, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        long cp = sc(MMAP, 0, 4096, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (is_err(cp))
            sc(EXIT, 93, 0, 0, 0, 0, 0);
        volatile unsigned char *cap = (volatile unsigned char *)cp;
        cap[0] = 0x66;
        long got = cap[0];
        sc(MUNMAP, cp, 4096, 0, 0, 0, 0);
        sc(EXIT, got == 0x66 ? 0 : 94, 0, 0, 0, 0, 0);
    }
    int status = -1;
    long w = sc(WAIT4, pid, (long)&status, 0, 0, 0, 0);

    row("chunks_gt_zero", total_chunks > 1 ? 1 : 0);
    row("coarse_err", coarse_err);
    row("fine_err", fine_err);
    row("chunk0_reuse", chunk0_val);
    row("other_mmap", other_mmap);
    row("other_truncate", other_truncate);
    row("window_shrink", window_shrink);
    row("anon_after", anon_val);
    row("child_status", w == pid ? status : 95);

    if (other_fd >= 0)
        sc(CLOSE, other_fd, 0, 0, 0, 0, 0);
    sc(CLOSE, fd, 0, 0, 0, 0, 0);
    sc(EXIT, 7, 0, 0, 0, 0, 0);
}
