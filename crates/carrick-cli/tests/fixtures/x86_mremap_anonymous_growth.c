// mremap of private anonymous rows, served as Linux serves it (#3152).
// The root, then a forked child (whose parent stays live and checks its own
// rows afterwards), each run three shapes:
//   1. grow in place: a written one-page row grows to three pages at the
//      same address, keeps its byte, and the new pages read 0 and take a
//      store;
//   2. shrink: the three-page row shrinks back to one page at the same
//      address and keeps its byte;
//   3. grow by move: an untouched one-page row with a blocker right after
//      it grows to two pages with MREMAP_MAYMOVE at a new address, reads 0
//      and takes a store, and its old address is vacant again (14 / 24).
// The child first shrinks the moved row it inherited (25). After the child
// exits, the parent rechecks its own kept and moved rows, the moved row
// still two pages (33).
// Exit 7 and `mremap ok`. A failed shape exits 10 + shape in the root and
// 20 + shape in the child, after writing the errno (or the bad value) as
// decimal. No libc: built -nostdlib -static.
static long sc(long n, long a, long b, long c, long d, long e) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = 0;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
#define PAGE 4096L
#define MMAP 9L
#define MUNMAP 11L
#define MREMAP 25L
#define WRITE 1L
#define EXIT_GROUP 231L
#define MAYMOVE 1L
#define PRIVATE_ANON 0x22L
#define FIXED_NOREPLACE 0x100000L

static void put_decimal(long value) {
    char buf[24];
    int at = 23;
    int negative = value < 0;
    unsigned long v = negative ? (unsigned long)(-value) : (unsigned long)value;
    buf[at--] = '\n';
    do {
        buf[at--] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    if (negative) buf[at--] = '-';
    sc(WRITE, 1, (long)&buf[at + 1], 23 - at, 0, 0);
}

static void fail(long code, long value) {
    put_decimal(value);
    sc(EXIT_GROUP, code, 0, 0, 0, 0);
}

static long map_anon(long hint, long len, long flags) {
    long addr = sc(MMAP, hint, len, 3, PRIVATE_ANON | flags, -1);
    if (addr < 0 && addr > -4096) fail(9, addr);
    return addr;
}

// The last shapes' rows, which the parent rechecks after its child exits.
static long kept_row;
static long kept_moved;

// Exits through `fail` on the first shape that differs from Linux.
static void shapes(long base) {
    // 1. Grow in place. Reserve three pages so the two above the row are
    // free, then give them back.
    long row = map_anon(0, 3 * PAGE, 0);
    if (sc(MUNMAP, row + PAGE, 2 * PAGE, 0, 0, 0) != 0) fail(9, 0);
    volatile unsigned char *p = (volatile unsigned char *)row;
    p[17] = 0x5a;
    long grown = sc(MREMAP, row, PAGE, 3 * PAGE, 0, 0);
    if (grown != row) fail(base + 1, grown);
    if (p[17] != 0x5a) fail(base + 1, p[17]);
    if (p[PAGE] != 0 || p[2 * PAGE + 4095] != 0) fail(base + 1, -1000);
    p[2 * PAGE + 9] = 0x33;
    if (p[2 * PAGE + 9] != 0x33) fail(base + 1, -1001);

    // 2. Shrink back to one page.
    long shrunk = sc(MREMAP, row, 3 * PAGE, PAGE, 0, 0);
    if (shrunk != row) fail(base + 2, shrunk);
    if (p[17] != 0x5a) fail(base + 2, p[17]);
    // The released tail is free again: a fixed no-replace map lands there.
    long tail = map_anon(row + PAGE, PAGE, FIXED_NOREPLACE);
    if (tail != row + PAGE) fail(base + 2, tail);

    // 3. Grow by move: a blocker right after an untouched row.
    long fresh = map_anon(0, 2 * PAGE, 0);
    if (sc(MUNMAP, fresh + PAGE, PAGE, 0, 0, 0) != 0) fail(9, 0);
    long blocker = map_anon(fresh + PAGE, PAGE, FIXED_NOREPLACE);
    if (blocker != fresh + PAGE) fail(9, blocker);
    long to = sc(MREMAP, fresh, PAGE, 2 * PAGE, MAYMOVE, 0);
    if (to < 0 && to > -4096) fail(base + 3, to);
    if (to == fresh) fail(base + 3, -1002);
    volatile unsigned char *q = (volatile unsigned char *)to;
    if (q[0] != 0 || q[PAGE + 4095] != 0) fail(base + 3, -1003);
    q[PAGE + 1] = 0x44;
    if (q[PAGE + 1] != 0x44) fail(base + 3, -1004);
    // The move retired the source: its old address is vacant again.
    long vacant = sc(MMAP, fresh, PAGE, 3, PRIVATE_ANON | FIXED_NOREPLACE, -1);
    if (vacant != fresh) fail(base + 4, vacant);
    kept_row = row;
    kept_moved = to;
}

void start_c(void) {
    shapes(10);
    long pid = sc(57, 0, 0, 0, 0, 0);
    if (pid < 0) fail(30, pid);
    if (pid == 0) {
        // The child shrinks the moved row it inherited (a resident page in
        // its copy); the parent's row must keep both pages (33).
        long inherited = kept_moved;
        if (sc(MREMAP, inherited, 2 * PAGE, PAGE, 0, 0) != inherited) fail(25, 0);
        shapes(20);
        sc(EXIT_GROUP, 0, 0, 0, 0, 0);
    }
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0) != pid) fail(31, 0);
    if (status != 0) fail(32, status);
    // The child's edits left the parent's own rows as the parent made them.
    if (((volatile unsigned char *)kept_row)[17] != 0x5a) fail(33, -1);
    if (((volatile unsigned char *)kept_moved)[PAGE + 1] != 0x44) fail(33, -2);
    if (sc(MMAP, kept_moved + PAGE, PAGE, 3, PRIVATE_ANON | FIXED_NOREPLACE, -1) != -17)
        fail(33, -3);
    sc(WRITE, 1, (long)"mremap ok\n", 10, 0, 0);
    sc(EXIT_GROUP, 7, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
