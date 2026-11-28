// mremap(MREMAP_MAYMOVE) of a populated private anonymous row, served as
// Linux serves it (#2611): the written pages keep their bytes at the new
// address, the growth reads 0 and takes a store, and the old address is
// vacant again. The root, then a forked child beside its live parent, each
// run the shape on a row of their own (11-15 / 21-25). The child also moves
// a populated row it inherited, whose pages it still shares with its parent
// (26-27): after the child exits, the parent's own copy keeps its address
// and bytes (33), and the parent's moved row keeps the bytes it wrote (34).
// Exit 7 and `populated move ok`. A failed shape writes the errno (or the
// bad value) as decimal and exits with its code. No libc: built -nostdlib
// -static.
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
#define EEXIST 17L

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

// A two-page row with a one-page blocker right after it, so growth in
// place is impossible and MREMAP_MAYMOVE must move.
static long blocked_row(void) {
    long row = map_anon(0, 3 * PAGE, 0);
    if (sc(MUNMAP, row + 2 * PAGE, PAGE, 0, 0, 0) != 0) fail(9, 0);
    long blocker = map_anon(row + 2 * PAGE, PAGE, FIXED_NOREPLACE);
    if (blocker != row + 2 * PAGE) fail(9, blocker);
    return row;
}

// Grows the populated two-page `row` to four pages with MREMAP_MAYMOVE and
// checks it as Linux leaves it: a new address, both written bytes kept,
// the growth 0 and writable, the old address vacant and the blocker kept.
// Returns the new address.
static long move_populated(long code, long row, unsigned char first,
                           unsigned char second) {
    long to = sc(MREMAP, row, 2 * PAGE, 4 * PAGE, MAYMOVE, 0);
    if (to < 0 && to > -4096) fail(code, to);
    if (to == row) fail(code, -1000);
    volatile unsigned char *q = (volatile unsigned char *)to;
    if (q[17] != first) fail(code + 1, q[17]);
    if (q[PAGE + 9] != second) fail(code + 1, q[PAGE + 9]);
    if (q[2 * PAGE] != 0 || q[4 * PAGE - 1] != 0) fail(code + 2, -1001);
    q[3 * PAGE + 1] = 0x44;
    if (q[3 * PAGE + 1] != 0x44) fail(code + 2, -1002);
    // The move retired the source: both old pages are vacant again.
    long vacant = sc(MMAP, row, 2 * PAGE, 3, PRIVATE_ANON | FIXED_NOREPLACE, -1);
    if (vacant != row) fail(code + 3, vacant);
    if (sc(MUNMAP, row, 2 * PAGE, 0, 0, 0) != 0) fail(9, 0);
    // The blocker is untouched.
    long blocked = sc(MMAP, row + 2 * PAGE, PAGE, 3, PRIVATE_ANON | FIXED_NOREPLACE, -1);
    if (blocked != -EEXIST) fail(code + 4, blocked);
    return to;
}

// The parent's moved row, which it rechecks after its child exits.
static long kept_moved;

// One populated move on a row the caller makes and fills itself.
static long own_row_moves(long code) {
    long row = blocked_row();
    volatile unsigned char *p = (volatile unsigned char *)row;
    p[17] = 0x5a;
    p[PAGE + 9] = 0xa5;
    long to = move_populated(code, row, 0x5a, 0xa5);
    // The moved pages still take stores.
    ((volatile unsigned char *)to)[17] = 0x77;
    if (((volatile unsigned char *)to)[17] != 0x77) fail(code, -1003);
    return to;
}

void start_c(void) {
    kept_moved = own_row_moves(11);
    // A populated row the child inherits and moves; the parent keeps it.
    long shared = blocked_row();
    volatile unsigned char *s = (volatile unsigned char *)shared;
    s[17] = 0x11;
    s[PAGE + 9] = 0x22;
    long pid = sc(57, 0, 0, 0, 0, 0);
    if (pid < 0) fail(30, pid);
    if (pid == 0) {
        own_row_moves(21);
        // The inherited row's pages are still shared with the parent.
        long to = move_populated(26, shared, 0x11, 0x22);
        // A store to a moved shared page is the child's own.
        ((volatile unsigned char *)to)[17] = 0x99;
        if (((volatile unsigned char *)to)[17] != 0x99) fail(26, -1004);
        sc(EXIT_GROUP, 0, 0, 0, 0, 0);
    }
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0) != pid) fail(31, 0);
    if (status != 0) fail(32, status);
    // The child's move left the parent's row at its address with its bytes.
    if (s[17] != 0x11) fail(33, s[17]);
    if (s[PAGE + 9] != 0x22) fail(33, s[PAGE + 9]);
    if (sc(MMAP, shared, PAGE, 3, PRIVATE_ANON | FIXED_NOREPLACE, -1) != -EEXIST)
        fail(33, -1);
    volatile unsigned char *k = (volatile unsigned char *)kept_moved;
    if (k[17] != 0x77 || k[PAGE + 9] != 0xa5 || k[3 * PAGE + 1] != 0x44)
        fail(34, k[17]);
    sc(WRITE, 1, (long)"populated move ok\n", 18, 0, 0);
    sc(EXIT_GROUP, 7, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
