// mremap of an old range that is not one mapping, served as Linux serves
// it (#3171, the native oracle on #3165). Linux shrinks before it asks for
// one mapping: a shrink (or a same-size call) needs only a mapping at
// `old_address`, else EFAULT, and retires the tail across whatever mappings
// and holes it spans; growth across mappings is EFAULT. The root runs every
// shape, then a forked child (beside its live parent) runs them again.
// One line per shape:
//   <name> r=<ret - base, or the negative errno> v=<page 0..3: 1 vacant, 0 occupied (EEXIST), E another answer> h=<head byte kept>
// The child's lines follow `child`. Exit 7. No libc: built -nostdlib -static.
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

static char out[4096];
static int at;
static void put(const char *s) { while (*s) out[at++] = *s++; }
static void put_long(long v) {
    char buf[24];
    int i = 0;
    unsigned long u = v < 0 ? (unsigned long)(-v) : (unsigned long)v;
    if (v < 0) out[at++] = '-';
    do { buf[i++] = (char)('0' + u % 10); u /= 10; } while (u);
    while (i) out[at++] = buf[--i];
}

static long base;
static long place(long page, long pages, long prot, long kind) {
    long a = sc(MMAP, base + page * PAGE, pages * PAGE, prot, kind | FIXED_NOREPLACE, -1);
    if (a != base + page * PAGE) { put("setup "); put_long(a); put("\n"); sc(WRITE, 1, (long)out, at, 0, 0); sc(EXIT_GROUP, 9, 0, 0, 0, 0); }
    return a;
}
static void touch(long page) { *(volatile unsigned char *)(base + page * PAGE) = 0x5a; }

static void report(const char *name, long r, int head_page) {
    put(name);
    put(" r=");
    if (r < 0 && r > -4096) put_long(r); else put_long(r - base);
    put(" v=");
    for (long pg = 0; pg < 4; pg++) {
        long a = sc(MMAP, base + pg * PAGE, PAGE, 3, PRIVATE_ANON | FIXED_NOREPLACE, -1);
        if (a == base + pg * PAGE) { out[at++] = '1'; sc(MUNMAP, a, PAGE, 0, 0, 0); }
        else if (a == -17) out[at++] = '0';
        else out[at++] = 'E';
    }
    put(" h=");
    if (head_page < 0) out[at++] = '-';
    else out[at++] = (*(volatile unsigned char *)(base + head_page * PAGE) == 0x5a) ? '1' : '0';
    put("\n");
    sc(MUNMAP, base, 8 * PAGE, 0, 0, 0);
}

static void shapes(void) {
    base = sc(MMAP, 0, 8 * PAGE, 3, PRIVATE_ANON, -1);
    sc(MUNMAP, base, 8 * PAGE, 0, 0, 0);
    long r;

    // Two separately made, same-type, touched rows (Linux may merge them).
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 3, PRIVATE_ANON); touch(0); touch(2);
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("same_type_touched_shrink_1", r, 0);
    // Same, untouched.
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 3, PRIVATE_ANON);
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("same_type_untouched_shrink_1", r, -1);
    // Different protections: RW then R.
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 1, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("rw_then_r_shrink_1", r, 0);
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 1, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, 2 * PAGE, 0, 0); report("rw_then_r_shrink_2", r, 0);
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 1, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, 3 * PAGE, 0, 0); report("rw_then_r_shrink_3", r, 0);
    // A hole in the retired tail: [row 2][hole 1][row 1].
    place(0, 2, 3, PRIVATE_ANON); place(3, 1, 3, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("hole_in_tail_shrink_1", r, 0);
    // A hole in the kept part: [row 1][hole 1][row 2], shrink to 3.
    place(0, 1, 3, PRIVATE_ANON); place(2, 2, 3, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, 3 * PAGE, 0, 0); report("hole_in_kept_shrink_3", r, 0);
    // old_address itself unmapped: [hole 1][row 3].
    place(1, 3, 3, PRIVATE_ANON);
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("hole_at_start_shrink_1", r, -1);
    // Nothing mapped at all.
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("all_hole_shrink_1", r, -1);
    // Same size across two types.
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 1, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, 4 * PAGE, 0, 0); report("rw_then_r_same_size", r, 0);
    // Growth across two types (context: not a shrink).
    place(0, 2, 3, PRIVATE_ANON); place(2, 2, 1, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, 5 * PAGE, MAYMOVE, 0); report("rw_then_r_grow_5", r, 0);
    // A single row, shrink (control).
    place(0, 4, 3, PRIVATE_ANON); touch(0);
    r = sc(MREMAP, base, 4 * PAGE, PAGE, 0, 0); report("one_row_shrink_1", r, 0);

}

void start_c(void) {
    shapes();
    long pid = sc(57, 0, 0, 0, 0, 0);
    if (pid < 0) { put("fork "); put_long(pid); put("\n"); sc(WRITE, 1, (long)out, at, 0, 0); sc(EXIT_GROUP, 9, 0, 0, 0, 0); }
    if (pid == 0) {
        at = 0;
        put("child\n");
        shapes();
        sc(WRITE, 1, (long)out, at, 0, 0);
        sc(EXIT_GROUP, 0, 0, 0, 0, 0);
    }
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0) != pid || status != 0) {
        put("child status "); put_long(status); put("\n");
        sc(WRITE, 1, (long)out, at, 0, 0);
        sc(EXIT_GROUP, 8, 0, 0, 0, 0);
    }
    sc(WRITE, 1, (long)out, at, 0, 0);
    sc(EXIT_GROUP, 7, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
