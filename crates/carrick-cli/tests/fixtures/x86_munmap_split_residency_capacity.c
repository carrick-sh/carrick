// A munmap that splits a residency row keeps both remaining parts (#2813).
// A process touches PAGES pages of one anonymous private mapping and forks.
// While the child waits, the parent unmaps every STRIDE-th page: each hole
// splits the residency row that covered it in two, so the row count grows
// until the table's probe chains are full. A part that finds no slot must
// not be dropped: the parent then writes every page it still maps (each
// write is a copy-on-write that needs the page's row), and the child writes
// all of its pages. Both read back their own bytes and the bytes written
// before the fork. Exit 7 and `split ok`. No libc: built -nostdlib -static.
static long sc(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}
#ifndef PAGES
#define PAGES 8192L
#endif
#ifndef STRIDE
#define STRIDE 2L
#endif
static unsigned char *arena;
static int write_and_check(unsigned char tag, long stride) {
    for (long page = 0; page < PAGES; page++) {
        if (page % stride == stride - 1) continue;
        arena[page * 4096 + 1] = tag;
    }
    for (long page = 0; page < PAGES; page++) {
        if (page % stride == stride - 1) continue;
        if (arena[page * 4096] != (unsigned char)(page + 3) || arena[page * 4096 + 1] != tag) return 1;
    }
    return 0;
}
void start_c(void) {
    // mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    register long r8 __asm__("r8") = -1, r9 __asm__("r9") = 0, r10 __asm__("r10") = 0x22;
    long mapped;
    __asm__ volatile("syscall" : "=a"(mapped) : "a"(9L), "D"(0L), "S"(PAGES * 4096), "d"(3L), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    if (mapped < 0) sc(231, 89, 0, 0, 0);
    arena = (unsigned char *)mapped;
    for (long page = 0; page < PAGES; page++) arena[page * 4096] = (unsigned char)(page + 3);
    int gate[2];
    if (sc(293, (long)gate, 0, 0, 0) != 0) sc(231, 87, 0, 0, 0);
    long pid = sc(57, 0, 0, 0, 0);
    if (pid < 0) sc(231, 90, 0, 0, 0);
    if (pid == 0) {
        char go;
        sc(3, gate[1], 0, 0, 0);
        // The parent closes its end once every hole is unmapped.
        sc(0, gate[0], (long)&go, 1, 0);
        sc(231, write_and_check('c', PAGES + 1), 0, 0, 0);
    }
    sc(3, gate[0], 0, 0, 0);
    for (long page = STRIDE - 1; page < PAGES; page += STRIDE) {
        if (sc(11, (long)arena + page * 4096, 4096, 0, 0) != 0) sc(231, 88, 0, 0, 0);
    }
    int parent = write_and_check('p', STRIDE);
    sc(3, gate[1], 0, 0, 0);
    int status = -1;
    int good = sc(61, pid, (long)&status, 0, 0) == pid && status == 0 && parent == 0;
    if (good) sc(1, 1, (long)"split ok\n", 9, 0);
    sc(231, good ? 7 : 1, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
