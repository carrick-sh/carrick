// Parent and child both write every page they share after a fork (#2813).
// Each resolved copy-on-write replaces the page's residency row, and 2048
// shared pages of an anonymous private mapping fill the residency table's
// probe chains: a replacement row that finds no slot must not be dropped.
// Each side then reads back its own bytes and the bytes written before the
// fork. Exit 7 and `rounds=1 ok`: every page held in both processes. No
// libc: built -nostdlib -static.
static long sc(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}
#define PAGES 2048L
#define ROUNDS 1
static unsigned char *arena;
static int write_and_check(unsigned char tag) {
    for (long page = 0; page < PAGES; page++) arena[page * 4096 + 1] = tag;
    for (long page = 0; page < PAGES; page++) {
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
    int good = 0;
    for (int round = 0; round < ROUNDS; round++) {
        long pid = sc(57, 0, 0, 0, 0);
        if (pid < 0) sc(231, 90, 0, 0, 0);
        if (pid == 0) sc(231, write_and_check('c' + round), 0, 0, 0);
        int parent = write_and_check('p' + round);
        int status = -1;
        if (sc(61, pid, (long)&status, 0, 0) == pid && status == 0 && parent == 0) good++;
    }
    char out[] = "rounds=0 ok\n";
    out[7] = '0' + good;
    sc(1, 1, (long)out, sizeof out - 1, 0);
    sc(231, good == ROUNDS ? 7 : 1, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
