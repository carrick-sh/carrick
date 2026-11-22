// A fork child killed by its own page fault must not take the carrier with
// it (#2792). Three siblings take fresh page faults while sixteen more
// children each write to an unmapped address and die of SIGSEGV. The parent
// reaps all nineteen and prints one line. Exit 7: every faulter died of
// SIGSEGV and every toucher exited 0. No libc: built -nostdlib -static.
static long sc(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}
#define TOUCHERS 3
#define FAULTERS 16
#define ARENA (8L << 20)
static char arena[ARENA] __attribute__((aligned(4096)));
static void toucher(void) {
    for (long at = 0; at < ARENA; at += 4096) arena[at] = 1;
    sc(231, 0, 0, 0, 0);
}
void start_c(void) {
    long touchers[TOUCHERS], faulters[FAULTERS];
    for (int i = 0; i < TOUCHERS; i++) {
        long pid = sc(57, 0, 0, 0, 0);
        if (pid < 0) sc(231, 90, 0, 0, 0);
        if (pid == 0) toucher();
        touchers[i] = pid;
    }
    for (int i = 0; i < FAULTERS; i++) {
        long pid = sc(57, 0, 0, 0, 0);
        if (pid < 0) sc(231, 91, 0, 0, 0);
        if (pid == 0) {
            *(volatile int *)8 = 1;
            sc(231, 3, 0, 0, 0);
        }
        faulters[i] = pid;
    }
    int segv = 0, clean = 0;
    for (int i = 0; i < FAULTERS; i++) {
        int status = 0;
        if (sc(61, faulters[i], (long)&status, 0, 0) == faulters[i] && status == 11) segv++;
    }
    for (int i = 0; i < TOUCHERS; i++) {
        int status = -1;
        if (sc(61, touchers[i], (long)&status, 0, 0) == touchers[i] && status == 0) clean++;
    }
    char out[] = "segv=00 clean=0\n";
    out[5] = '0' + segv / 10;
    out[6] = '0' + segv % 10;
    out[14] = '0' + clean;
    sc(1, 1, (long)out, sizeof out - 1, 0);
    sc(231, segv == FAULTERS && clean == TOUCHERS ? 7 : 1, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
