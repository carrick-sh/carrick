// A user exception that is not a page fault belongs to the task that raised
// it (#1514). Fork children execute `ud2`, divide by zero and `int3` beside
// three siblings that take fresh page faults; each must die of its own
// signal (SIGILL, SIGFPE, SIGTRAP) and leave the others running. One more
// child handles SIGILL: its handler reads si_code, steps over the `ud2`
// and the child exits 40 + si_code. The parent reaps everyone and prints one
// line. Exit 7: every row matched. No libc: built -nostdlib -static.
static long sc(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}
#define TOUCHERS 3
#define EACH 4
#define ARENA (4L << 20)
static char arena[ARENA] __attribute__((aligned(4096)));
static void toucher(void) {
    for (long at = 0; at < ARENA; at += 4096) arena[at] = 1;
    sc(231, 0, 0, 0, 0);
}
static void raise_kind(int kind) {
    if (kind == 0) __asm__ volatile("ud2");
    if (kind == 1) __asm__ volatile("xor %%edx,%%edx\n xor %%ecx,%%ecx\n div %%ecx" : : : "rax", "rcx", "rdx");
    if (kind == 2) __asm__ volatile("int3");
}
struct kernel_sigaction {
    void (*handler)(int, void *, void *);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};
void restorer(void);
__asm__(".globl restorer\nrestorer:\n mov $15,%eax\n syscall\n");
static volatile int seen_code = -1;
static void on_ill(int sig, void *info, void *context) {
    (void)sig;
    seen_code = ((int *)info)[2];
    // uc_mcontext.gregs[REG_RIP]: step over the two-byte `ud2`.
    ((unsigned long *)context)[21] += 2;
}
static long spawn(void) {
    long pid = sc(57, 0, 0, 0, 0);
    if (pid < 0) sc(231, 90, 0, 0, 0);
    return pid;
}
static void two(char *at, int value) {
    at[0] = '0' + value / 10;
    at[1] = '0' + value % 10;
}
void start_c(void) {
    static const int signal_of[3] = {4, 8, 5};
    long touchers[TOUCHERS], raisers[3][EACH];
    for (int i = 0; i < TOUCHERS; i++) {
        long pid = spawn();
        if (pid == 0) toucher();
        touchers[i] = pid;
    }
    for (int i = 0; i < EACH; i++) {
        for (int kind = 0; kind < 3; kind++) {
            long pid = spawn();
            if (pid == 0) {
                raise_kind(kind);
                sc(231, 3, 0, 0, 0);
            }
            raisers[kind][i] = pid;
        }
    }
    long handler = spawn();
    if (handler == 0) {
        struct kernel_sigaction action = {on_ill, 0x04000004UL, restorer, 0};
        if (sc(13, 4, (long)&action, 0, 8) != 0) sc(231, 92, 0, 0, 0);
        raise_kind(0);
        sc(231, 40 + seen_code, 0, 0, 0);
    }
    int died[3] = {0, 0, 0}, clean = 0, handled = -1;
    for (int kind = 0; kind < 3; kind++) {
        for (int i = 0; i < EACH; i++) {
            int status = 0;
            if (sc(61, raisers[kind][i], (long)&status, 0, 0) == raisers[kind][i] &&
                (status & 0x7f) == signal_of[kind])
                died[kind]++;
        }
    }
    int status = -1;
    if (sc(61, handler, (long)&status, 0, 0) == handler && (status & 0x7f) == 0) handled = (status >> 8) & 0xff;
    for (int i = 0; i < TOUCHERS; i++) {
        status = -1;
        if (sc(61, touchers[i], (long)&status, 0, 0) == touchers[i] && status == 0) clean++;
    }
    char out[] = "ill=00 fpe=00 trap=00 handled=00 clean=0\n";
    two(out + 4, died[0]);
    two(out + 11, died[1]);
    two(out + 19, died[2]);
    two(out + 30, handled < 0 ? 0 : handled);
    out[39] = '0' + clean;
    sc(1, 1, (long)out, sizeof out - 1, 0);
    int ok = died[0] == EACH && died[1] == EACH && died[2] == EACH && handled == 42 && clean == TOUCHERS;
    sc(231, ok ? 7 : 1, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
