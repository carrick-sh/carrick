// The run root and its thread sleep (#2832 record B).
//
// The root's main thread starts one raw `CLONE_VM` thread. Each calls
// `nanosleep` and relative `clock_nanosleep` on CLOCK_REALTIME and
// CLOCK_MONOTONIC for 2 ms, and checks that each returned 0 after at least
// 2 ms of CLOCK_MONOTONIC. On x86 the run root has no host sleep
// continuation, so a decline there is answered ENOSYS (-38) at once. The
// main thread waits for its thread with the same sleep, prints `sleep=ok`
// and exits 7, or prints the first bad call's code and return and exits 95.
//
// No libc: the thread is a raw `clone` call on a mapped stack.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
// rdi: clone flags; rsi: the new stack, holding the argument then the entry.
long thread_spawn(long flags, void *stack);
__asm__(".globl thread_spawn\n"
        "thread_spawn:\n"
        " mov $56,%eax\n"
        " xor %edx,%edx\n"
        " xor %r10d,%r10d\n"
        " xor %r8d,%r8d\n"
        " syscall\n"
        " test %rax,%rax\n"
        " jnz 1f\n"
        " pop %rdi\n"
        " pop %rax\n"
        " call *%rax\n"
        " mov $60,%eax\n"
        " xor %edi,%edi\n"
        " syscall\n"
        "1: ret\n");

#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
#define INTERVAL 2000000L
static volatile int done;
static volatile long bad_code, bad_ret;

static long now(void) {
    long ts[2];
    if (sc(228, 1, (long)ts, 0, 0, 0, 0) != 0) return -1; // clock_gettime(CLOCK_MONOTONIC)
    return ts[0] * 1000000000L + ts[1];
}

// code: 1 nanosleep, 2 clock_nanosleep REALTIME, 3 clock_nanosleep MONOTONIC;
// +10 for the thread; +100 when it returned early.
static void sleep_each(long base) {
    long interval[2] = {0, INTERVAL};
    for (long code = 1; code <= 3; code++) {
        long start = now();
        long ret = code == 1 ? sc(35, (long)interval, 0, 0, 0, 0, 0)
                             : sc(230, code == 2 ? 0 : 1, 0, (long)interval, 0, 0, 0);
        long slept = now() - start;
        if (ret != 0 || slept < INTERVAL) {
            if (!bad_code) {
                bad_code = base + code + (ret == 0 ? 100 : 0);
                bad_ret = ret;
            }
            return;
        }
    }
}

static void member(void *unused) {
    (void)unused;
    sleep_each(10);
    done = 1;
}

static void put_hex(const char *label, long value) {
    char line[32];
    int n = 0;
    while (*label) line[n++] = *label++;
    for (int i = 15; i >= 0; i--) line[n++] = "0123456789abcdef"[(value >> (4 * i)) & 15];
    line[n++] = '\n';
    sc(1, 1, (long)line, n, 0, 0, 0);
}

void start_c(long *sp) {
    (void)sp;
    long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
    if (stack < 0 && stack > -4096) sc(231, 96, 0, 0, 0, 0, 0);
    long *top = (long *)(stack + 65536) - 2;
    top[0] = 0;
    top[1] = (long)member;
    if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 97, 0, 0, 0, 0, 0);
    sleep_each(0);
    long interval[2] = {0, INTERVAL};
    for (int waited = 0; !done && waited < 2500; waited++) {
        if (sc(35, (long)interval, 0, 0, 0, 0, 0) != 0) break;
    }
    if (!done && !bad_code) bad_code = 98;
    if (bad_code) {
        put_hex("bad code=", bad_code);
        put_hex("ret=", bad_ret);
        sc(231, 95, 0, 0, 0, 0, 0);
    }
    sc(1, 1, (long)"sleep=ok\n", 9, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
