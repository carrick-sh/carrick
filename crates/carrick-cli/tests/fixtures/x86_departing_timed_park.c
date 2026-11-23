// A thread's timed park whose vCPU leaves the guest (#2876 R1 step 0).
//
// In a fork child (and then in the root), thread A sleeps 200 ms with
// `nanosleep`, while thread B keeps making host crossings (`openat` of "/"
// and `close`) until A wakes. A crossing makes the executor leave the
// guest, and the slot's foreign deadlines move to the carrier's server.
// Linux wakes A after 200 ms. The process prints `c ok` / `r ok`, or the
// elapsed milliseconds if A woke early or late (over 1.5 s); a process
// whose A does not wake within 5 s prints `timeout` and exits 98.
// The root exits 7. No libc: raw syscalls on mapped stacks.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
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
#define CLONE_THREAD_FLAGS 0x50f00
static volatile int woke;
static volatile long slept_ms;
static volatile long crossings;

static long now_ns(void) {
    long ts[2] = {0, 0};
    sc(228, 1, (long)ts, 0, 0, 0, 0);
    return ts[0] * 1000000000L + ts[1];
}

static void sleeper(void *unused) {
    (void)unused;
    long start = now_ns();
    long req[2] = {0, 200000000};
    sc(35, (long)req, 0, 0, 0, 0, 0);
    slept_ms = (now_ns() - start) / 1000000;
    woke = 1;
    for (;;) sc(35, (long)req, 0, 0, 0, 0, 0);
}

static void crosser(void *unused) {
    (void)unused;
    while (!woke) {
        long fd = sc(257, -100, (long)"/", 0, 0, 0, 0); // openat(AT_FDCWD, "/", O_RDONLY)
        if (fd >= 0) sc(3, fd, 0, 0, 0, 0, 0);
        crossings++;
        sc(24, 0, 0, 0, 0, 0, 0);
    }
    long pause[2] = {1, 0};
    for (;;) sc(35, (long)pause, 0, 0, 0, 0, 0);
}

static void spawn(void (*entry)(void *)) {
    long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
    if (stack < 0 && stack > -4096) sc(231, 96, 0, 0, 0, 0, 0);
    long *top = (long *)(stack + 65536) - 2;
    top[0] = 0;
    top[1] = (long)entry;
    if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 96, 0, 0, 0, 0, 0);
}

static void put_num(char **at, long value) {
    char digits[24];
    int n = 0;
    do {
        digits[n++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (n) *(*at)++ = digits[--n];
}

static void run(char who) {
    spawn(crosser);
    spawn(sleeper);
    long deadline = now_ns() + 5000000000L;
    long pause[2] = {0, 1000000};
    while (!woke) {
        if (now_ns() > deadline) {
            char line[] = "? timeout\n";
            line[0] = who;
            sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
            sc(231, 98, 0, 0, 0, 0, 0);
        }
        sc(35, (long)pause, 0, 0, 0, 0, 0);
    }
    char line[64];
    char *at = line;
    *at++ = who;
    *at++ = ' ';
    if (slept_ms >= 200 && slept_ms < 1500 && crossings > 0) {
        *at++ = 'o';
        *at++ = 'k';
    } else {
        put_num(&at, slept_ms);
        *at++ = ' ';
        put_num(&at, crossings);
    }
    *at++ = '\n';
    sc(1, 1, (long)line, at - line, 0, 0, 0);
}

void start_c(long *sp) {
    (void)sp;
    long pid = sc(57, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        run('c');
        sc(231, 0, 0, 0, 0, 0, 0);
    }
    if (pid < 0) sc(231, 95, 0, 0, 0, 0, 0);
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid) sc(231, 94, 0, 0, 0, 0, 0);
    if (status != 0) {
        char line[] = "child status 0x0000\n";
        for (int i = 0; i < 4; i++) line[18 - i] = "0123456789abcdef"[(status >> (4 * i)) & 15];
        sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
    }
    run('r');
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
