// Signal handlers on never-touched alternate stacks, in two live threads.
//
// This is the shape of the Go runtime's preemption: every thread registers
// its own alternate signal stack, mapped and never touched, and a SA_ONSTACK
// SIGURG handler; another thread sends SIGURG at it with tgkill. Linux makes
// each stack page resident as it writes the signal frame (a demand-zero
// page, like any user write), and runs the handler on that stack.
//
// Two clone threads each map 64 KiB, register it with sigaltstack without
// touching it, report ready, and yield in a loop. The root sends SIGURG to
// each thread in turn ROUNDS times, then stops them and waits for both.
// The handler records that it ran and that its stack pointer lies inside
// its own thread's alternate stack.
//
// Exit status names the first step that differs from Linux:
//   90 rt_sigaction failed   91 mmap of a thread stack failed
//   92 clone failed          93 the threads did not start
//   94 the threads did not stop
//   95 a handler ran outside its thread's alternate stack, a thread's
//      own mmap or sigaltstack failed, or a syscall a handler interrupted
//      returned the wrong result
//   96 a thread's handler never ran
//   7  every step matched Linux
// A thread whose signal frame is refused is killed by SIGSEGV instead.
//
// No libc: the threads are raw `clone` calls on mapped stacks.
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
void restorer(void);
__asm__(".globl restorer\nrestorer:\n mov $15,%eax\n syscall\n hlt\n");

#define THREADS 2
#define ROUNDS 4000
#define ALT (64 * 1024)
#define SIGURG 23
#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
static volatile int stop;
static volatile int started;
static volatile int done;
static volatile int bad;
static volatile int tids[THREADS];
static volatile int hits[THREADS];
static volatile long alt_lo[THREADS];

struct kernel_sigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    unsigned long mask;
};

static int self_index(void) {
    int tid = (int)sc(186, 0, 0, 0, 0, 0, 0); // gettid
    for (int i = 0; i < THREADS; i++)
        if (tids[i] == tid) return i;
    return -1;
}

static void handler(int sig, void *info, void *uc) {
    (void)sig;
    (void)info;
    (void)uc;
    char probe;
    int i = self_index();
    if (i < 0) {
        __sync_fetch_and_add(&bad, 1);
        return;
    }
    long sp = (long)&probe;
    if (sp < alt_lo[i] || sp >= alt_lo[i] + ALT) __sync_fetch_and_add(&bad, 1);
    __sync_fetch_and_add(&hits[i], 1);
}

static void worker(void *arg) {
    long i = (long)arg;
    tids[i] = (int)sc(186, 0, 0, 0, 0, 0, 0);
    long alt = sc(9, 0, ALT, 3, 0x22, -1, 0); // mmap, never touched
    if (alt < 0 && alt > -4096) {
        __sync_fetch_and_add(&bad, 1);
        __sync_fetch_and_add(&started, 1);
        return;
    }
    alt_lo[i] = alt;
    long ss[3] = {alt, 0, ALT}; // ss_sp, ss_flags, ss_size
    if (sc(131, (long)ss, 0, 0, 0, 0, 0) != 0) __sync_fetch_and_add(&bad, 1);
    __sync_fetch_and_add(&started, 1);
    // A handler delivered on a syscall return keeps that call's result:
    // gettid answers this thread's id however its frame setup was served.
    while (!stop) {
        if (sc(186, 0, 0, 0, 0, 0, 0) != tids[i]) __sync_fetch_and_add(&bad, 1);
        sc(24, 0, 0, 0, 0, 0, 0); // sched_yield
    }
    __sync_fetch_and_add(&done, 1);
    for (;;) sc(60, 0, 0, 0, 0, 0, 0); // exit this thread only
}

void _start(void) {
    struct kernel_sigaction act = {
        (void *)handler,
        0x08000000 | 0x04000000 | 0x10000000 | 4, // ONSTACK | RESTORER | RESTART | SIGINFO
        (void *)restorer,
        0,
    };
    if (sc(13, SIGURG, (long)&act, 0, 8, 0, 0) != 0) sc(231, 90, 0, 0, 0, 0, 0);
    for (long i = 0; i < THREADS; i++) {
        long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
        if (stack < 0 && stack > -4096) sc(231, 91, 0, 0, 0, 0, 0);
        long *top = (long *)(stack + 65536);
        *--top = (long)worker;
        *--top = i;
        if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 92, 0, 0, 0, 0, 0);
    }
    for (long spin = 0; started < THREADS; spin++) {
        if (spin > 50000000) sc(231, 93, 0, 0, 0, 0, 0);
        sc(24, 0, 0, 0, 0, 0, 0);
    }
    int pid = (int)sc(39, 0, 0, 0, 0, 0, 0); // getpid
    for (int r = 0; r < ROUNDS; r++) {
        sc(234, pid, tids[r % THREADS], SIGURG, 0, 0, 0); // tgkill
        if ((r & 7) == 0) sc(24, 0, 0, 0, 0, 0, 0);
    }
    stop = 1;
    for (long spin = 0; done < THREADS; spin++) {
        if (spin > 50000000) sc(231, 94, 0, 0, 0, 0, 0);
        sc(24, 0, 0, 0, 0, 0, 0);
    }
    if (bad) sc(231, 95, 0, 0, 0, 0, 0);
    for (int i = 0; i < THREADS; i++)
        if (hits[i] == 0) sc(231, 96, 0, 0, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
