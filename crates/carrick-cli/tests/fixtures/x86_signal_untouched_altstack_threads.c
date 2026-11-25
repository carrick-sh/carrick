// Signal handlers on never-touched alternate stacks, in two live threads.
//
// This is the shape of the Go runtime's preemption: every thread registers
// its own alternate signal stack, mapped and never touched, and a SA_ONSTACK
// SIGURG handler; another thread sends SIGURG at it with tgkill. Linux makes
// each stack page resident as it writes the signal frame (a demand-zero
// page, like any user write), and runs the handler on that stack.
//
// Each clone thread masks SIGURG, maps 64 KiB (never touching it), calls
// sigaltstack, signals ready via a checked futex wake, waits on `go[i]`, and
// then enters rt_sigsuspend(&base_mask). Root queues one checked tgkill(SIGURG)
// while SIGURG is masked, releases `go[i]`, and waits for one handler
// acknowledgement without replacement signals. Round 0 therefore delivers the
// first SIGURG (onto the untouched altstack) deterministically at
// rt_sigsuspend's exit checkpoint, where the worker checks -EINTR, hits==1, and
// the preserved blocked mask across NeedsSupply + sigreturn before unmasking
// for rounds 1..199 over checked gettid / 7-byte self-pipe / sched_yield calls.
//
// Exit status names the first step that differs from Linux:
//   90 rt_sigaction failed   91 mmap of a thread stack failed
//   92 clone failed          93 the threads did not start
//   94 the threads did not stop
//   95 a handler ran outside its thread's alternate stack, received bad
//      arguments or duplicate deliveries, a thread's own syscall/mask check
//      failed, or an interrupted syscall returned wrongly
//   96 a tgkill signal was lost (handler did not acknowledge within bound)
//   97 tgkill failed
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
#define ROUNDS 200
#define ALT (64 * 1024)
#define SIGURG 23
#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define CLOCK_MONOTONIC 1
#define SIG_BLOCK 0
#define SIG_SETMASK 2

struct kernel_timespec {
    long tv_sec;
    long tv_nsec;
};

struct kernel_sigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    unsigned long mask;
};

static volatile int stop;
static volatile int started;
static volatile int done;
static volatile int bad;
static volatile int go[THREADS];
static volatile int tids[THREADS];
static volatile int hits[THREADS];
static volatile long alt_lo[THREADS];

static int self_index(void) {
    int tid = (int)sc(186, 0, 0, 0, 0, 0, 0); // gettid
    for (int i = 0; i < THREADS; i++)
        if (__atomic_load_n(&tids[i], __ATOMIC_ACQUIRE) == tid) return i;
    return -1;
}

static int wait_eq(volatile int *word, int target, long timeout_ms) {
    struct kernel_timespec now, deadline, rem;
    if (sc(228, CLOCK_MONOTONIC, (long)&deadline, 0, 0, 0, 0) != 0) return -1;
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    for (;;) {
        int cur = __atomic_load_n(word, __ATOMIC_ACQUIRE);
        if (cur == target) return 1;
        if (cur > target) return -1;
        if (sc(228, CLOCK_MONOTONIC, (long)&now, 0, 0, 0, 0) != 0) return -1;
        long sec = deadline.tv_sec - now.tv_sec;
        long nsec = deadline.tv_nsec - now.tv_nsec;
        if (nsec < 0) {
            sec -= 1;
            nsec += 1000000000L;
        }
        if (sec < 0 || (sec == 0 && nsec <= 0)) return 0;
        rem.tv_sec = sec;
        rem.tv_nsec = nsec;
        sc(202, (long)word, FUTEX_WAIT, cur, (long)&rem, 0, 0);
    }
}

static void handler(int sig, void *info, void *uc) {
    char probe;
    if (sig != SIGURG || !info || !uc) {
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        return;
    }
    int i = self_index();
    if (i < 0) {
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        return;
    }
    long sp = (long)&probe;
    long lo = __atomic_load_n(&alt_lo[i], __ATOMIC_ACQUIRE);
    if (sp < lo || sp >= lo + ALT) __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&hits[i], 1, __ATOMIC_RELEASE);
    if (sc(202, (long)&hits[i], FUTEX_WAKE, 1, 0, 0, 0) < 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
}

static void worker(void *arg) {
    long i = (long)arg;
    int tid = (int)sc(186, 0, 0, 0, 0, 0, 0);
    if (tid <= 0) __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&tids[i], tid, __ATOMIC_RELEASE);

    int spipe[2] = {-1, -1};
    if (sc(293, (long)spipe, 0, 0, 0, 0, 0) != 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);

    unsigned long urg_mask = 1UL << (SIGURG - 1);
    unsigned long base_mask = 0;
    if (sc(14, SIG_BLOCK, (long)&urg_mask, (long)&base_mask, 8, 0, 0) != 0
        || (base_mask & urg_mask) != 0) {
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    }

    long alt = sc(9, 0, ALT, 3, 0x22, -1, 0); // mmap, never touched
    if (alt < 0 && alt > -4096) {
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&started, 1, __ATOMIC_RELEASE);
        sc(202, (long)&started, FUTEX_WAKE, 1, 0, 0, 0);
        return;
    }
    __atomic_store_n(&alt_lo[i], alt, __ATOMIC_RELEASE);
    long ss[3] = {alt, 0, ALT}; // ss_sp, ss_flags, ss_size
    if (sc(131, (long)ss, 0, 0, 0, 0, 0) != 0) __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);

    __atomic_add_fetch(&started, 1, __ATOMIC_RELEASE);
    if (sc(202, (long)&started, FUTEX_WAKE, 1, 0, 0, 0) < 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);

    if (wait_eq(&go[i], 1, 2000) != 1) {
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        return;
    }
    if (__atomic_load_n(&hits[i], __ATOMIC_ACQUIRE) != 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);

    // Round 0: SIGURG was queued while masked, so rt_sigsuspend(&base_mask)
    // is deterministically the checkpoint that takes the first (untouched-altstack)
    // delivery and must return -EINTR (-4) with SIGURG still blocked in mask.
    long ssrc = sc(130, (long)&base_mask, 8, 0, 0, 0, 0);
    if (ssrc != -4) __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    int after_r0 = __atomic_load_n(&hits[i], __ATOMIC_ACQUIRE);
    if (after_r0 == 0) sc(231, 96, 0, 0, 0, 0, 0); // lost SIGURG at rt_sigsuspend
    if (after_r0 != 1) __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);

    unsigned long cur_mask = 0;
    if (sc(14, SIG_SETMASK, 0, (long)&cur_mask, 8, 0, 0) != 0
        || (cur_mask & urg_mask) == 0) {
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    }
    if (sc(14, SIG_SETMASK, (long)&base_mask, 0, 8, 0, 0) != 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);

    static const char magic[7] = "CARRICK";
    char buf[7];
    while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
        if ((int)sc(186, 0, 0, 0, 0, 0, 0) != tid)
            __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        if (sc(1, spipe[1], (long)magic, 7, 0, 0, 0) != 7)
            __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        if (sc(0, spipe[0], (long)buf, 7, 0, 0, 0) != 7)
            __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        for (int k = 0; k < 7; k++) {
            if (buf[k] != magic[k]) __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        }
        if (sc(24, 0, 0, 0, 0, 0, 0) != 0)
            __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED); // sched_yield
    }
    if (sc(3, spipe[0], 0, 0, 0, 0, 0) != 0 || sc(3, spipe[1], 0, 0, 0, 0, 0) != 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    if (sc(11, alt, ALT, 0, 0, 0, 0) != 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&done, 1, __ATOMIC_RELEASE);
    if (sc(202, (long)&done, FUTEX_WAKE, 1, 0, 0, 0) < 0)
        __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
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
    if (wait_eq(&started, THREADS, 2000) != 1) sc(231, 93, 0, 0, 0, 0, 0);
    int pid = (int)sc(39, 0, 0, 0, 0, 0, 0); // getpid
    // Send one checked tgkill per worker and require one acknowledged handler
    // execution before sending another signal to that worker. Round 0 queues
    // while SIGURG is masked and releases go[i] into rt_sigsuspend so the
    // untouched-altstack frame write happens on a single deterministic checkpoint.
    for (int r = 0; r < ROUNDS; r++) {
        for (int i = 0; i < THREADS; i++) {
            if (__atomic_load_n(&hits[i], __ATOMIC_ACQUIRE) != r) sc(231, 95, 0, 0, 0, 0, 0);
            int tid = __atomic_load_n(&tids[i], __ATOMIC_ACQUIRE);
            if (sc(234, pid, tid, SIGURG, 0, 0, 0) != 0) sc(231, 97, 0, 0, 0, 0, 0);
            if (r == 0) {
                __atomic_store_n(&go[i], 1, __ATOMIC_RELEASE);
                if (sc(202, (long)&go[i], FUTEX_WAKE, 1, 0, 0, 0) < 0)
                    sc(231, 95, 0, 0, 0, 0, 0);
            }
            int w = wait_eq(&hits[i], r + 1, 1500);
            if (w == 0) sc(231, 96, 0, 0, 0, 0, 0);
            if (w < 0) sc(231, 95, 0, 0, 0, 0, 0);
            if (__atomic_load_n(&bad, __ATOMIC_ACQUIRE)) sc(231, 95, 0, 0, 0, 0, 0);
        }
    }
    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    if (wait_eq(&done, THREADS, 2000) != 1) sc(231, 94, 0, 0, 0, 0, 0);
    if (__atomic_load_n(&bad, __ATOMIC_ACQUIRE)) sc(231, 95, 0, 0, 0, 0, 0);
    for (int i = 0; i < THREADS; i++)
        if (__atomic_load_n(&hits[i], __ATOMIC_ACQUIRE) != ROUNDS) sc(231, 96, 0, 0, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
