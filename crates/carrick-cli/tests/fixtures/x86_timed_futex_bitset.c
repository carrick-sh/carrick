// Timed FUTEX_WAIT_BITSET in a run root and in a fork child (#3174).
//
// glibc's pthread_cond_timedwait, sem_timedwait and pthread_mutex_timedlock
// wait with FUTEX_WAIT_BITSET and an ABSOLUTE deadline on CLOCK_MONOTONIC or
// (with FUTEX_CLOCK_REALTIME) CLOCK_REALTIME, and treat an unexpected errno
// such as ENOSYS as fatal (it aborts). Each process here runs every Linux
// answer of that wait, between two live threads, and prints one line:
//
//   mono   a monotonic deadline 50 ms out, word unchanged: ETIMEDOUT (-110),
//          never before the deadline
//   rt     the same on CLOCK_REALTIME
//   past   a deadline already past: ETIMEDOUT at once
//   eagain the word differs from the expected value: EAGAIN (-11)
//   einval tv_nsec of one second: EINVAL (-22)
//   efault an unmapped timespec: EFAULT (-14)
//   zmask  an empty bitset with a valid deadline: EINVAL (-22)
//   zmaskfault an empty bitset with an unmapped timespec: EFAULT (-14),
//          since Linux reads the timeout before it checks the word
//   misalign / misalignfault the same two for a misaligned word, on
//          CLOCK_REALTIME: EINVAL, then EFAULT
//   wake   a second thread wakes the waiter (its wake counts one): 0
//   eintr  a SIGUSR1 handler without SA_RESTART interrupts the wait
//   sarestart a SA_RESTART SIGUSR2 handler interrupts it: still EINTR on
//          Linux (native oracle), since a timed wait is not restarted
//          after a handler runs. The waiter stays alive until the sender
//          has stopped, so no signal can target an exited thread
//   pool   the most timed waiters one wake call found parked at once: 16
//          waiters re-park on every early wake until a single FUTEX_WAKE
//          counts all 16, while the main thread keeps running. All 16 hold
//          a park at the same moment, so a parked timed wait holds no
//          execution slot
//
// A word "early" or "late" in a field means the wait returned before its
// deadline, or long after it. The fork child prints its own line; the run
// root prints after reaping it. Exit 7: both lines printed and the child
// exited 0.
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

#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define FUTEX_WAIT_BITSET_PRIVATE 137
#define FUTEX_CLOCK_REALTIME 256
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define SIGUSR1 10
#define SIGUSR2 12
#define POOL 16
#define MS 1000000L

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

static long now_ns(int clock) {
    struct kernel_timespec ts;
    if (sc(228, clock, (long)&ts, 0, 0, 0, 0) != 0) sc(231, 90, 0, 0, 0, 0, 0);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static struct kernel_timespec at(long ns) {
    struct kernel_timespec ts = {ns / 1000000000L, ns % 1000000000L};
    return ts;
}

static long wait_bitset(volatile int *word, int expected, int clock, const struct kernel_timespec *deadline) {
    long op = FUTEX_WAIT_BITSET_PRIVATE | (clock == CLOCK_REALTIME ? FUTEX_CLOCK_REALTIME : 0);
    return sc(202, (long)word, op, expected, (long)deadline, 0, 0xffffffffL);
}

// Wait, untimed, until *word == target. Order is on the futex word only.
static void wait_eq(volatile int *word, int target) {
    for (;;) {
        int cur = __atomic_load_n(word, __ATOMIC_ACQUIRE);
        if (cur == target) return;
        sc(202, (long)word, FUTEX_WAIT_PRIVATE, cur, 0, 0, 0);
    }
}

static void bump(volatile int *word) {
    __atomic_add_fetch(word, 1, __ATOMIC_RELEASE);
    sc(202, (long)word, FUTEX_WAKE_PRIVATE, 0x7fffffff, 0, 0, 0);
}

static void spawn(void (*entry)(long), long arg) {
    long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
    if (stack < 0 && stack > -4096) sc(231, 91, 0, 0, 0, 0, 0);
    long *top = (long *)(stack + 65536);
    *--top = (long)entry;
    *--top = arg;
    if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 92, 0, 0, 0, 0, 0);
}

// One timed waiter's custody: the word it waits on, its clock, its
// deadline, and its answer.
struct waiter {
    volatile int word;
    volatile int tid;
    volatile int done;
    volatile int release;
    volatile int gone;
    int clock;
    long deadline_ns;
    long result;
    long returned_ns;
};

static void waiter_entry(long arg) {
    struct waiter *w = (struct waiter *)arg;
    __atomic_store_n(&w->tid, (int)sc(186, 0, 0, 0, 0, 0, 0), __ATOMIC_RELEASE);
    struct kernel_timespec deadline = at(w->deadline_ns);
    w->result = wait_bitset(&w->word, 0, w->clock, &deadline);
    w->returned_ns = now_ns(w->clock);
    bump(&w->done);
    // Stay alive until the driver releases this thread: a signal sent after
    // `done` still finds it, never an exited tid (ESRCH).
    wait_eq(&w->release, 1);
    // Its last touch of `w`: the driver may reuse it once this reads 1.
    bump(&w->gone);
}

// Let a waiter thread go, and wait until it no longer touches its custody.
static void finish(struct waiter *w) {
    bump(&w->release);
    wait_eq(&w->gone, 1);
}

static volatile int hits;
static void handler(int sig) {
    (void)sig;
    __atomic_add_fetch(&hits, 1, __ATOMIC_RELAXED);
}

static char *put(char *p, const char *s) {
    while (*s) *p++ = *s++;
    return p;
}

static char *put_long(char *p, long v) {
    char digits[24];
    int n = 0;
    unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;
    if (v < 0) *p++ = '-';
    do {
        digits[n++] = '0' + u % 10;
        u /= 10;
    } while (u);
    while (n) *p++ = digits[--n];
    return p;
}

// The answer of one timed waiter, with "early" when it returned before its
// deadline and "late" when it returned more than `slack_ms` after it.
static char *put_timed(char *p, const char *name, struct waiter *w, long slack_ms) {
    p = put(p, " ");
    p = put(p, name);
    p = put(p, "=");
    p = put_long(p, w->result);
    if (w->result == -110 && w->returned_ns < w->deadline_ns) p = put(p, "early");
    if (w->returned_ns > w->deadline_ns + slack_ms * MS) p = put(p, "late");
    return p;
}

// Run one waiter thread with a deadline `ms` out and wait for its answer.
static void timed(struct waiter *w, int clock, long ms) {
    w->clock = clock;
    w->deadline_ns = now_ns(clock) + ms * MS;
    spawn(waiter_entry, (long)w);
    wait_eq(&w->done, 1);
    finish(w);
}

// Interrupt a waiter with `sig` every 20 ms until it answers. A signal that
// lands before the waiter enters its wait only runs the handler; a later one
// interrupts the wait itself.
static void interrupt(struct waiter *w, int sig) {
    int pid = (int)sc(39, 0, 0, 0, 0, 0, 0);
    while (__atomic_load_n(&w->tid, __ATOMIC_ACQUIRE) == 0) sc(24, 0, 0, 0, 0, 0, 0);
    struct kernel_timespec gap = {0, 20 * MS};
    while (!__atomic_load_n(&w->done, __ATOMIC_ACQUIRE)) {
        if (sc(234, pid, w->tid, sig, 0, 0, 0) != 0) sc(231, 97, 0, 0, 0, 0, 0);
        sc(35, (long)&gap, 0, 0, 0, 0, 0);
    }
    finish(w);
}

// The pool word is 0 while the driver probes and 1 once it releases the
// waiters; `pool_armed` counts every wait a pool thread is about to enter.
static volatile int pool_word;
static volatile int pool_armed;
static volatile int pool_done;
static long pool_errors;

static void pool_entry(long i) {
    (void)i;
    struct kernel_timespec deadline = at(now_ns(CLOCK_MONOTONIC) + 5000 * MS);
    for (;;) {
        __atomic_add_fetch(&pool_armed, 1, __ATOMIC_RELEASE);
        long r = wait_bitset(&pool_word, 0, CLOCK_MONOTONIC, &deadline);
        // Woken (0) or released before entering (EAGAIN): re-park until the
        // driver releases the pool. Anything else is a wrong answer.
        if (r != 0 && r != -11) __atomic_add_fetch(&pool_errors, 1, __ATOMIC_RELAXED);
        if (r != 0 && r != -11) break;
        if (__atomic_load_n(&pool_word, __ATOMIC_ACQUIRE) != 0) break;
    }
    bump(&pool_done);
}

static void run(const char *who) {
    char line[512];
    char *p = put(line, who);
    struct waiter w;

    w = (struct waiter){0};
    timed(&w, CLOCK_MONOTONIC, 50);
    p = put_timed(p, "mono", &w, 2000);

    w = (struct waiter){0};
    timed(&w, CLOCK_REALTIME, 50);
    p = put_timed(p, "rt", &w, 2000);

    // A deadline already past answers at once, after the value check. (Half
    // of "now": a guest's monotonic clock may read under a second, and a
    // negative tv_sec is EINVAL.)
    struct kernel_timespec past = at(now_ns(CLOCK_MONOTONIC) / 2);
    volatile int word = 0;
    p = put(p, " past=");
    p = put_long(p, wait_bitset(&word, 0, CLOCK_MONOTONIC, &past));
    p = put(p, " eagain=");
    struct kernel_timespec later = at(now_ns(CLOCK_MONOTONIC) + 5000 * MS);
    p = put_long(p, wait_bitset(&word, 1, CLOCK_MONOTONIC, &later));
    struct kernel_timespec bad = {0, 1000000000L};
    p = put(p, " einval=");
    p = put_long(p, wait_bitset(&word, 0, CLOCK_MONOTONIC, &bad));
    p = put(p, " efault=");
    p = put_long(p, wait_bitset(&word, 0, CLOCK_MONOTONIC, (const struct kernel_timespec *)16));
    // Linux reads and validates the timespec before the word's operands.
    p = put(p, " zmask=");
    p = put_long(p, sc(202, (long)&word, FUTEX_WAIT_BITSET_PRIVATE, 0, (long)&later, 0, 0));
    p = put(p, " zmaskfault=");
    p = put_long(p, sc(202, (long)&word, FUTEX_WAIT_BITSET_PRIVATE, 0, 16, 0, 0));
    struct kernel_timespec rt_later = at(now_ns(CLOCK_REALTIME) + 5000 * MS);
    long rt_op = FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME;
    p = put(p, " misalign=");
    p = put_long(p, sc(202, (long)&word + 1, rt_op, 0, (long)&rt_later, 0, 0xffffffffL));
    p = put(p, " misalignfault=");
    p = put_long(p, sc(202, (long)&word + 1, rt_op, 0, 16, 0, 0xffffffffL));

    // A wake that counts one has woken this waiter inside its wait.
    w = (struct waiter){0};
    w.clock = CLOCK_MONOTONIC;
    w.deadline_ns = now_ns(CLOCK_MONOTONIC) + 5000 * MS;
    spawn(waiter_entry, (long)&w);
    while (!__atomic_load_n(&w.done, __ATOMIC_ACQUIRE)
           && sc(202, (long)&w.word, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) != 1)
        sc(24, 0, 0, 0, 0, 0, 0);
    wait_eq(&w.done, 1);
    finish(&w);
    p = put(p, " wake=");
    p = put_long(p, w.result);
    if (w.returned_ns >= w.deadline_ns) p = put(p, "late");

    // Without SA_RESTART the signal ends the wait.
    w = (struct waiter){0};
    w.clock = CLOCK_MONOTONIC;
    w.deadline_ns = now_ns(CLOCK_MONOTONIC) + 5000 * MS;
    spawn(waiter_entry, (long)&w);
    interrupt(&w, SIGUSR1);
    p = put(p, " eintr=");
    p = put_long(p, w.result);
    if (w.returned_ns >= w.deadline_ns) p = put(p, "late");

    // With SA_RESTART a handler still ends a timed wait.
    hits = 0;
    w = (struct waiter){0};
    w.clock = CLOCK_MONOTONIC;
    w.deadline_ns = now_ns(CLOCK_MONOTONIC) + 5000 * MS;
    spawn(waiter_entry, (long)&w);
    interrupt(&w, SIGUSR2);
    p = put(p, " sarestart=");
    p = put_long(p, w.result);
    if (w.returned_ns >= w.deadline_ns) p = put(p, "late");
    if (__atomic_load_n(&hits, __ATOMIC_RELAXED) < 1) p = put(p, "unsignalled");

    // The pool: one FUTEX_WAKE must count all 16 timed waiters parked at
    // once, while this thread keeps running. Each probe waits until every
    // woken waiter has armed its next wait; a waiter between arming and
    // parking only lowers that probe's count, and it re-parks. Ordered on
    // the waiters' own arm counts; the bound is a hang guard below their
    // 5 s deadline, never a verdict.
    pool_word = 0;
    pool_armed = 0;
    pool_done = 0;
    pool_errors = 0;
    for (long i = 0; i < POOL; i++) spawn(pool_entry, i);
    long woken = 0, most = 0;
    long give_up = now_ns(CLOCK_MONOTONIC) + 4000 * MS;
    while (most < POOL && now_ns(CLOCK_MONOTONIC) < give_up) {
        while (__atomic_load_n(&pool_armed, __ATOMIC_ACQUIRE) < POOL + woken
               && now_ns(CLOCK_MONOTONIC) < give_up)
            sc(24, 0, 0, 0, 0, 0, 0);
        long n = sc(202, (long)&pool_word, FUTEX_WAKE_PRIVATE, 0x7fffffff, 0, 0, 0);
        if (n < 0) break;
        woken += n;
        if (n > most) most = n;
    }
    __atomic_store_n(&pool_word, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&pool_done, __ATOMIC_ACQUIRE) < POOL)
        if (sc(202, (long)&pool_word, FUTEX_WAKE_PRIVATE, 0x7fffffff, 0, 0, 0) == 0)
            sc(24, 0, 0, 0, 0, 0, 0);
    p = put(p, " pool=");
    p = put_long(p, most);
    if (pool_errors) p = put(p, "wrong");
    p = put(p, "\n");
    sc(1, 1, (long)line, p - line, 0, 0, 0);
}

// The kernel enters _start with no return address on the stack.
__attribute__((force_align_arg_pointer)) void _start(void) {
    struct kernel_sigaction interrupting = {(void *)handler, 0x04000000, (void *)restorer, 0};
    struct kernel_sigaction restarting = {(void *)handler, 0x04000000 | 0x10000000, (void *)restorer, 0};
    if (sc(13, SIGUSR1, (long)&interrupting, 0, 8, 0, 0) != 0) sc(231, 93, 0, 0, 0, 0, 0);
    if (sc(13, SIGUSR2, (long)&restarting, 0, 8, 0, 0) != 0) sc(231, 93, 0, 0, 0, 0, 0);
    long child = sc(57, 0, 0, 0, 0, 0, 0);
    if (child < 0) sc(231, 94, 0, 0, 0, 0, 0);
    if (child == 0) {
        run("child");
        sc(231, 0, 0, 0, 0, 0, 0);
    }
    int status = -1;
    if (sc(61, child, (long)&status, 0, 0, 0, 0) != child) sc(231, 95, 0, 0, 0, 0, 0);
    run("root");
    sc(231, status == 0 ? 7 : 96, 0, 0, 0, 0, 0);
}
