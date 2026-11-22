// #2776: a process reads its own thread group from /proc/self/task, and a
// second process reads it from /proc/<tgid>/task. Two live threads: the
// leader lists itself, starts a worker and lists both, releases the worker
// and joins it on its CLONE_CHILD_CLEARTID word, then waits (bounded) for
// the worker's tid to leave the listing. A fork child then lists its own
// group (one thread) and the parent's by number (one thread, the leader).
// One line: a count per stage, or the negated errno of the failing call.
// Exit 7 when every stage saw exactly the live threads. No libc: built
// -nostdlib -static.
static long sc(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}
#define SYS_write 1
#define SYS_sched_yield 24
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_wait4 61
#define SYS_gettid 186
#define SYS_futex 202
#define SYS_getdents64 217
#define SYS_exit_group 231
#define SYS_openat 257
#define SYS_close 3
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

// clone(2) with a new stack: the child pops its entry and calls it.
long spawn(void (*entry)(void), void *stack_top, int *tid);
__asm__(".text\n.globl spawn\nspawn:\n"
        " sub $8,%rsi\n mov %rdi,(%rsi)\n"
        " mov %rdx,%r10\n"          // ctid
        " mov $0x350f00,%edi\n"     // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|CHILD_CLEARTID
        " xor %r8,%r8\n mov $56,%eax\n syscall\n"
        " test %rax,%rax\n jnz 1f\n"
        " pop %rax\n call *%rax\n"
        " xor %edi,%edi\n mov $60,%eax\n syscall\n"
        "1: ret\n");

static volatile int hold = 1;
static int worker_tid;
static char worker_stack[1 << 16] __attribute__((aligned(16)));

static void worker(void) {
    while (hold) sc(SYS_futex, (long)&hold, FUTEX_WAIT, 1, 0);
}

static long parse_tid(const char *name) {
    long value = 0;
    if (!*name) return -1;
    for (; *name; name++) {
        if (*name < '0' || *name > '9') return -1;
        value = value * 10 + (*name - '0');
    }
    return value;
}

// The number of tids `path` lists, with every tid in `want` present (bit i
// of *seen), or a negated errno.
static long list(const char *path, const long *want, int wanted, int *seen) {
    static char buffer[4096];
    long fd = sc(SYS_openat, -100, (long)path, 0x10000 /* O_RDONLY|O_DIRECTORY */, 0);
    if (fd < 0) return fd;
    long count = 0;
    *seen = 0;
    for (;;) {
        long got = sc(SYS_getdents64, fd, (long)buffer, sizeof buffer, 0);
        if (got < 0) {
            sc(SYS_close, fd, 0, 0, 0);
            return got;
        }
        if (got == 0) break;
        for (long at = 0; at < got;) {
            unsigned short reclen = *(unsigned short *)(buffer + at + 16);
            long tid = parse_tid(buffer + at + 19);
            if (tid >= 0) {
                count++;
                for (int i = 0; i < wanted; i++)
                    if (want[i] == tid) *seen |= 1 << i;
            }
            at += reclen;
        }
    }
    sc(SYS_close, fd, 0, 0, 0);
    return count;
}

static char *put(char *at, const char *label, long value) {
    while (*label) *at++ = *label++;
    if (value < 0) {
        *at++ = '-';
        value = -value;
    }
    char digits[20];
    int n = 0;
    do {
        digits[n++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (n) *at++ = digits[--n];
    return at;
}

static void number_path(char *path, long pid) {
    char *at = put(path, "/proc/", pid);
    for (const char *tail = "/task"; *tail;) *at++ = *tail++;
    *at = 0;
}

void start_c(void) {
    long self = sc(SYS_gettid, 0, 0, 0, 0);
    int seen = 0;
    // Stage 1: one thread, the leader.
    long initial = list("/proc/self/task", &self, 1, &seen);
    int ok = initial == 1 && seen == 1;

    // Stage 2: two live threads.
    long spawned = spawn(worker, worker_stack + sizeof worker_stack, &worker_tid);
    if (spawned <= 0) sc(SYS_exit_group, 90, 0, 0, 0);
    long both[2] = {self, spawned};
    long live = list("/proc/self/task", both, 2, &seen);
    ok &= live == 2 && seen == 3;

    // Stage 3: the worker exits and is joined; its tid leaves the listing.
    hold = 0;
    sc(SYS_futex, (long)&hold, FUTEX_WAKE, 1, 0);
    for (int tid; (tid = worker_tid) != 0;) sc(SYS_futex, (long)&worker_tid, FUTEX_WAIT, tid, 0);
    long joined = 0;
    for (int round = 0; round < 20000; round++) {
        joined = list("/proc/self/task", both, 2, &seen);
        if (joined < 0 || (joined == 1 && seen == 1)) break;
        sc(SYS_sched_yield, 0, 0, 0, 0);
    }
    ok &= joined == 1 && seen == 1;

    // Stage 4: a second process lists its own group and this one's.
    long parent = sc(SYS_getpid, 0, 0, 0, 0);
    long pid = sc(SYS_fork, 0, 0, 0, 0);
    if (pid < 0) sc(SYS_exit_group, 91, 0, 0, 0);
    if (pid == 0) {
        long me = sc(SYS_gettid, 0, 0, 0, 0);
        long own = list("/proc/self/task", &me, 1, &seen);
        int good = own == 1 && seen == 1;
        char path[40];
        number_path(path, parent);
        long theirs = list(path, &parent, 1, &seen);
        good &= theirs == 1 && seen == 1;
        // 0: both listings right. Otherwise the first wrong count or errno.
        sc(SYS_exit_group, good ? 0 : (own != 1 ? 100 : 101), 0, 0, 0);
    }
    int status = -1;
    long reaped = sc(SYS_wait4, pid, (long)&status, 0, 0);
    long child = reaped == pid ? status : reaped;
    ok &= child == 0;

    char out[128];
    char *at = put(out, "initial=", initial);
    at = put(at, " live=", live);
    at = put(at, " joined=", joined);
    at = put(at, " child_status=", child);
    *at++ = '\n';
    sc(SYS_write, 1, (long)out, at - out, 0);
    sc(SYS_exit_group, ok ? 7 : 1, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
