// close_range(2) in the run root and in a fork child, compared with Linux.
//
// Each process opens two pipes (four consecutive numbers b..b+3, the lowest
// free ones; a test harness may hold a lower one open) and prints one line
// per call with its raw return value and the F_GETFD answer of b..b+3 after
// it (-9 is EBADF, 1 is FD_CLOEXEC):
// - the invalid shapes first (first > last, an unknown flag): EINVAL, and
//   nothing is closed;
// - CLOSE_RANGE_CLOEXEC on b..b: b stays open with FD_CLOEXEC;
// - a range past the table (b+2..~0U): b+2 and b+3 close;
// - CLOSE_RANGE_UNSHARE on b+1..b+1: b+1 closes;
// - a range with nothing open (b+100..b+200): 0;
// - a host file (`/`) at b+1 between ring pipe ends b+2 and b+3:
//   CLOSE_RANGE_CLOEXEC over b+1..b+3 marks all three, then b+1..~0U closes
//   all three.
// The child runs first and exits 0; the root waits for it and runs the same
// sequence. The root then starts a thread sharing its table (CLONE_FILES)
// over a fresh pipe b, b+1: the thread closes b+1 with a plain close_range
// (the root sees it closed) and then b with CLOSE_RANGE_UNSHARE, which
// closes b in the thread's private copy only. One line reports the
// thread's two return values, its own F_GETFD of b, and the root's F_GETFD
// of b and b+1 after the thread is done. Last, a fork child's leader
// raw-exits beside its one worker, whose CLOSE_RANGE_UNSHARE of b is then a
// plain range (one `l` line). The root exits 7. No libc: raw
// syscalls only; the thread is a raw `clone` on a mapped stack.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

#define CLOSE_RANGE_UNSHARE 2
#define CLOSE_RANGE_CLOEXEC 4

static void put_num(char **at, long value) {
    char digits[24];
    int n = 0;
    unsigned long v = value < 0 ? -(unsigned long)value : (unsigned long)value;
    if (value < 0) *(*at)++ = '-';
    do {
        digits[n++] = '0' + v % 10;
        v /= 10;
    } while (v);
    while (n) *(*at)++ = digits[--n];
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

static long base;

static void report(char who, const char *what, long ret) {
    char line[128];
    char *at = line;
    *at++ = who;
    *at++ = ' ';
    while (*what) *at++ = *what++;
    *at++ = '=';
    put_num(&at, ret);
    for (long fd = base; fd <= base + 3; fd++) {
        *at++ = ' ';
        put_num(&at, sc(72, fd, 1, 0, 0, 0, 0)); // fcntl(fd, F_GETFD)
    }
    *at++ = '\n';
    sc(1, 1, (long)line, at - line, 0, 0, 0);
}

static void sequence(char who) {
    int fds[4];
    if (sc(293, (long)fds, 0, 0, 0, 0, 0) != 0 || sc(293, (long)(fds + 2), 0, 0, 0, 0, 0) != 0)
        sc(231, 96, 0, 0, 0, 0, 0);
    base = fds[0];
    report(who, "open", fds[3] - fds[0]);
    report(who, "reversed", sc(436, base + 2, base + 1, 0, 0, 0, 0));
    report(who, "badflag", sc(436, base, base + 3, 8, 0, 0, 0));
    report(who, "cloexec", sc(436, base, base, CLOSE_RANGE_CLOEXEC, 0, 0, 0));
    report(who, "tail", sc(436, base + 2, ~0U, 0, 0, 0, 0));
    report(who, "unshare", sc(436, base + 1, base + 1, CLOSE_RANGE_UNSHARE, 0, 0, 0));
    report(who, "empty", sc(436, base + 100, base + 200, 0, 0, 0, 0));
    long host = sc(257, -100, (long)"/", 0x10000, 0, 0, 0); // openat(AT_FDCWD, "/", O_DIRECTORY)
    if (sc(293, (long)fds, 0, 0, 0, 0, 0) != 0) sc(231, 93, 0, 0, 0, 0, 0);
    report(who, "mixed-open", host - base);
    report(who, "mixed-cloexec", sc(436, base + 1, base + 3, CLOSE_RANGE_CLOEXEC, 0, 0, 0));
    report(who, "mixed", sc(436, base + 1, ~0U, 0, 0, 0, 0));
    sc(3, base, 0, 0, 0, 0, 0);
}

static volatile int done;
static volatile long shared_ret, unshare_ret, own_view;

static void member(void *unused) {
    (void)unused;
    shared_ret = sc(436, base + 1, base + 1, 0, 0, 0, 0);
    unshare_ret = sc(436, base, base, CLOSE_RANGE_UNSHARE, 0, 0, 0);
    own_view = sc(72, base, 1, 0, 0, 0, 0);
    done = 1;
}

static void threads(void) {
    int fds[2];
    if (sc(293, (long)fds, 0, 0, 0, 0, 0) != 0) sc(231, 92, 0, 0, 0, 0, 0);
    base = fds[0];
    long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
    if (stack < 0 && stack > -4096) sc(231, 91, 0, 0, 0, 0, 0);
    long *top = (long *)(stack + 65536) - 2;
    top[0] = 0;
    top[1] = (long)member;
    if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 90, 0, 0, 0, 0, 0);
    long interval[2] = {0, 2000000L};
    for (int waited = 0; !done && waited < 2500; waited++) sc(35, (long)interval, 0, 0, 0, 0, 0);
    char line[128];
    char *at = line;
    const char *what = "t shared=";
    while (*what) *at++ = *what++;
    put_num(&at, shared_ret);
    what = " unshare=";
    while (*what) *at++ = *what++;
    put_num(&at, unshare_ret);
    what = " own=";
    while (*what) *at++ = *what++;
    put_num(&at, own_view);
    what = " root=";
    while (*what) *at++ = *what++;
    put_num(&at, sc(72, base, 1, 0, 0, 0, 0));
    *at++ = ' ';
    put_num(&at, sc(72, base + 1, 1, 0, 0, 0, 0));
    *at++ = '\n';
    sc(1, 1, (long)line, at - line, 0, 0, 0);
}

// A fork child whose leader raw-exits (SYS_exit) while its one worker
// thread lives (#2949 review P0-1): the worker is then the table's only
// user, so its CLOSE_RANGE_UNSHARE is a plain range on Linux (0, b closed).
// The leader's clear-tid word ends the worker's bounded wait; if it never
// clears, the bound passes with the leader long gone all the same.
static volatile int leader_word;

static void lone(void *unused) {
    (void)unused;
    long interval[2] = {0, 2000000L};
    for (int waited = 0; leader_word != 0 && waited < 500; waited++) sc(35, (long)interval, 0, 0, 0, 0, 0);
    long interval_settle[2] = {0, 20000000L};
    sc(35, (long)interval_settle, 0, 0, 0, 0, 0);
    char line[96];
    char *at = line;
    const char *what = "l unshare=";
    while (*what) *at++ = *what++;
    put_num(&at, sc(436, base, base, CLOSE_RANGE_UNSHARE, 0, 0, 0));
    what = " own=";
    while (*what) *at++ = *what++;
    put_num(&at, sc(72, base, 1, 0, 0, 0, 0));
    *at++ = ' ';
    put_num(&at, sc(72, base + 1, 1, 0, 0, 0, 0));
    *at++ = '\n';
    sc(1, 1, (long)line, at - line, 0, 0, 0);
    sc(231, 0, 0, 0, 0, 0, 0);
}

static void leader_exit(void) {
    long pid = sc(57, 0, 0, 0, 0, 0, 0); // fork
    if (pid == 0) {
        int fds[2];
        if (sc(293, (long)fds, 0, 0, 0, 0, 0) != 0) sc(231, 89, 0, 0, 0, 0, 0);
        base = fds[0];
        leader_word = (int)sc(186, 0, 0, 0, 0, 0, 0); // gettid
        sc(218, (long)&leader_word, 0, 0, 0, 0, 0);    // set_tid_address
        long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
        if (stack < 0 && stack > -4096) sc(231, 88, 0, 0, 0, 0, 0);
        long *top = (long *)(stack + 65536) - 2;
        top[0] = 0;
        top[1] = (long)lone;
        if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 87, 0, 0, 0, 0, 0);
        sc(60, 0, 0, 0, 0, 0, 0); // the leader's raw exit
    }
    if (pid < 0) sc(231, 86, 0, 0, 0, 0, 0);
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) sc(231, 85, 0, 0, 0, 0, 0);
}

void start_c(long *sp) {
    (void)sp;
    long pid = sc(57, 0, 0, 0, 0, 0, 0); // fork
    if (pid == 0) {
        sequence('c');
        sc(231, 0, 0, 0, 0, 0, 0);
    }
    if (pid < 0) sc(231, 95, 0, 0, 0, 0, 0);
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) sc(231, 94, 0, 0, 0, 0, 0);
    sequence('r');
    threads();
    leader_exit();
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
