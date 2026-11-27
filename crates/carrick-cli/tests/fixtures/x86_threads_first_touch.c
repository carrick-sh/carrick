// Four threads of one MM first-touch fresh anonymous pages (#3105).
//
// The root starts four raw `CLONE_VM` threads and releases them together
// through a futex, so they fault concurrently. Each maps PAGES fresh private
// anonymous pages and writes one word to every page, then the root checks
// every word. A first touch only fills a not-present entry, and x86 caches
// translations only from present entries, so Linux drains no translation on
// another CPU for it; the KVM row counts the cross-CPU drains Carrick ran.
//
// Exits 7 after printing `ok`; 93 when a map fails (its errno is printed),
// 94 when a thread does not start, 98 when the threads take over ten seconds,
// 99 when a page does not read back. Every futex wait is bounded (100 ms).
//
// No libc: each thread is a raw `clone` call on a mapped stack.
#ifndef PAGES
#define PAGES 256
#endif
#define THREADS 4
#define PAGE 4096L

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
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define MAP_FLAGS 0x22 /* PRIVATE | ANONYMOUS */
#define PROT_RW 3

static int go;
static int running;
static long map_errno;
static long *maps[THREADS];

#define LOAD(word) __atomic_load_n(&(word), __ATOMIC_ACQUIRE)

// Waits at most 100 ms for *word to leave value; 98 after 100 waits.
static void futex_wait(int *word, int value) {
    static int waits;
    long timeout[2] = {0, 100000000L};
    if (__atomic_add_fetch(&waits, 1, __ATOMIC_RELAXED) > 100) sc(231, 98, 0, 0, 0, 0, 0);
    sc(202, (long)word, FUTEX_WAIT_PRIVATE, value, (long)timeout, 0, 0);
}
static void futex_wake(int *word) {
    sc(202, (long)word, FUTEX_WAKE_PRIVATE, 0x7fffffff, 0, 0, 0);
}

static void worker(long index) {
    while (!LOAD(go)) futex_wait(&go, 0);
    long *map = (long *)sc(9, 0, PAGES * PAGE, PROT_RW, MAP_FLAGS, -1, 0);
    if ((unsigned long)map > -4096UL) {
        long none = 0;
        __atomic_compare_exchange_n(&map_errno, &none, -(long)map, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    } else {
        for (long page = 0; page < PAGES; page++) map[page * (PAGE / 8)] = index * PAGES + page;
        __atomic_store_n(&maps[index], map, __ATOMIC_RELEASE);
    }
    __atomic_sub_fetch(&running, 1, __ATOMIC_RELEASE);
    futex_wake(&running);
}

static void put(const char *text, long len) { sc(1, 1, (long)text, len, 0, 0, 0); }

static void put_errno(long value) {
    char line[] = "errno 0000\n";
    for (int digit = 9; digit >= 6; digit--, value /= 10) line[digit] = '0' + value % 10;
    put(line, sizeof line - 1);
}

void _start(void) {
    __atomic_store_n(&running, THREADS, __ATOMIC_RELEASE);
    for (long index = 0; index < THREADS; index++) {
        long *stack = (long *)sc(9, 0, 16 * PAGE, PROT_RW, MAP_FLAGS, -1, 0);
        if ((unsigned long)stack > -4096UL) {
            put_errno(-(long)stack);
            sc(231, 93, 0, 0, 0, 0, 0);
        }
        long *top = stack + 16 * PAGE / 8 - 2;
        top[0] = index;
        top[1] = (long)worker;
        if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 94, 0, 0, 0, 0, 0);
    }
    __atomic_store_n(&go, 1, __ATOMIC_RELEASE);
    futex_wake(&go);
    for (int left = LOAD(running); left != 0; left = LOAD(running)) futex_wait(&running, left);
    if (LOAD(map_errno)) {
        put_errno(LOAD(map_errno));
        sc(231, 93, 0, 0, 0, 0, 0);
    }
    for (long index = 0; index < THREADS; index++) {
        long *map = LOAD(maps[index]);
        for (long page = 0; page < PAGES; page++)
            if (map[page * (PAGE / 8)] != index * PAGES + page) sc(231, 99, 0, 0, 0, 0, 0);
    }
    put("ok\n", 3);
    sc(231, 7, 0, 0, 0, 0, 0);
}
