// #3081: exit_group ends every thread of the group, whatever it is blocked in.
//
// The root's main thread starts THREADS raw CLONE_THREAD siblings. Each one
// marks itself parked (an atomic count, then its own word) and then sleeps in
// nanosleep({SLEEP_SECS, 0}) in a loop, forever. The root waits on a futex
// until every sibling has said it is about to sleep, then gives them 20 ms
// to be inside nanosleep, prints `parked=<n>` and calls exit_group(7).
// Linux ends the siblings at once: the process exits 7 well inside a second.
// A group exit that leaves a sleeper parked holds the run open to its bound.
//
// Exit codes: 7 the group exited; 96 a stack map failed; 97 a clone failed;
// 98 the siblings never all parked inside 2 s; 99 the root came back from
// exit_group.
//
// No libc: each thread is a raw `clone` call on a mapped stack.
#ifndef THREADS
#define THREADS 4
#endif
#ifndef SLEEP_SECS
#define SLEEP_SECS 1
#endif
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
static volatile int parked;

static void member(void *unused) {
    (void)unused;
    __atomic_add_fetch(&parked, 1, __ATOMIC_SEQ_CST);
    sc(202, (long)&parked, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    long interval[2] = {SLEEP_SECS, 0};
    for (;;) sc(35, (long)interval, 0, 0, 0, 0, 0);
}

void start_c(long *sp) {
    (void)sp;
    for (int i = 0; i < THREADS; i++) {
        long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
        if (stack < 0 && stack > -4096) sc(231, 96, 0, 0, 0, 0, 0);
        long *top = (long *)(stack + 65536) - 2;
        top[0] = 0;
        top[1] = (long)member;
        if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 97, 0, 0, 0, 0, 0);
    }
    // Wait for every sibling's mark; each mark wakes the futex. A bounded
    // wait (100 ms each, 2 s in all) keeps a lost wake from hanging the run.
    long tick[2] = {0, 100000000L};
    for (int waited = 0; waited < 20; waited++) {
        int seen = __atomic_load_n(&parked, __ATOMIC_SEQ_CST);
        if (seen == THREADS) break;
        sc(202, (long)&parked, FUTEX_WAIT_PRIVATE, seen, (long)tick, 0, 0);
    }
    if (__atomic_load_n(&parked, __ATOMIC_SEQ_CST) != THREADS) sc(231, 98, 0, 0, 0, 0, 0);
    // Every sibling has made its mark and is at, or inside, its nanosleep.
    long settle[2] = {0, 20000000L};
    sc(35, (long)settle, 0, 0, 0, 0, 0);
    char line[] = "parked=0\n";
    line[7] = '0' + THREADS;
    sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
    sc(60, 99, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
