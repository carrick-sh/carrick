// Threads of an exec'd fork child edit their shared address space (#2851).
//
// With no argument the root forks four children in turn; each execs this
// image with the argument `c`. The exec'd child starts six `CLONE_VM`
// threads. Each thread, and then the child's own thread, maps, protects,
// advises and unmaps anonymous memory in a loop, as a C runtime's thread
// stacks and allocator arenas do. Edits of one address space from seven
// threads contend: a call that meets another's edit waits and reruns its
// saved `SYSCALL`, and the thread it shares a CPU with may preempt that
// rerun before the instruction executes. A rerun must stay at `SYSCALL`
// (rewound once more, it runs the two bytes before it). The child exits 0
// when every call returned what Linux returns; its members, done, sleep
// until that exit_group. The root prints `ok=4` and exits 7, or a failed
// child's wait status and exits 95.
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

#define THREADS 6
#define ROUNDS 64
#define SPAN (16 * 4096)
#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
static volatile int done;
static volatile int bad;

static void edit_mappings(void) {
    for (int i = 0; i < ROUNDS; i++) {
        long map = sc(9, 0, SPAN, 3, 0x22, -1, 0); // mmap PROT_READ|WRITE, PRIVATE|ANONYMOUS
        if (map < 0 && map > -4096) {
            __sync_fetch_and_add(&bad, 1);
            return;
        }
        ((volatile char *)map)[4096] = 1;
        if (sc(10, map, 4096, 0, 0, 0, 0) != 0) // mprotect the first page PROT_NONE
            __sync_fetch_and_add(&bad, 1);
        if (sc(28, map + 4096, SPAN - 4096, 4, 0, 0, 0) != 0) // madvise MADV_DONTNEED
            __sync_fetch_and_add(&bad, 1);
        if (((volatile char *)map)[4096] != 0) // DONTNEED drops private anonymous bytes
            __sync_fetch_and_add(&bad, 1);
        if (sc(11, map, SPAN, 0, 0, 0, 0) != 0) // munmap
            __sync_fetch_and_add(&bad, 1);
    }
}

// A member then sleeps until the leader's exit_group ends the process.
static void member(void *unused) {
    (void)unused;
    edit_mappings();
    __sync_fetch_and_add(&done, 1);
    long pause[2] = {1, 0};
    for (;;) sc(35, (long)pause, 0, 0, 0, 0, 0);
}

static void child(void) {
    for (int i = 0; i < THREADS; i++) {
        long stack = sc(9, 0, 65536, 3, 0x22, -1, 0);
        if (stack < 0 && stack > -4096) sc(231, 96, 0, 0, 0, 0, 0);
        long *top = (long *)(stack + 65536) - 2;
        top[0] = 0;
        top[1] = (long)member;
        if (thread_spawn(CLONE_THREAD_FLAGS, top) < 0) sc(231, 97, 0, 0, 0, 0, 0);
    }
    edit_mappings();
    long pause[2] = {0, 1000000};
    for (int waited = 0; done != THREADS; waited++) {
        if (waited == 5000) sc(231, 98, 0, 0, 0, 0, 0);
        sc(35, (long)pause, 0, 0, 0, 0, 0);
    }
    sc(231, bad ? 99 : 0, 0, 0, 0, 0, 0);
}

void start_c(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    if (argc > 1) child();
    for (int round = 0; round < 4; round++) {
        long pid = sc(57, 0, 0, 0, 0, 0, 0);
        if (pid == 0) {
            char *args[] = {argv[0], "c", 0};
            sc(59, (long)argv[0], (long)args, (long)envp, 0, 0, 0);
            sc(59, (long)"/proc/self/exe", (long)args, (long)envp, 0, 0, 0);
            sc(231, 93, 0, 0, 0, 0, 0);
        }
        int status = -1;
        if (pid < 0 || sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) {
            // The wait status in hex: a signal in the low byte, an exit code above.
            char line[] = "child status 0x0000\n";
            for (int i = 0; i < 4; i++) line[18 - i] = "0123456789abcdef"[(status >> (4 * i)) & 15];
            sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
            sc(231, 95, 0, 0, 0, 0, 0);
        }
    }
    sc(1, 1, (long)"ok=4\n", 5, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
