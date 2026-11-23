// A thread of an exec'd fork child reads a host file (#2832).
//
// With no argument the root forks four children in turn; each execs this
// image with the argument `c`. The exec'd child starts two `CLONE_VM`
// threads with the flags a language runtime uses. Each thread opens the
// image's own file, reads its first bytes, maps its first page privately
// and closes it. The private file mapping is a call the host serves for the
// stopped task, which here is a member of the exec'd process and never its
// leader (without the mapping the run passes). The leader waits for both
// and exits 0. The root prints `ok=4` and exits 7.
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

#define THREADS 2
#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
static const char *image_path;
static volatile int done;
static volatile int bad;

static void member(void *unused) {
    (void)unused;
    unsigned char head[4] = {0, 0, 0, 0};
    long fd = sc(2, (long)image_path, 0, 0, 0, 0, 0);
    if (fd < 0) fd = sc(2, (long)"/proc/self/exe", 0, 0, 0, 0, 0);
    if (fd < 0 || sc(17, fd, (long)head, 4, 0, 0, 0) != 4 || head[0] != 0x7f || head[1] != 'E'
        || head[2] != 'L' || head[3] != 'F')
        __sync_fetch_and_add(&bad, 1);
    if (fd >= 0) {
        long map = sc(9, 0, 4096, 1, 2, fd, 0);
        if ((map < 0 && map > -4096) || ((unsigned char *)map)[1] != 'E')
            __sync_fetch_and_add(&bad, 1);
        sc(3, fd, 0, 0, 0, 0, 0);
    }
    __sync_fetch_and_add(&done, 1);
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
    image_path = argv[0];
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
        if (pid < 0 || sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0)
            sc(231, 95, 0, 0, 0, 0, 0);
    }
    sc(1, 1, (long)"ok=4\n", 5, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
