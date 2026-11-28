// A non-main thread vforks and execs while sibling threads edit memory (#2890).
//
// This is the shape of the Go runtime's `fork/exec` once it runs more than
// one P: the root reads its CPU mask with `sched_getaffinity`, starts four
// `CLONE_VM` threads that map, touch and unmap anonymous memory and yield in
// a loop, and a fifth thread forks with `clone(CLONE_VM | CLONE_VFORK)` and
// execs this image with the argument `c` in the child, sixteen times. While
// the vfork child runs on the shared address space, the forking thread is
// suspended and the four siblings keep editing that address space. The
// exec'd image exits 0 at once. On exec failure the vfork child exits with
// the errno (Go reports it as `fork/exec ...: bad address` for EFAULT).
// The root prints `ok=16` and exits 7; a failed round prints its wait status
// and the root exits 95; a failed clone prints its errno as the status's low
// byte and the root exits 94. 96 is a thread that did not
// start, 97 a refused `sched_getaffinity`, 98 threads that did not finish
// within five seconds (it prints the rounds done and the workers done), 99
// a memory edit that did not return what Linux returns.
//
// Built with -DWORKERS=0 there are no siblings; with -DFROM_MAIN the root's
// own thread forks, with no spawner thread. With -DREADERS the siblings
// instead `pread` this image (a host file) into a fresh, never-touched
// anonymous map and check the byte count and the bytes, as Go's build reads
// its package archives into fresh heap spans (#3050: `read ...: bad
// address`). A read that answers anything but the image's size (zero
// included) exits 93, printing its errno; one whose bytes differ from the
// image's exits 90.
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

// The exec request: two candidate paths for this image, argv, envp.
struct exec_req {
    const char *path;
    const char *fallback;
    char **argv;
    char **envp;
};
// rdi: the request. `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)` on the caller's
// own stack, as vfork does. The child only reads the request and makes
// syscalls (it never returns or writes memory), then execs or exits with the
// errno. The parent returns the child's pid, or -errno.
long vfork_exec(const struct exec_req *req);
__asm__(".globl vfork_exec\n"
        "vfork_exec:\n"
        " mov %rdi,%r8\n"
        " mov $56,%eax\n"
        " mov $0x4111,%edi\n"
        " xor %esi,%esi\n"
        " xor %edx,%edx\n"
        " xor %r10d,%r10d\n"
        " syscall\n"
        " test %rax,%rax\n"
        " jnz 1f\n"
        " mov %r8,%rbx\n"
        " mov $59,%eax\n"
        " mov (%rbx),%rdi\n"
        " mov 16(%rbx),%rsi\n"
        " mov 24(%rbx),%rdx\n"
        " syscall\n"
        " mov $59,%eax\n"
        " mov 8(%rbx),%rdi\n"
        " mov 16(%rbx),%rsi\n"
        " mov 24(%rbx),%rdx\n"
        " syscall\n"
        " mov %eax,%edi\n"
        " neg %edi\n"
        " mov $231,%eax\n"
        " syscall\n"
        "1: ret\n");

#ifndef WORKERS
#define WORKERS 4
#endif
#define ROUNDS 16
#define SPAN (16 * 4096)
// With READERS, each sibling reads a large image into a large fresh map, so
// every read's completion writes hundreds of never-touched destination pages.
#define READ_SPAN (1024 * 1024)
#ifdef READERS
__attribute__((used)) static const char image_pad[512 * 1024] = {1};
#endif
#define CLONE_THREAD_FLAGS 0x50f00 /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
static volatile int stop;
static volatile int workers_done;
static volatile int spawner_done;
static volatile int rounds_done;
static volatile int bad;
static volatile int failed_round = -1;
static volatile int failed_status;
static volatile int failed_clone;
static volatile long read_answer;
// Set with the first wrong read answer, so a zero-byte answer is caught.
static volatile int read_wrong;
// Set when a read returned the right count but bytes the image lacks.
static volatile int read_differs;
static long image_fd = -1;
static long image_size;
static struct exec_req req;
#ifdef READERS
// The image as the root read it before the siblings start: each sibling's
// destination must hold exactly these bytes.
static char probe[READ_SPAN];
#endif

// pread64 the whole image into `buf` from offset 0, as many calls as the
// kernel takes (a read may be short): the bytes read, or the first -errno.
static long read_all(long buf, long cap) {
    long done = 0;
    while (done < cap) {
        long got = sc(17, image_fd, buf + done, cap - done, done, 0, 0);
        if (got < 0) return got;
        if (got == 0) break;
        done += got;
    }
    return done;
}

static void read_image(void *unused) {
    (void)unused;
    while (!stop) {
        long map = sc(9, 0, READ_SPAN, 3, 0x22, -1, 0); // mmap PROT_READ|WRITE, PRIVATE|ANONYMOUS
        if (map < 0 && map > -4096) {
            __sync_fetch_and_add(&bad, 1);
            break;
        }
        long got = read_all(map, READ_SPAN); // into untouched memory
        if (got != image_size) {
            if (__sync_bool_compare_and_swap(&read_wrong, 0, 1)) read_answer = got;
        } else {
#ifdef READERS
            for (long i = 0; i < got; i++)
                if (((volatile char *)map)[i] != probe[i]) {
                    read_differs = 1;
                    break;
                }
#endif
        }
        if (sc(11, map, READ_SPAN, 0, 0, 0, 0) != 0) // munmap
            __sync_fetch_and_add(&bad, 1);
        sc(24, 0, 0, 0, 0, 0, 0); // sched_yield
    }
    // A reader ends with its own raw `exit` (thread_spawn's return), so the
    // root's exit_group meets no sleeping sibling: that is another shape.
    __sync_fetch_and_add(&workers_done, 1);
}

static void edit_memory(void *unused) {
    (void)unused;
    while (!stop) {
        long map = sc(9, 0, SPAN, 3, 0x22, -1, 0); // mmap PROT_READ|WRITE, PRIVATE|ANONYMOUS
        if (map < 0 && map > -4096) {
            __sync_fetch_and_add(&bad, 1);
            break;
        }
        for (long off = 0; off < SPAN; off += 4096) ((volatile char *)map)[off] = 1;
        if (sc(11, map, SPAN, 0, 0, 0, 0) != 0) // munmap
            __sync_fetch_and_add(&bad, 1);
        sc(24, 0, 0, 0, 0, 0, 0); // sched_yield
    }
    __sync_fetch_and_add(&workers_done, 1);
    long pause[2] = {1, 0};
    for (;;) sc(35, (long)pause, 0, 0, 0, 0, 0);
}

static void spawn_rounds(void *unused) {
    (void)unused;
    for (int round = 0; round < ROUNDS; round++) {
        long pid = vfork_exec(&req);
        if (pid < 0) {
            // The clone's errno in the low byte, as a wait status's signal would be.
            failed_status = (int)-pid;
            failed_round = round;
            failed_clone = 1;
            break;
        }
        int status = -1;
        if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) {
            failed_status = status;
            failed_round = round;
            break;
        }
        rounds_done = round + 1;
    }
    spawner_done = 1;
#ifdef READERS
    return;
#endif
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

static long now_ns(void) {
    long ts[2] = {0, 0};
    sc(228, 1, (long)ts, 0, 0, 0, 0); // clock_gettime(CLOCK_MONOTONIC)
    return ts[0] * 1000000000L + ts[1];
}

static void put_count(char *at, int value) {
    at[0] = '0' + value / 10 % 10;
    at[1] = '0' + value % 10;
}

// Waits five seconds at most; past that, prints how far the threads got.
static void wait_for(volatile int *flag, int want) {
    long pause[2] = {0, 1000000};
    long deadline = now_ns() + 60000000000L;
    while (*flag != want) {
        if (now_ns() > deadline) {
            char line[] = "timeout rounds 00 workers 00\n";
            put_count(line + 15, rounds_done);
            put_count(line + 26, workers_done);
            sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
            sc(231, 98, 0, 0, 0, 0, 0);
        }
        sc(35, (long)pause, 0, 0, 0, 0, 0);
    }
}

void start_c(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    if (argc > 1) sc(231, 0, 0, 0, 0, 0, 0);
    unsigned long mask[16];
    if (sc(204, 0, sizeof mask, (long)mask, 0, 0, 0) <= 0) // sched_getaffinity, as Go sizes its Ps
        sc(231, 97, 0, 0, 0, 0, 0);
    static char *args[3];
    args[0] = argv[0];
    args[1] = "c";
    args[2] = 0;
    req.path = argv[0];
    req.fallback = "/proc/self/exe";
    req.argv = args;
    req.envp = envp;
#ifdef READERS
    image_fd = sc(257, -100, (long)argv[0], 0, 0, 0, 0); // openat(AT_FDCWD, image, O_RDONLY)
    for (long off = 0; off < READ_SPAN; off += 4096) probe[off] = 1;
    image_size = image_fd < 0 ? -1 : read_all((long)probe, READ_SPAN);
    if (image_size < (long)sizeof image_pad || image_size >= READ_SPAN) sc(231, 92, 0, 0, 0, 0, 0);
    for (int i = 0; i < WORKERS; i++) spawn(read_image);
#else
    for (int i = 0; i < WORKERS; i++) spawn(edit_memory);
#endif
#ifdef FROM_MAIN
    // Control: the root's own thread forks, with no spawner thread.
    for (int round = 0; round < ROUNDS && failed_round < 0; round++) {
        long pid = vfork_exec(&req);
        int status = -1;
        if (pid < 0) {
            failed_status = (int)-pid;
            failed_round = round;
            failed_clone = 1;
        } else if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) {
            failed_status = status;
            failed_round = round;
        } else {
            rounds_done = round + 1;
        }
    }
#else
    spawn(spawn_rounds);
    wait_for(&spawner_done, 1);
#endif
    stop = 1;
    wait_for(&workers_done, WORKERS);
    if (failed_round >= 0) {
        // The round and its wait status in hex: a signal in the low byte, an exit code (the errno) above.
        char line[] = "round 00 status 0x0000\n";
        line[6] = '0' + failed_round / 10;
        line[7] = '0' + failed_round % 10;
        for (int i = 0; i < 4; i++) line[21 - i] = "0123456789abcdef"[(failed_status >> (4 * i)) & 15];
        sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
        sc(231, failed_clone ? 94 : 95, 0, 0, 0, 0, 0);
    }
    if (read_wrong) {
        // The first wrong read answer, negated: an errno (14 is EFAULT);
        // 0000 for a short or zero-byte answer.
        char line[] = "read errno 0000\n";
        long errno_ = read_answer < 0 ? -read_answer : 0;
        for (int i = 0; i < 4; i++) line[14 - i] = '0' + (char)(errno_ / (i == 0 ? 1 : i == 1 ? 10 : i == 2 ? 100 : 1000) % 10);
        sc(1, 1, (long)line, sizeof line - 1, 0, 0, 0);
        sc(231, 93, 0, 0, 0, 0, 0);
    }
    if (read_differs) {
        sc(1, 1, (long)"read bytes differ\n", 18, 0, 0, 0);
        sc(231, 90, 0, 0, 0, 0, 0);
    }
    sc(1, 1, (long)"ok=16\n", 6, 0, 0, 0);
    sc(231, bad ? 99 : 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
