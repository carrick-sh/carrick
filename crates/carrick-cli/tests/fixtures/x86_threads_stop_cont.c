// Multi-threaded + forked x86_64 Linux guest for stop/continue and ptrace
// attach/detach cycles (#2962). Built -nostdlib -static -no-pie.
//
// Three CLONE_THREAD workers and one forked child run concurrently across
// futexes, pipes and nanosleep parks after printing "READY\n", so host
// SIGSTOP/SIGCONT and ptrace stops interrupt vCPUs in CPL3 user compute, CPL0
// syscalls, child CR3, and CPL0 idle HLT on the maintenance root.

static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

long stop_cont_thread_spawn(long flags, void *stack);
__asm__(".globl stop_cont_thread_spawn\n"
        "stop_cont_thread_spawn:\n"
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

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_MMAP 9
#define SYS_NANOSLEEP 35
#define SYS_FORK 57
#define SYS_WAIT4 61
#define SYS_FUTEX 202
#define SYS_EXIT_GROUP 231
#define SYS_PIPE2 293

#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define CLONE_THREAD_FLAGS 0x50f00L

struct timespec_abi {
    long tv_sec;
    long tv_nsec;
};

static int ready_count;
static int go_gate;
static int turn;
static int done_count;
static long worker_sum[3];
static int req_pipe[2];
static int rep_pipe[2];

static void sleep_ms(long ms) {
    struct timespec_abi req;
    struct timespec_abi rem;
    req.tv_sec = 0;
    req.tv_nsec = ms * 1000000L;
    rem.tv_sec = 0;
    rem.tv_nsec = 0;
    while (sc(SYS_NANOSLEEP, (long)&req, (long)&rem, 0, 0, 0, 0) == -4) {
        req = rem;
    }
}

static void wait_for_go(void) {
    __atomic_add_fetch(&ready_count, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&go_gate, __ATOMIC_ACQUIRE) == 0) {
        sc(SYS_FUTEX, (long)&go_gate, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    }
}

static void finish_worker(void) {
    __atomic_add_fetch(&done_count, 1, __ATOMIC_SEQ_CST);
    sc(SYS_FUTEX, (long)&done_count, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
}

static void futex_worker_0(long unused) {
    (void)unused;
    wait_for_go();
    long acc = 0;
    for (int r = 0; r < 24; r++) {
        while (__atomic_load_n(&turn, __ATOMIC_ACQUIRE) != 0) {
            sc(SYS_FUTEX, (long)&turn, FUTEX_WAIT_PRIVATE, 1, 0, 0, 0);
        }
        sleep_ms(6);
        acc += (long)(r + 1) * 3L;
        __atomic_store_n(&turn, 1, __ATOMIC_RELEASE);
        sc(SYS_FUTEX, (long)&turn, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    }
    __atomic_store_n(&worker_sum[0], acc, __ATOMIC_RELEASE);
    finish_worker();
}

static void futex_worker_1(long unused) {
    (void)unused;
    wait_for_go();
    long acc = 0;
    for (int r = 0; r < 24; r++) {
        while (__atomic_load_n(&turn, __ATOMIC_ACQUIRE) != 1) {
            sc(SYS_FUTEX, (long)&turn, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
        }
        sleep_ms(6);
        acc += (long)(r + 1) * 5L;
        __atomic_store_n(&turn, 0, __ATOMIC_RELEASE);
        sc(SYS_FUTEX, (long)&turn, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    }
    __atomic_store_n(&worker_sum[1], acc, __ATOMIC_RELEASE);
    finish_worker();
}

static void pipe_worker_2(long unused) {
    (void)unused;
    wait_for_go();
    long acc = 0;
    for (int r = 1; r <= 16; r++) {
        unsigned char b = (unsigned char)r;
        unsigned char reply = 0;
        sleep_ms(8);
        if (sc(SYS_WRITE, req_pipe[1], (long)&b, 1, 0, 0, 0) != 1) {
            sc(SYS_EXIT_GROUP, 91, 0, 0, 0, 0, 0);
        }
        if (sc(SYS_READ, rep_pipe[0], (long)&reply, 1, 0, 0, 0) != 1) {
            sc(SYS_EXIT_GROUP, 92, 0, 0, 0, 0, 0);
        }
        acc += (long)reply;
    }
    __atomic_store_n(&worker_sum[2], acc, __ATOMIC_RELEASE);
    finish_worker();
}

static void child_loop(void) {
    sc(SYS_CLOSE, req_pipe[1], 0, 0, 0, 0, 0);
    sc(SYS_CLOSE, rep_pipe[0], 0, 0, 0, 0, 0);
    unsigned char ready = 0x5a;
    if (sc(SYS_WRITE, rep_pipe[1], (long)&ready, 1, 0, 0, 0) != 1) {
        sc(SYS_EXIT_GROUP, 81, 0, 0, 0, 0, 0);
    }
    for (int r = 0; r < 16; r++) {
        unsigned char b = 0;
        long n = sc(SYS_READ, req_pipe[0], (long)&b, 1, 0, 0, 0);
        if (n != 1) {
            sc(SYS_EXIT_GROUP, 82, 0, 0, 0, 0, 0);
        }
        unsigned char out = (unsigned char)(b * 2);
        if (sc(SYS_WRITE, rep_pipe[1], (long)&out, 1, 0, 0, 0) != 1) {
            sc(SYS_EXIT_GROUP, 83, 0, 0, 0, 0, 0);
        }
    }
    sc(SYS_EXIT_GROUP, 0, 0, 0, 0, 0, 0);
}

static void spawn_one(void (*fn)(long), long arg) {
    long mem = sc(SYS_MMAP, 0, 16384, 3, 0x22, -1, 0);
    if (mem < 0 && mem > -4096) {
        sc(SYS_EXIT_GROUP, 90, 0, 0, 0, 0, 0);
    }
    long *top = (long *)(mem + 16384);
    *--top = (long)fn;
    *--top = arg;
    long rc = stop_cont_thread_spawn(CLONE_THREAD_FLAGS, top);
    if (rc < 0) {
        sc(SYS_EXIT_GROUP, 93, 0, 0, 0, 0, 0);
    }
}

void start_c(void) {
    if (sc(SYS_PIPE2, (long)req_pipe, 0, 0, 0, 0, 0) != 0 ||
        sc(SYS_PIPE2, (long)rep_pipe, 0, 0, 0, 0, 0) != 0) {
        sc(SYS_EXIT_GROUP, 88, 0, 0, 0, 0, 0);
    }
    long child = sc(SYS_FORK, 0, 0, 0, 0, 0, 0);
    if (child < 0) {
        sc(SYS_EXIT_GROUP, 89, 0, 0, 0, 0, 0);
    }
    if (child == 0) {
        child_loop();
    }
    sc(SYS_CLOSE, req_pipe[0], 0, 0, 0, 0, 0);
    sc(SYS_CLOSE, rep_pipe[1], 0, 0, 0, 0, 0);

    unsigned char child_ready = 0;
    if (sc(SYS_READ, rep_pipe[0], (long)&child_ready, 1, 0, 0, 0) != 1 || child_ready != 0x5a) {
        sc(SYS_EXIT_GROUP, 87, 0, 0, 0, 0, 0);
    }

    spawn_one(futex_worker_0, 0);
    spawn_one(futex_worker_1, 1);
    spawn_one(pipe_worker_2, 2);

    while (__atomic_load_n(&ready_count, __ATOMIC_ACQUIRE) < 3) {
        sleep_ms(1);
    }

    const char ready_msg[] = "READY\n";
    if (sc(SYS_WRITE, 1, (long)ready_msg, 6, 0, 0, 0) != 6) {
        sc(SYS_EXIT_GROUP, 94, 0, 0, 0, 0, 0);
    }

    __atomic_store_n(&go_gate, 1, __ATOMIC_RELEASE);
    sc(SYS_FUTEX, (long)&go_gate, FUTEX_WAKE_PRIVATE, 0x7fffffff, 0, 0, 0);

    while (1) {
        int done = __atomic_load_n(&done_count, __ATOMIC_ACQUIRE);
        if (done >= 3) {
            break;
        }
        sc(SYS_FUTEX, (long)&done_count, FUTEX_WAIT_PRIVATE, done, 0, 0, 0);
    }

    int status = -1;
    if (sc(SYS_WAIT4, child, (long)&status, 0, 0, 0, 0) != child || status != 0) {
        sc(SYS_EXIT_GROUP, 95, 0, 0, 0, 0, 0);
    }

    long total = __atomic_load_n(&worker_sum[0], __ATOMIC_ACQUIRE) +
                 __atomic_load_n(&worker_sum[1], __ATOMIC_ACQUIRE) +
                 __atomic_load_n(&worker_sum[2], __ATOMIC_ACQUIRE);

    char out[8];
    out[0] = 'O';
    out[1] = 'K';
    out[2] = ' ';
    out[3] = (char)('0' + ((total / 1000) % 10));
    out[4] = (char)('0' + ((total / 100) % 10));
    out[5] = (char)('0' + ((total / 10) % 10));
    out[6] = (char)('0' + (total % 10));
    out[7] = '\n';
    if (sc(SYS_WRITE, 1, (long)out, 8, 0, 0, 0) != 8) {
        sc(SYS_EXIT_GROUP, 96, 0, 0, 0, 0, 0);
    }
    sc(SYS_EXIT_GROUP, total == 2672 ? 7 : 1, 0, 0, 0, 0, 0);
}

__asm__(".globl _start\n_start:\n and $-16,%rsp\n call start_c\n hlt\n");
