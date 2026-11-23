// Empty-set select(2)/pselect6(2) and nfds=0 poll(2)/ppoll(2) (#2848).
//
// Tests both the run root and a fork child against native Linux for:
// - 10 ms sleeps returning 0 after at least 10 ms of CLOCK_MONOTONIC;
// - zero timeouts returning 0 immediately;
// - a caught SIGUSR1 interrupting a 2 s sleep with -EINTR (-4).
//
// No libc: compiled freestanding with raw syscalls.
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

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_poll 7
#define SYS_rt_sigaction 13
#define SYS_pipe 22
#define SYS_select 23
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_clock_gettime 228
#define SYS_exit_group 231
#define SYS_pselect6 270
#define SYS_ppoll 271

#define SIGUSR1 10
#define SA_RESTORER 0x04000000UL
#define CLOCK_MONOTONIC 1
#define TEN_MS_NS 10000000L
#define ONE_SEC_NS 1000000000L

struct k_sigaction {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

void sig_restorer(void);
__asm__(".globl sig_restorer\n"
        "sig_restorer:\n"
        " mov $15,%eax\n"
        " syscall\n");

static volatile long usr1_seen;

static void on_usr1(int sig) {
    (void)sig;
    usr1_seen++;
}

static long now_ns(void) {
    long ts[2];
    if (sc(SYS_clock_gettime, CLOCK_MONOTONIC, (long)ts, 0, 0, 0, 0) != 0) {
        return -1;
    }
    return ts[0] * ONE_SEC_NS + ts[1];
}

static int append_str(char *buf, int n, const char *s) {
    while (*s) buf[n++] = *s++;
    return n;
}

static int append_dec(char *buf, int n, long v) {
    if (v < 0) {
        buf[n++] = '-';
        v = -v;
    }
    char tmp[24];
    int k = 0;
    do {
        tmp[k++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v > 0);
    while (k > 0) buf[n++] = tmp[--k];
    return n;
}

static void report(const char *who, const char *name, long ret, int ok) {
    char line[128];
    int n = 0;
    n = append_str(line, n, who);
    line[n++] = '.';
    n = append_str(line, n, name);
    n = append_str(line, n, " ret=");
    n = append_dec(line, n, ret);
    n = append_str(line, n, " ok=");
    n = append_dec(line, n, ok ? 1 : 0);
    line[n++] = '\n';
    sc(SYS_write, 1, (long)line, n, 0, 0, 0);
}

static void run_sleep_checks(const char *who) {
    long tv[2];
    long ts[2];
    long t0, dt, ret;

    tv[0] = 0;
    tv[1] = 10000;
    t0 = now_ns();
    ret = sc(SYS_select, 0, 0, 0, 0, (long)tv, 0);
    dt = now_ns() - t0;
    report(who, "select_10ms", ret, ret == 0 && dt >= TEN_MS_NS && tv[0] == 0 && tv[1] <= 10000);

    ts[0] = 0;
    ts[1] = TEN_MS_NS;
    t0 = now_ns();
    ret = sc(SYS_pselect6, 0, 0, 0, 0, (long)ts, 0);
    dt = now_ns() - t0;
    report(who, "pselect6_10ms", ret, ret == 0 && dt >= TEN_MS_NS);

    tv[0] = 0;
    tv[1] = 0;
    ret = sc(SYS_select, 0, 0, 0, 0, (long)tv, 0);
    report(who, "select_zero", ret, ret == 0);

    ts[0] = 0;
    ts[1] = 0;
    ret = sc(SYS_pselect6, 0, 0, 0, 0, (long)ts, 0);
    report(who, "pselect6_zero", ret, ret == 0);

    t0 = now_ns();
    ret = sc(SYS_poll, 0, 0, 10, 0, 0, 0);
    dt = now_ns() - t0;
    report(who, "poll_10ms", ret, ret == 0 && dt >= TEN_MS_NS);

    ts[0] = 0;
    ts[1] = TEN_MS_NS;
    t0 = now_ns();
    ret = sc(SYS_ppoll, 0, 0, (long)ts, 0, 8, 0);
    dt = now_ns() - t0;
    report(who, "ppoll_10ms", ret, ret == 0 && dt >= TEN_MS_NS);

    ret = sc(SYS_poll, 0, 0, 0, 0, 0, 0);
    report(who, "poll_zero", ret, ret == 0);

    ts[0] = 0;
    ts[1] = 0;
    ret = sc(SYS_ppoll, 0, 0, (long)ts, 0, 8, 0);
    report(who, "ppoll_zero", ret, ret == 0);
}

static void check_child_eintr(void) {
    int p1[2], p2[2];
    if (sc(SYS_pipe, (long)p1, 0, 0, 0, 0, 0) != 0) sc(SYS_exit_group, 91, 0, 0, 0, 0, 0);
    if (sc(SYS_pipe, (long)p2, 0, 0, 0, 0, 0) != 0) sc(SYS_exit_group, 91, 0, 0, 0, 0, 0);
    long pid = sc(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (pid < 0) sc(SYS_exit_group, 92, 0, 0, 0, 0, 0);
    if (pid == 0) {
        sc(SYS_close, p1[0], 0, 0, 0, 0, 0);
        sc(SYS_close, p2[0], 0, 0, 0, 0, 0);

        char ready = 'R';
        usr1_seen = 0;
        sc(SYS_write, p1[1], (long)&ready, 1, 0, 0, 0);
        sc(SYS_close, p1[1], 0, 0, 0, 0, 0);
        long tv[2] = {2, 0};
        long t0 = now_ns();
        long ret = sc(SYS_select, 0, 0, 0, 0, (long)tv, 0);
        long dt = now_ns() - t0;
        report("child", "select_eintr", ret,
               ret == -4 && usr1_seen == 1 && dt < ONE_SEC_NS && tv[0] < 2);

        usr1_seen = 0;
        sc(SYS_write, p2[1], (long)&ready, 1, 0, 0, 0);
        sc(SYS_close, p2[1], 0, 0, 0, 0, 0);
        long ts[2] = {2, 0};
        t0 = now_ns();
        ret = sc(SYS_pselect6, 0, 0, 0, 0, (long)ts, 0);
        dt = now_ns() - t0;
        report("child", "pselect6_eintr", ret, ret == -4 && usr1_seen == 1 && dt < ONE_SEC_NS);

        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    }
    sc(SYS_close, p1[1], 0, 0, 0, 0, 0);
    sc(SYS_close, p2[1], 0, 0, 0, 0, 0);
    char b = 0;
    long delay[2] = {0, 20000000};
    if (sc(SYS_read, p1[0], (long)&b, 1, 0, 0, 0) != 1) sc(SYS_exit_group, 93, 0, 0, 0, 0, 0);
    sc(SYS_close, p1[0], 0, 0, 0, 0, 0);
    sc(SYS_nanosleep, (long)delay, 0, 0, 0, 0, 0);
    sc(SYS_kill, pid, SIGUSR1, 0, 0, 0, 0);

    if (sc(SYS_read, p2[0], (long)&b, 1, 0, 0, 0) != 1) sc(SYS_exit_group, 93, 0, 0, 0, 0, 0);
    sc(SYS_close, p2[0], 0, 0, 0, 0, 0);
    sc(SYS_nanosleep, (long)delay, 0, 0, 0, 0, 0);
    sc(SYS_kill, pid, SIGUSR1, 0, 0, 0, 0);

    int status = -1;
    if (sc(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) {
        sc(SYS_exit_group, 94, 0, 0, 0, 0, 0);
    }
}

static void check_root_eintr(void) {
    int p1[2];
    if (sc(SYS_pipe, (long)p1, 0, 0, 0, 0, 0) != 0) sc(SYS_exit_group, 95, 0, 0, 0, 0, 0);
    long root_pid = sc(SYS_getpid, 0, 0, 0, 0, 0, 0);
    long pid = sc(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (pid < 0) sc(SYS_exit_group, 96, 0, 0, 0, 0, 0);
    if (pid == 0) {
        sc(SYS_close, p1[1], 0, 0, 0, 0, 0);
        char b = 0;
        if (sc(SYS_read, p1[0], (long)&b, 1, 0, 0, 0) != 1) sc(SYS_exit_group, 97, 0, 0, 0, 0, 0);
        sc(SYS_close, p1[0], 0, 0, 0, 0, 0);
        long delay[2] = {0, 20000000};
        sc(SYS_nanosleep, (long)delay, 0, 0, 0, 0, 0);
        sc(SYS_kill, root_pid, SIGUSR1, 0, 0, 0, 0);
        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    }
    sc(SYS_close, p1[0], 0, 0, 0, 0, 0);
    char ready = 'R';
    usr1_seen = 0;
    sc(SYS_write, p1[1], (long)&ready, 1, 0, 0, 0);
    sc(SYS_close, p1[1], 0, 0, 0, 0, 0);
    long tv[2] = {2, 0};
    long t0 = now_ns();
    long ret = sc(SYS_select, 0, 0, 0, 0, (long)tv, 0);
    long dt = now_ns() - t0;
    report("root", "select_eintr", ret,
           ret == -4 && usr1_seen == 1 && dt < ONE_SEC_NS && tv[0] < 2);

    int status = -1;
    if (sc(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) {
        sc(SYS_exit_group, 98, 0, 0, 0, 0, 0);
    }
}

void start_c(long *sp) {
    (void)sp;
    struct k_sigaction act = {
        .handler = on_usr1,
        .flags = SA_RESTORER,
        .restorer = sig_restorer,
        .mask = 0,
    };
    if (sc(SYS_rt_sigaction, SIGUSR1, (long)&act, 0, 8, 0, 0) != 0) {
        sc(SYS_exit_group, 90, 0, 0, 0, 0, 0);
    }

    run_sleep_checks("root");

    long pid = sc(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (pid < 0) sc(SYS_exit_group, 99, 0, 0, 0, 0, 0);
    if (pid == 0) {
        run_sleep_checks("child");
        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    }
    int status = -1;
    if (sc(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0) {
        sc(SYS_exit_group, 100, 0, 0, 0, 0, 0);
    }

    check_child_eintr();
    check_root_eintr();
    sc(SYS_exit_group, 7, 0, 0, 0, 0, 0);
}

__asm__(".globl _start\n"
        "_start:\n"
        " mov %rsp,%rdi\n"
        " and $-16,%rsp\n"
        " call start_c\n"
        " hlt\n");
