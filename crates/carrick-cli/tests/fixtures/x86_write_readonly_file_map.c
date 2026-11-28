// A write to a read-only private file mapping is an access error (#3170).
//
// The program maps the first page of its own executable PROT_READ and
// MAP_PRIVATE and, without touching it first, writes to it. Linux delivers
// SIGSEGV with si_code SEGV_ACCERR (2) and si_addr at the written byte: the
// page is mapped, its protection denies the write (sigaction(2)). The very
// first touch is the write, so the fault is a first-touch (translation)
// fault, not a protection fault on a resident page.
//
// Built with -DHOLE it writes instead into the page unmapped between two
// anonymous maps (three pages mapped, the middle one unmapped again). Linux
// answers SEGV_MAPERR (1) there: no mapping covers the page. The exit codes
// below then name SEGV_ACCERR as the wrong answer (94), and 7 is MAPERR.
//
// Exit status names the first step that differs from Linux:
//   90 open failed   91 mmap failed   92 rt_sigaction failed
//   93 the write landed (no signal)
//   94 SIGSEGV with SEGV_MAPERR (1): the page was reported unmapped
//   95 SIGSEGV with another si_code   96 si_addr is not the written byte
//   97 another signal or bad handler arguments
//   7  SIGSEGV, SEGV_ACCERR, at the written byte, as on Linux
//
// No libc.
static long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

void restorer(void);
__asm__(".globl restorer\nrestorer:\n mov $15,%eax\n syscall\n hlt\n");

#define SIGSEGV 11
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
#define PROT_READ 1
#define MAP_PRIVATE 2
#define AT_FDCWD (-100)

struct kernel_sigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    unsigned long mask;
};

struct linux_siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    int pad;
    void *si_addr;
};

static volatile char *target;

static __attribute__((noreturn)) void finish(long code) {
    for (;;) sc(231, code, 0, 0, 0, 0, 0); // exit_group
}

#ifdef HOLE
#define EXPECTED_CODE 1
#define WRONG_CODE 2
#else
#define EXPECTED_CODE 2
#define WRONG_CODE 1
#endif

static void handler(int sig, struct linux_siginfo *info, void *uc) {
    if (sig != SIGSEGV || !info || !uc || info->si_signo != SIGSEGV) finish(97);
    if (info->si_code == WRONG_CODE) finish(94);
    if (info->si_code != EXPECTED_CODE) finish(95);
    if (info->si_addr != (void *)target) finish(96);
    finish(7);
}

__attribute__((noreturn, used)) void start_c(long *sp) {
#ifdef HOLE
    (void)sp;
    // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS.
    long map = sc(9, 0, 3 * 4096, 3, MAP_PRIVATE | 0x20, -1, 0); // mmap
    if (map < 0 && map > -4096) finish(91);
    map += 4096;
    if (sc(11, map, 4096, 0, 0, 0, 0) != 0) finish(90); // munmap the middle
#else
    const char *self = (const char *)sp[1]; // argv[0]
    long fd = sc(257, AT_FDCWD, (long)self, 0 /* O_RDONLY */, 0, 0, 0); // openat
    if (fd < 0) finish(90);
    long map = sc(9, 0, 4096, PROT_READ, MAP_PRIVATE, fd, 0); // mmap
    if (map < 0 && map > -4096) finish(91);
#endif
    struct kernel_sigaction action = {
        (void *)handler,
        SA_SIGINFO | SA_RESTORER,
        (void *)restorer,
        0,
    };
    if (sc(13, SIGSEGV, (long)&action, 0, 8, 0, 0) != 0) finish(92); // rt_sigaction
    target = (volatile char *)(map + 0x40);
    *target = 0x5a; // the first touch of the page, and a write
    finish(93);
}

__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
