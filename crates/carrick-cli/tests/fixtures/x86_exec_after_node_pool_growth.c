// A fork child execs after its parent grew the shared reservation node pool
// past its bootstrap nodes (#3046).
//
// With no argument the root forks one child, which blocks reading a pipe.
// While both processes are live, the root maps MAPPINGS single pages with
// alternating protections, so no two merge and each takes its own
// reservation node: the pool outgrows its bootstrap nodes and CPL0
// publishes a node bank. The root then wakes the child, which execs this
// image with the argument `c`; the exec'd image exits 0 at once. The root
// prints `ok=1` and exits 7.
//
// A refused exec exits 100 + errno (112 is ENOMEM); 96 is a refused
// mapping, 95 a child that did not exit 0 or 100 + errno.
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

#define MAPPINGS 1536

void start_c(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    if (argc > 1) sc(231, 0, 0, 0, 0, 0, 0);
    int pipe[2] = {-1, -1};
    if (sc(22, (long)pipe, 0, 0, 0, 0, 0) != 0) sc(231, 94, 0, 0, 0, 0, 0);
    long pid = sc(57, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
        char go = 0;
        if (sc(0, pipe[0], (long)&go, 1, 0, 0, 0) != 1) sc(231, 94, 0, 0, 0, 0, 0);
        char *args[] = {argv[0], "c", 0};
        long ret = sc(59, (long)argv[0], (long)args, (long)envp, 0, 0, 0);
        sc(231, ret < 0 && ret > -100 ? 100 - ret : 93, 0, 0, 0, 0, 0);
    }
    if (pid < 0) sc(231, 94, 0, 0, 0, 0, 0);
    for (int i = 0; i < MAPPINGS; i++) {
        long map = sc(9, 0, 4096, (i & 1) ? 1 : 3, 0x22, -1, 0);
        if (map < 0 && map > -4096) sc(231, 96, 0, 0, 0, 0, 0);
    }
    char go = 1;
    if (sc(1, pipe[1], (long)&go, 1, 0, 0, 0) != 1) sc(231, 94, 0, 0, 0, 0, 0);
    int status = -1;
    if (sc(61, pid, (long)&status, 0, 0, 0, 0) != pid) sc(231, 95, 0, 0, 0, 0, 0);
    if ((status & 0x7f) != 0) sc(231, 95, 0, 0, 0, 0, 0);
    int code = (status >> 8) & 0xff;
    if (code != 0) sc(231, code > 100 ? code : 95, 0, 0, 0, 0, 0);
    sc(1, 1, (long)"ok=1\n", 5, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
