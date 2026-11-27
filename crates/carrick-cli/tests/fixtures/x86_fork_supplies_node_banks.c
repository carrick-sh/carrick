// A fork whose child needs more reservation nodes than the shared pool
// holds succeeds: the fork supplies a node bank and reruns (#3085).
//
// The root maps MAPPINGS single pages with alternating protections, so no
// two merge and each takes its own reservation node. The pool starts at
// 1024 nodes and grows by banks of 4096, so the mappings leave it at one
// bank (5120 nodes) holding about 3200. A fork copies the parent's tree
// into the child: about 6400 nodes, past the pool, so the first fork needs
// a bank. Its child stays live (blocked reading a pipe), and the second
// fork needs about 9600 nodes, past two banks, so it needs another.
// The root then releases both children, reaps them, prints `ok=2` and
// exits 7.
//
// A refused fork exits 100 + errno (114 is EFAULT, 111 EAGAIN); 96 is a
// refused mapping, 95 a child that did not exit 0, 94 a pipe failure.
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

#define MAPPINGS 3200
#define CHILDREN 2

void start_c(long *sp) {
    (void)sp;
    int pipe[2] = {-1, -1};
    if (sc(22, (long)pipe, 0, 0, 0, 0, 0) != 0) sc(231, 94, 0, 0, 0, 0, 0);
    for (int i = 0; i < MAPPINGS; i++) {
        long map = sc(9, 0, 4096, (i & 1) ? 1 : 3, 0x22, -1, 0);
        if (map < 0 && map > -4096) sc(231, 96, 0, 0, 0, 0, 0);
    }
    long pids[CHILDREN];
    for (int i = 0; i < CHILDREN; i++) {
        long pid = sc(57, 0, 0, 0, 0, 0, 0);
        if (pid == 0) {
            char go = 0;
            if (sc(0, pipe[0], (long)&go, 1, 0, 0, 0) != 1) sc(231, 94, 0, 0, 0, 0, 0);
            sc(231, 0, 0, 0, 0, 0, 0);
        }
        if (pid < 0) sc(231, pid > -100 ? 100 - pid : 93, 0, 0, 0, 0, 0);
        pids[i] = pid;
    }
    char go[CHILDREN] = {1, 1};
    if (sc(1, pipe[1], (long)go, CHILDREN, 0, 0, 0) != CHILDREN) sc(231, 94, 0, 0, 0, 0, 0);
    for (int i = 0; i < CHILDREN; i++) {
        int status = -1;
        if (sc(61, pids[i], (long)&status, 0, 0, 0, 0) != pids[i]) sc(231, 95, 0, 0, 0, 0, 0);
        if ((status & 0xffff) != 0) sc(231, 95, 0, 0, 0, 0, 0);
    }
    sc(1, 1, (long)"ok=2\n", 5, 0, 0, 0);
    sc(231, 7, 0, 0, 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start_c\n hlt\n");
