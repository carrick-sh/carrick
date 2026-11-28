// `tuxcall` (x86_64 184), a syscall Linux reserves and never implements,
// answers ENOSYS natively and in Carrick's ring alike; Carrick's ring counts it as a refusal, and the
// compat report must show that count (#3152). Exit 7 and `U` when both of two
// calls answer -ENOSYS; 11 after writing the value otherwise. No libc: built
// -nostdlib -static.
static long sc(long n, long a, long b, long c) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}
#define WRITE 1L
#define EXIT_GROUP 231L
#define TUXCALL 184L
#define ENOSYS 38L

void _start(void) {
    long ret = sc(TUXCALL, 0, 0, 0);
    if (ret == -ENOSYS) ret = sc(TUXCALL, 0, 0, 0);
    if (ret != -ENOSYS) {
        char bad = (char)('0' + (-ret) % 10);
        sc(WRITE, 1, (long)&bad, 1);
        sc(EXIT_GROUP, 11, 0, 0);
    }
    sc(WRITE, 1, (long)"U\n", 2);
    sc(EXIT_GROUP, 7, 0, 0);
    for (;;) {
    }
}
