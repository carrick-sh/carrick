// Reducers for #2668 and #2701: see build.sh for the modes and how to run them.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void say(const char *s) { write(1, s, strlen(s)); }
static volatile sig_atomic_t hit;
static volatile uintptr_t hit_addr;
static volatile int hit_code;
#include <setjmp.h>
#include <sched.h>
static sigjmp_buf env;
static void on_segv(int sig, siginfo_t *si, void *uc) {
  (void)sig; (void)uc;
  hit = 1; hit_addr = (uintptr_t)si->si_addr; hit_code = si->si_code;
  siglongjmp(env, 1);
}

static pid_t spawn(int hold_fd[2], int do_exec) {
  if (pipe(hold_fd)) { perror("pipe"); _exit(90); }
  pid_t c = fork();
  if (c < 0) { printf("fork errno=%d\n", errno); fflush(stdout); _exit(91); }
  if (c == 0) {
    close(hold_fd[1]);
    char b;
    read(hold_fd[0], &b, 1); // stay alive until the parent releases us
    if (do_exec) { execl("/bin/true", "true", (char *)0); _exit(92); }
    _exit(7);
  }
  close(hold_fd[0]);
  return c;
}
static int reap(pid_t c, int hold_fd[2]) {
  close(hold_fd[1]);
  int st = 0;
  if (waitpid(c, &st, 0) != c) return -1;
  return st;
}

static int t_rwx(void) {
  unsigned char *p = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) { say("mmap failed\n"); return 2; }
  p[0] = 0x11;
  int h[2];
  pid_t c = spawn(h, 0);
  say("rwx: write with child alive\n");
  p[1] = 0x22;
  say("rwx: alive write ok\n");
  int st = reap(c, h);
  printf("rwx: child status %#x\n", st); fflush(stdout);
  p[2] = 0x33;
  if (p[0] != 0x11 || p[1] != 0x22 || p[2] != 0x33) return 3;
  say("rwx: PASS\n");
  return 0;
}

static int alt_touch;
static int t_kw(int rwx) {
  // kernel copy-out into a pre-fork-touched page the parent has not written since the fork
  size_t len = 1 << 20;
  char *p = mmap(0, len, PROT_READ | PROT_WRITE | (rwx ? PROT_EXEC : 0), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(p, 0x5a, len);
  int fds[2]; if (pipe(fds)) return 2;
  int h[2];
  pid_t c = spawn(h, 0);
  if (write(fds[1], "abcdefgh", 8) != 8) return 3;
  long n = read(fds[0], p + 4096 * 3 + 5, 8);
  printf("kw: alive read=%ld errno=%d\n", n, n < 0 ? errno : 0); fflush(stdout);
  if (n != 8 || memcmp(p + 4096 * 3 + 5, "abcdefgh", 8) || p[4096 * 3 + 4] != 0x5a) return 4;
  reap(c, h);
  if (write(fds[1], "ABCDEFGH", 8) != 8) return 5;
  n = read(fds[0], p + 4096 * 9 + 5, 8);
  printf("kw: reaped read=%ld errno=%d\n", n, n < 0 ? errno : 0); fflush(stdout);
  if (n != 8 || memcmp(p + 4096 * 9 + 5, "ABCDEFGH", 8)) return 6;
  // straddle two COW pages
  if (write(fds[1], "12345678", 8) != 8) return 7;
  n = read(fds[0], p + 4096 * 20 - 3, 8);
  if (n != 8 || memcmp(p + 4096 * 20 - 3, "12345678", 8)) return 8;
  say("kw: PASS\n");
  return 0;
}

static volatile sig_atomic_t chld;
static void on_chld(int sig) { (void)sig; char probe[256]; probe[0] = 1; chld = probe[0]; }
// A region whose first page is touched before the fork: its neighbours are
// mapped and never touched, so the kernel must make them resident itself.
static char *sparse(size_t len) {
  char *p = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p != MAP_FAILED) p[0] = 1;
  return p;
}
static int t_chld(void) {
  char *stk = sparse(256 << 10);
  stack_t ss = {.ss_sp = stk + 4096, .ss_size = 60 << 10, .ss_flags = 0};
  if (sigaltstack(&ss, 0)) return 2;
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_chld; sa.sa_flags = SA_ONSTACK;
  sigaction(SIGCHLD, &sa, 0);
  pid_t c = fork();
  if (c == 0) _exit(7);
  int st = 0;
  while (waitpid(c, &st, 0) != c) {}
  for (int i = 0; i < 1000 && !chld; i++) sched_yield();
  printf("chld: handler=%d status=%#x\n", (int)chld, st); fflush(stdout);
  if (!chld) return 3;
  say("chld: PASS\n");
  return 0;
}
static int t_kwp(void) {
  char *p = sparse(256 << 10);
  int fds[2]; if (pipe(fds)) return 2;
  int h[2];
  pid_t c = spawn(h, 0);
  if (write(fds[1], "abcdefgh", 8) != 8) return 3;
  long n = read(fds[0], p + 4096 * 3 + 5, 8);
  printf("kwp: alive read=%ld errno=%d\n", n, n < 0 ? errno : 0); fflush(stdout);
  if (n != 8 || memcmp(p + 4096 * 3 + 5, "abcdefgh", 8)) return 4;
  reap(c, h);
  if (write(fds[1], "ABCDEFGH", 8) != 8) return 5;
  n = read(fds[0], p + 4096 * 9 + 5, 8);
  printf("kwp: reaped read=%ld errno=%d\n", n, n < 0 ? errno : 0); fflush(stdout);
  if (n != 8 || memcmp(p + 4096 * 9 + 5, "ABCDEFGH", 8)) return 6;
  say("kwp: PASS\n");
  return 0;
}
static int alt_sparse;

static int t_alt(void) {
  static char stk[65536];
  if (alt_touch) memset(stk, 0x77, sizeof stk);
  stack_t ss = {.ss_sp = stk, .ss_size = sizeof stk, .ss_flags = 0};
  if (alt_sparse) { ss.ss_sp = sparse(256 << 10) + 4096; ss.ss_size = 60 << 10; }
  if (sigaltstack(&ss, 0)) { perror("sigaltstack"); return 2; }
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = on_segv;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  sigaction(SIGSEGV, &sa, 0);
  int h[2];
  pid_t c = spawn(h, 0);
  if (!sigsetjmp(env, 1)) { *(volatile int *)0x10 = 1; }
  printf("alt: alive hit=%d addr=%#lx code=%d\n", (int)hit, (unsigned long)hit_addr, hit_code); fflush(stdout);
  if (!hit || hit_addr != 0x10) return 3;
  hit = 0;
  reap(c, h);
  if (!sigsetjmp(env, 1)) { *(volatile int *)0x20 = 1; }
  printf("alt: reaped hit=%d addr=%#lx code=%d\n", (int)hit, (unsigned long)hit_addr, hit_code); fflush(stdout);
  if (!hit || hit_addr != 0x20) return 4;
  say("alt: PASS\n");
  return 0;
}

static int t_brk(int do_exec) {
  char *base = sbrk(0);
  // touch some heap before the fork
  if (sbrk(1 << 20) == (void *)-1) return 2;
  for (size_t i = 0; i < (1 << 20); i += 4096) base[i] = 1;
  char *m0 = mmap(0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  for (size_t i = 0; i < (1 << 20); i += 4096) m0[i] = 1;
  for (int round = 0; round < 2; round++) {
    int h[2];
    pid_t c = spawn(h, do_exec);
    if (round == 1) reap(c, h);
    // grow brk by 24 MiB in 128 KiB steps, one byte per page: crosses 2 MiB boundaries.
    for (int step = 0; step < 96; step++) {
      char *old = sbrk(128 << 10);
      if (old == (void *)-1) { printf("brk: sbrk errno=%d\n", errno); fflush(stdout); return 5; }
      for (size_t i = 0; i < (128 << 10); i += 4096) old[i] = (char)step;
    }
    say("brk: heap growth ok\n");
    for (int k = 0; k < 16; k++) {
      size_t len = (k & 1) ? (1 << 20) : (256 << 10);
      char *m = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (m == MAP_FAILED) { printf("brk: mmap errno=%d\n", errno); fflush(stdout); return 6; }
      for (size_t i = 0; i < len; i += 4096) m[i] = (char)k;
      if (k % 3 == 0) munmap(m, len);
    }
    say("brk: fresh mmap ok\n");
    if (round == 0) reap(c, h);
  }
  say("brk: PASS\n");
  return 0;
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "rwx";
  int direct = argc > 2;
  if (!direct) {
    // run the test in a forked child so it is a native child
    pid_t c = fork();
    if (c == 0) {
      execl("/proc/self/exe", argv[0], mode, "direct", (char *)0);
      // fall through: run in the fork child itself
    } else {
      int st;
      waitpid(c, &st, 0);
      printf("launcher: mode=%s status=%#x\n", mode, st);
      return st ? 1 : 0;
    }
  }
  if (!strcmp(mode, "rwx")) return t_rwx();
  if (!strcmp(mode, "alt")) return t_alt();
  if (!strcmp(mode, "altt")) { alt_touch = 1; return t_alt(); }
  if (!strcmp(mode, "altp")) { alt_sparse = 1; return t_alt(); }
  if (!strcmp(mode, "chld")) return t_chld();
  if (!strcmp(mode, "kwp")) return t_kwp();
  if (!strcmp(mode, "kw")) return t_kw(0);
  if (!strcmp(mode, "kwx")) return t_kw(1);
  if (!strcmp(mode, "brk")) return t_brk(0);
  if (!strcmp(mode, "brkx")) return t_brk(1);
  return 64;
}
