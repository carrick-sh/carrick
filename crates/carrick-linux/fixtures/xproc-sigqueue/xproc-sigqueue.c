// Cross-process queued-signal (sigqueue) fidelity lock for the carrick KVM
// backend (Task 8). Proves that a REAL-TIME signal queued from one carrick
// guest process to a SIBLING guest process is delivered into the sibling's
// guest WITH the sender's si_value intact — via the shared MAP_SHARED xsignal
// ring, NOT a native rt_sigqueueinfo (which would not reach the guest).
//
// Behaviour:
//   parent installs an SA_SIGINFO handler for SIGRTMIN that checks
//     si->si_value.sival_int == 0x1234 and, on match, sets a flag;
//   parent forks; the CHILD does
//     union sigval sv; sv.sival_int = 0x1234; sigqueue(getppid(), SIGRTMIN, sv);
//   parent (blocked in pause()) wakes when the handler runs, reaps the child,
//     and writes exactly "val-ok" to stdout iff the payload matched.
//
// The handler is installed BEFORE the fork so there is no ordering race: the
// child cannot deliver SIGRTMIN before the parent is ready to catch it. Nothing
// else is written to stdout; the expected output is exactly "val-ok".
// _GNU_SOURCE (before any include) exposes the POSIX.1b real-time-signal API on
// glibc: SIGRTMIN and sigqueue(3) live behind _POSIX_C_SOURCE >= 199309L. Relying
// on glibc's implicit _DEFAULT_SOURCE happens to work today, but a future in-guest
// gcc (14+, where implicit function declarations are a hard error) would reject
// sigqueue() — declare the feature explicitly. Matches proc-directed-nonmain.c.
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile sig_atomic_t got_val = 0;

static void on_rt(int signo, siginfo_t *si, void *uctx) {
  (void)signo;
  (void)uctx;
  if (si && si->si_value.sival_int == 0x1234)
    got_val = 1;
  else
    got_val = -1;
}

int main(void) {
  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = on_rt;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGRTMIN, &sa, 0))
    return 2;

  pid_t parent = getpid();
  pid_t child = fork();
  if (child < 0)
    return 3;
  if (child == 0) {
    // Give the parent a beat to reach pause(), then queue SIGRTMIN with a
    // sigval payload to the PARENT (a cross-process queued signal).
    usleep(50 * 1000);
    union sigval sv;
    sv.sival_int = 0x1234;
    if (sigqueue(parent, SIGRTMIN, sv))
      _exit(4);
    _exit(0);
  }

  // Parent: block in pause() until the SA_SIGINFO handler runs. A bounded
  // fallback loop guards against a wedged run hanging the smoke for its full
  // timeout (the handler does not exit, so pause() returns -1/EINTR each time).
  for (int i = 0; i < 600 && got_val == 0; i++)
    pause();

  int st;
  (void)waitpid(child, &st, 0);

  if (got_val == 1) {
    ssize_t _ = write(1, "val-ok", 6);
    (void)_;
    return 0;
  }
  return 5;
}
