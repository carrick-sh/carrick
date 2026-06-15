// Async child-exit SIGCHLD lock for the carrick KVM backend (Task 5). Proves
// that a guest which installs a SIGCHLD handler and reaps FROM the handler (an
// event-loop style reap — it NEVER calls a blocking wait4 on the synchronous
// path) is delivered SIGCHLD asynchronously the instant the child exits.
//
// On a KVM guest a fork = separate host processes; carrick must observe the
// child's exit and publish the recorded exit-signal to the recorded parent tid
// (the pump-thread reaper). Before Task 5 this was a no-op on KVM and the parent
// hung forever in its `while (!got) pause()` loop. On HVF the same delivery runs
// off an EVFILT_PROC/NOTE_EXIT kqueue watch.
//
// Behaviour:
//   parent installs an SA_SIGINFO|SA_RESTART SIGCHLD handler that
//     waitpid(-1, &st, WNOHANG)s the zombie and sets `volatile got = 1`;
//   parent forks a child that usleep(50ms)s then _exit(0)s;
//   parent does NOT call wait4 in main — it loops `while (!got) pause()`, then
//     writes exactly "sigchld-ok" and _exit(0)s.
//
// The handler is installed BEFORE the fork so there is no ordering race: the
// child cannot exit before the parent is ready to catch the SIGCHLD. Nothing
// else is written to stdout; the expected output is exactly "sigchld-ok".
// _GNU_SOURCE (before any include) keeps parity with the other in-guest
// fixtures (a future gcc 14+ with hard implicit-decl errors needs the explicit
// feature macro for the POSIX signal/wait surface).
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile sig_atomic_t got = 0;

static void on_chld(int signo, siginfo_t *si, void *uctx) {
  (void)signo;
  (void)si;
  (void)uctx;
  // Reap any exited child WITHOUT blocking (event-loop style). The synchronous
  // wait4 path is deliberately NOT taken in main(): the delivery here must be
  // driven purely by the async SIGCHLD.
  int st;
  while (waitpid(-1, &st, WNOHANG) > 0) {
  }
  got = 1;
}

int main(void) {
  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = on_chld;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGCHLD, &sa, 0))
    return 2;

  pid_t child = fork();
  if (child < 0)
    return 3;
  if (child == 0) {
    // Give the parent a beat to reach the pause() loop, then exit so the
    // parent receives SIGCHLD asynchronously.
    usleep(50 * 1000);
    _exit(0);
  }

  // Parent: spin in pause() until the SIGCHLD handler sets `got`. A bounded
  // fallback loop guards against a wedged run hanging the smoke for its full
  // timeout (each pause() returns -1/EINTR when any signal is delivered).
  for (int i = 0; i < 600 && !got; i++)
    pause();

  if (got) {
    ssize_t _ = write(1, "sigchld-ok", 10);
    (void)_;
    _exit(0);
  }
  return 5;
}
