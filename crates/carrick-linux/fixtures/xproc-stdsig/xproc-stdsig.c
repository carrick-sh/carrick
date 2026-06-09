// Cross-process STANDARD-signal disposition-mirroring lock for the carrick KVM
// backend (Task 6). Proves that a sibling guest process's kill() of a STANDARD
// catchable signal (SIGUSR1) RUNS the receiver's installed handler, and its
// kill() of a SIG_IGN'd standard signal (SIGUSR2) is DROPPED — instead of the
// host default action TERMINATING the receiving carrick process.
//
// This is the CPython test_interprocess_signal / LTP kill02 case. It is
// NON-namespaced (plain run-elf, no pid-ns), so a guest kill(target, SIGUSR1/2)
// of a standard signal takes the host-kill path (libc::kill of the host signum),
// NOT the cross-process xsignal ring. On a KVM guest a fork = SEPARATE host
// processes; the receiver carrick process installs NO host handler for SIGUSR1
// by default, so the host SIGUSR1 took its DEFAULT action and TERMINATED the
// receiver before any guest handler ran (and a guest SIG_IGN of SIGUSR2 was not
// mirrored to the host, so a sibling's kill killed the parent there too). Task 6
// makes KVM install REAL host routed handlers mirroring the guest disposition.
//
// Behaviour:
//   parent installs sigaction(SIGUSR1, {sa_handler=h1}) where h1 sets a flag;
//   parent signal(SIGUSR2, SIG_IGN) — ignore SIGUSR2;
//   parent forks; the CHILD does
//     kill(getppid(), SIGUSR2);  // must be DROPPED — parent ignores it
//     kill(getppid(), SIGUSR1);  // must RUN h1
//     _exit(0);
//   parent (blocked in pause()) wakes when h1 runs, reaps the child, and writes
//     exactly "usr1-ok". The SIG_IGN of SIGUSR2 is proven by the parent
//     SURVIVING the SIGUSR2 (a non-mirrored ignore would let the sibling kill
//     host-default-terminate the parent before SIGUSR1 ever arrived).
//
// Both dispositions are set BEFORE the fork so there is no ordering race: the
// child cannot deliver either signal before the parent is ready. Nothing else is
// written to stdout; the expected output is exactly "usr1-ok".
// _GNU_SOURCE (before any include) keeps parity with the other in-guest fixtures
// (a future gcc 14+ with hard implicit-decl errors needs the explicit feature
// macro for the POSIX signal/wait surface).
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile sig_atomic_t got_usr1 = 0;

static void on_usr1(int signo) {
  (void)signo;
  ssize_t _ = write(1, "usr1-ok", 7);
  (void)_;
  got_usr1 = 1;
}

int main(void) {
  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGUSR1, &sa, 0))
    return 2;
  // Ignore SIGUSR2: a sibling's kill of it must be DROPPED, not terminate us.
  if (signal(SIGUSR2, SIG_IGN) == SIG_ERR)
    return 3;

  pid_t parent = getpid();
  pid_t child = fork();
  if (child < 0)
    return 4;
  if (child == 0) {
    // Give the parent a beat to reach pause(), then send the two standard
    // signals to the PARENT (cross-process kills on the host-kill path).
    usleep(50 * 1000);
    // SIGUSR2 first: it must be dropped (parent ignores it). If KVM did not
    // host-ignore it, the parent would die here and never print usr1-ok.
    kill(parent, SIGUSR2);
    usleep(20 * 1000);
    // SIGUSR1: must run the parent's handler.
    kill(parent, SIGUSR1);
    _exit(0);
  }

  // Parent: block in pause() until on_usr1 sets the flag. A bounded fallback
  // loop guards against a wedged run hanging the smoke for its full timeout
  // (pause() returns -1/EINTR on each delivery; the handler does not exit).
  for (int i = 0; i < 600 && !got_usr1; i++)
    pause();

  int st;
  (void)waitpid(child, &st, 0);

  // The handler already wrote "usr1-ok" on delivery; exit 0 iff it ran (and
  // therefore the parent SURVIVED the prior SIGUSR2 — the SIG_IGN mirror works).
  if (got_usr1)
    _exit(0);
  return 5;
}
