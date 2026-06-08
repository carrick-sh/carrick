// si_pid regression lock for the carrick KVM backend (Phase 2 / signal refactor
// Task 2). Proves the dispatcher's siginfo-queue path supplies the SENDER's pid
// in siginfo->si_pid for a self-directed kill(2) with an SA_SIGINFO handler.
//
// This is NOT the async last_sender_for path (which is correctly 0 on KVM — KVM
// has no host-signal pump yet, Task 7). It is the GUEST-issued send: glibc's
// kill(getpid(),SIGUSR1) lowers to the kill(2)/rt_sigqueueinfo dispatcher arm,
// which queues an SI_USER siginfo carrying the caller's (== this guest's) pid;
// the generic loop then injects that exact siginfo into the handler's frame.
//
// Behaviour:
//   install SIGUSR1 handler (SA_SIGINFO)
//   kill(getpid(), SIGUSR1)
//   in handler: read si->si_pid, assert it == getpid() (and non-zero)
//   print "sender-pid-ok", exit(0)
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t got_pid;

static void handler(int signo, siginfo_t *si, void *uc) {
  (void)signo;
  (void)uc;
  got_pid = si->si_pid;
}

int main(void) {
  pid_t me = getpid();

  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGUSR1, &sa, 0))
    return 2;

  if (kill(me, SIGUSR1))
    return 3;

  // The handler must have run synchronously by the time kill() returns.
  if (got_pid == 0) /* a missing si_pid (the bug this locks) reads back 0 */
    return 4;
  if (got_pid != me) /* si_pid must be the sender == this process */
    return 5;

  // Print the observed sender pid for the trace, then the success token.
  printf("si_pid=%d getpid=%d\n", (int)got_pid, (int)me);
  printf("sender-pid-ok\n");
  return 0;
}
