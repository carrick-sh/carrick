// Host-signal pump conformance lock for the carrick KVM backend (timer/signal
// refactor, Task 7). Proves a process-directed SIGTERM is published into the
// shared PROC_PENDING mask + fans out to a thread that delivers the handler.
//
// VARIANT: GUEST-fork-kill. The harness runs each case synchronously, capturing
// stdout, so it cannot easily `kill -TERM` the carrick guest mid-case. Instead
// the guest itself forks a child that `kill(getppid(), SIGTERM)`s the PARENT — a
// guest-issued PROCESS-DIRECTED kill. This exercises the SAME fan-out: the
// dispatcher's kill(2) arm publishes SIGTERM into PROC_PENDING and wakes the
// process; the parent (blocked in pause()) re-checks pending, drains the
// process-directed bit, and runs the handler. Before Task 7 the wake never
// reached the pause()-blocked parent, so the handler did not run.
//
// Behaviour:
//   install a SIGTERM handler that prints "got-term\n" + exit(0)
//   fork: child does kill(getppid(), SIGTERM) then _exit(0)
//   parent: pause() forever, waiting for the handler to fire
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static void on_term(int signo) {
  (void)signo;
  // write(2) is async-signal-safe; printf is not, but a one-shot terminal
  // handler that immediately exits is fine for the fixture. Use write to be
  // strictly correct.
  const char msg[] = "got-term\n";
  ssize_t _ = write(1, msg, sizeof msg - 1);
  (void)_;
  _exit(0);
}

int main(void) {
  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_term;
  if (sigaction(SIGTERM, &sa, 0))
    return 2;

  pid_t parent = getpid();
  pid_t child = fork();
  if (child < 0)
    return 3;
  if (child == 0) {
    // Give the parent a beat to reach pause(), then kill it (process-directed).
    usleep(50 * 1000);
    if (kill(parent, SIGTERM))
      _exit(4);
    _exit(0);
  }

  // Parent: block in pause() until the SIGTERM handler runs and exits. A bounded
  // fallback loop (the handler calls _exit, so we never actually iterate to the
  // end) guards against a wedged run hanging the smoke for its full timeout.
  for (int i = 0; i < 600; i++)
    pause(); // returns -1/EINTR after a (delivered, non-exiting) signal
  // If we get here the handler never ran (the bug this locks): reap + fail.
  int st;
  (void)waitpid(child, &st, 0);
  return 5;
}
