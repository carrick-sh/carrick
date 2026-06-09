// POSIX-timer fork-inheritance lock for the carrick KVM backend. Proves that a
// forked child does NOT inherit the parent's POSIX per-process timer ids: POSIX
// says a fork child starts with NO inherited timers, so an inherited timer id
// must be unknown in the child (timer_getoverrun -> -1/EINVAL). On the carrick
// KVM backend this is enforced by host_signal::reinit_after_fork, which clears
// the process-global carrick-timer-core registry in the child (the parent's
// timer-fallback threads do not survive fork, so an inherited armed slot would
// have no backing thread anyway).
//
// Behaviour:
//   parent timer_create(CLOCK_MONOTONIC, NULL, &tid) to obtain a timer id (NULL
//     sevp -> SIGALRM default; we never let it fire, so the disposition is moot);
//   parent forks; the CHILD calls timer_getoverrun(tid) on the INHERITED id and
//     requires it to fail with errno == EINVAL (the child inherited no timers),
//     then writes exactly "child-clean" to stdout and _exit(0); any other result
//     is _exit(3);
//   the PARENT reaps the child, confirms ITS OWN timer is still live
//     (timer_getoverrun(tid) >= 0 — the clear only affected the child), and
//     propagates the child's exit status (so the case fails if the child did not
//     observe EINVAL). The parent writes NOTHING to stdout; only the child prints.
//
// _GNU_SOURCE (before any include) exposes the POSIX.1b timer API on glibc
// (timer_create/timer_getoverrun live behind _POSIX_C_SOURCE >= 199309L); declare
// the feature explicitly so a future in-guest gcc does not reject the calls.
// Matches the xproc-sigqueue / proc-directed-nonmain fixture style.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
  timer_t tid;
  if (timer_create(CLOCK_MONOTONIC, NULL, &tid))
    return 2;

  pid_t child = fork();
  if (child < 0)
    return 4;
  if (child == 0) {
    // Child: the inherited timer id must be unknown here (POSIX: no inherited
    // timers across fork). timer_getoverrun on an unknown id fails with EINVAL.
    errno = 0;
    int rc = timer_getoverrun(tid);
    if (rc == -1 && errno == EINVAL) {
      ssize_t _ = write(1, "child-clean", 11);
      (void)_;
      _exit(0);
    }
    _exit(3);
  }

  // Parent: reap the child (EINTR-safe), then confirm its OWN timer survived the
  // child's clear, and propagate the child's exit status.
  int st;
  for (;;) {
    pid_t w = waitpid(child, &st, 0);
    if (w == child)
      break;
    if (w < 0 && errno == EINTR)
      continue;
    return 5;
  }

  // The clear must be child-local: the parent's own id is still live (>= 0).
  if (timer_getoverrun(tid) < 0)
    return 6;

  if (WIFEXITED(st))
    return WEXITSTATUS(st);
  return 7;
}
