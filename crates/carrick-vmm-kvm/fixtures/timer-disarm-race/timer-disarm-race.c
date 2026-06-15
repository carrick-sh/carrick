#define _GNU_SOURCE
// Disarm-during-fire / retire-on-generation-bump conformance lock for the
// carrick interval-timer fallback (timer/signal shared-core effort). Proves a
// repeating ITIMER_REAL that is DISARMED immediately after arming delivers NO
// late SIGALRM — the fallback thread launched for the arm's generation must
// retire when the disarm bumps the slot generation past it.
//
// Behaviour:
//   Install a SIGALRM handler that sets `late = 1` (and writes a marker to
//   STDERR so a regression is unambiguous; STDOUT stays clean).
//   setitimer(ITIMER_REAL, value=1ms interval=1ms) — arm a repeating timer.
//   setitimer(ITIMER_REAL, value=0 interval=0)      — disarm IMMEDIATELY.
//   nanosleep well past several intervals (100ms).
//   If no SIGALRM arrived: write "no-late-alarm" to STDOUT, _exit(0).
//   Else: _exit(3).
#include <signal.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t late;

static void on_alarm(int s) {
  (void)s;
  late = 1;
  // STDERR marker only; STDOUT must stay clean. Consume the return value so the
  // in-guest gcc (-Wunused-result on write) stays quiet.
  ssize_t n = write(2, "late-alarm", 10);
  (void)n;
}

int main(void) {
  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_alarm;
  if (sigaction(SIGALRM, &sa, 0))
    _exit(2);

  struct itimerval arm;
  arm.it_value.tv_sec = 0;
  arm.it_value.tv_usec = 1000; // 1ms
  arm.it_interval.tv_sec = 0;
  arm.it_interval.tv_usec = 1000; // 1ms repeating
  if (setitimer(ITIMER_REAL, &arm, 0))
    _exit(4);

  // Disarm IMMEDIATELY — the fallback launched for the arm generation must
  // retire on this disarm's generation bump and fire no late SIGALRM.
  struct itimerval off;
  off.it_value.tv_sec = 0;
  off.it_value.tv_usec = 0;
  off.it_interval.tv_sec = 0;
  off.it_interval.tv_usec = 0;
  if (setitimer(ITIMER_REAL, &off, 0))
    _exit(5);

  // Sleep well past several 1ms intervals (100ms). Ignore EINTR and finish the
  // remaining time — though with a correctly disarmed timer there should be no
  // interruption at all.
  struct timespec req = {0, 100 * 1000 * 1000}; // 100ms
  struct timespec rem;
  while (nanosleep(&req, &rem) != 0) {
    req = rem;
  }

  if (late == 0)
    return write(1, "no-late-alarm", 13) == 13 ? 0 : 6;
  _exit(3);
}
