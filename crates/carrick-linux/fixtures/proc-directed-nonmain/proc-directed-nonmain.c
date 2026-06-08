// PROC_PENDING fan-out conformance lock for the carrick KVM backend (timer/
// signal refactor, Task 7). Proves a PROCESS-directed signal whose main thread
// BLOCKS it is delivered to a sibling worker that does NOT block it — Linux's
// thread-group semantics (a process-directed signal runs on any unblocked
// thread).
//
// Behaviour:
//   MAIN thread blocks SIGUSR1 (pthread_sigmask SIG_BLOCK).
//   spawns a WORKER that does NOT block SIGUSR1 and busy-waits on a flag.
//   MAIN: kill(getpid(), SIGUSR1)  — process-directed.
//   The worker's handler must run and set the flag, printing "worker-got-it".
//
// The dispatcher's raise_process_directed routes the signal to the unblocked
// sibling (SignalThread{worker}) and kicks its vCPU; the worker re-checks
// pending at its safe point and delivers the handler. The handler asserts it ran
// on the worker (gettid() == worker_tid), not main.
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile sig_atomic_t worker_ran;
static volatile int worker_ready;
static pid_t worker_tid;

static void h(int s) {
  (void)s;
  if ((pid_t)syscall(SYS_gettid) == worker_tid)
    worker_ran = 1;
}

static void *worker(void *arg) {
  (void)arg;
  worker_tid = (pid_t)syscall(SYS_gettid);
  // The worker must NOT block SIGUSR1: it inherits main's mask at creation, so
  // explicitly UNblock it here.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &set, 0);
  __atomic_store_n(&worker_ready, 1, __ATOMIC_SEQ_CST);
  // Busy-wait so the cross-thread kick delivers at an EL0 safe point (not in a
  // syscall), with a bounded fallback so a wedged run fails fast.
  for (int i = 0; i < 5000 && !worker_ran; i++)
    usleep(1000);
  return 0;
}

int main(void) {
  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_handler = h;
  if (sigaction(SIGUSR1, &sa, 0))
    return 2;

  // MAIN blocks SIGUSR1 — so a process-directed SIGUSR1 must NOT be delivered to
  // main; it must fan out to the unblocked worker.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (pthread_sigmask(SIG_BLOCK, &set, 0))
    return 3;

  pthread_t t;
  if (pthread_create(&t, 0, worker, 0))
    return 4;
  while (!__atomic_load_n(&worker_ready, __ATOMIC_SEQ_CST))
    usleep(1000);
  usleep(20 * 1000); // let the worker enter its busy-wait

  if (kill(getpid(), SIGUSR1)) // process-directed
    return 5;

  if (pthread_join(t, 0))
    return 6;
  if (!worker_ran)
    return 7;
  return write(1, "worker-got-it", 13) == 13 ? 0 : 8;
}
