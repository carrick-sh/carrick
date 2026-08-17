/*
 * stop_the_world.c — differential reproducer for carrick's stop-the-world
 * barrier RAISE decision (as opposed to its drain).
 *
 * What it measures
 * ----------------
 * Carrick raises a process-wide barrier before mutating shared guest state
 * (stage-1 page-table edits, in-process fork). The decision to raise it is
 * keyed on `kicker.count()`, which counts LIVE vCPU LEASES — not the threads
 * that can execute guest code. A sibling parked in a blocking wait has already
 * released its lease, so a two-thread process reads 1 and the barrier stays
 * down while a thread that can be woken at any moment still exists.
 *
 * This fixture holds the WORKLOAD constant and varies only the sibling's park
 * state, so a difference in barrier probes is attributable to the predicate and
 * nothing else:
 *
 *   spin  — the sibling burns guest cycles and never leaves guest. It holds its
 *           vCPU lease, so `kicker.count()` sees it. POSITIVE CONTROL: the
 *           barrier probes must fire. If they do not, the instrument is broken
 *           and no zero elsewhere may be read as evidence.
 *   park  — the sibling blocks in read(2) on a pipe nobody writes until the end.
 *           It is still a guest-code executor (the write at the end wakes it),
 *           but it has released its lease. THE GAP: barrier probes go quiet
 *           while the identical mutation load runs.
 *
 * Workloads:
 *   mmap  — N rounds of mmap/touch/munmap (stage-1 descriptor edits).
 *   fork  — N rounds of fork + _exit + waitpid (the in-process fork transaction).
 *
 * The guest prints its own operation count so a zero probe count is read
 * against a positive, self-reported workload rather than as an empty capture.
 *
 * Build (native arm64 container, static so no loader work perturbs the count):
 *   docker run --rm --platform linux/arm64 -v "$PWD:/w" -w /w gcc:14-bookworm \
 *     gcc -O1 -static -pthread -o stop_the_world stop_the_world.c
 *
 * Usage: stop_the_world <spin|park> <mmap|fork> <iterations>
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int pipefd[2];
static volatile int stop_spin;
static volatile unsigned long spin_counter;

static void *sibling_park(void *unused) {
  char byte;
  (void)unused;
  /* One blocking read. Nothing writes until main is finished, so this thread
   * spends the whole measurement window parked with its vCPU lease released
   * — while remaining fully able to resume and execute guest code. */
  while (read(pipefd[0], &byte, 1) < 0) {
  }
  return NULL;
}

static void *sibling_spin(void *unused) {
  (void)unused;
  /* Pure guest-side work: no syscall, so this thread never leaves guest and
   * never releases its lease. */
  while (!stop_spin) {
    spin_counter++;
  }
  return NULL;
}

static long run_mmap(long iterations) {
  long done = 0;
  for (long i = 0; i < iterations; i++) {
    size_t length = 1024 * 1024;
    void *p = mmap(NULL, length, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
      perror("mmap");
      return done;
    }
    /* Touch the first and last page so the mapping is really materialised. */
    ((volatile char *)p)[0] = 1;
    ((volatile char *)p)[length - 1] = 1;
    if (mprotect(p, length, PROT_READ) != 0) {
      perror("mprotect");
      return done;
    }
    if (munmap(p, length) != 0) {
      perror("munmap");
      return done;
    }
    done++;
  }
  return done;
}

static long run_fork(long iterations) {
  long done = 0;
  for (long i = 0; i < iterations; i++) {
    pid_t child = fork();
    if (child < 0) {
      perror("fork");
      return done;
    }
    if (child == 0) {
      _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
      perror("waitpid");
      return done;
    }
    done++;
  }
  return done;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <spin|park> <mmap|fork> <iterations>\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];
  const char *workload = argv[2];
  long iterations = strtol(argv[3], NULL, 10);

  if (pipe(pipefd) != 0) {
    perror("pipe");
    return 1;
  }

  pthread_t sibling;
  int parked = strcmp(mode, "park") == 0;
  if (!parked && strcmp(mode, "spin") != 0) {
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
  }
  if (pthread_create(&sibling, NULL, parked ? sibling_park : sibling_spin,
                     NULL) != 0) {
    perror("pthread_create");
    return 1;
  }
  /* Let the sibling reach its steady state (parked in read, or spinning in
   * guest) before the measured mutations start. */
  usleep(300 * 1000);

  long done;
  if (strcmp(workload, "mmap") == 0) {
    done = run_mmap(iterations);
  } else if (strcmp(workload, "fork") == 0) {
    done = run_fork(iterations);
  } else {
    fprintf(stderr, "unknown workload %s\n", workload);
    return 2;
  }

  /* Wake / stop the sibling and join, proving it was a live executor all along. */
  stop_spin = 1;
  if (write(pipefd[1], "x", 1) != 1) {
    perror("write");
  }
  pthread_join(sibling, NULL);

  printf("stop-the-world-fixture mode=%s workload=%s ops=%ld spins=%lu\n", mode,
         workload, done, spin_counter);
  fflush(stdout);
  return done == iterations ? 0 : 1;
}
