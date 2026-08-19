/* shared-futex-fork-ladder.c — where does LTP futex_cmp_requeue01's time go?
 *
 * The suite forks N children that park in a MAP_SHARED FUTEX_WAIT, then walks
 * /proc/<pid>/stat for EVERY child until it reads 'S' — `TST_PROCESS_STATE_WAIT
 * (pid,'S',0)`, a 1 ms poll with NO timeout — and only THEN issues the requeue.
 * A child's own wait deadline is 5000 ms, so if fork+scan exceeds that, every
 * child has already left the futex when the requeue lands and the requeue
 * truthfully reports 0.
 *
 * That is exactly what the current artifact does: test 3 (100 waiters, wake 50
 * / requeue 50) returns 100 and PASSES, and test 4 (100 waiters, wake 0 /
 * requeue 70) — same waiter count, later in the run — returns 0 with 0 children
 * woken. Same size, different cumulative load, opposite outcome. So the thing
 * to measure is the two PRE-REQUEUE phases, not the requeue.
 *
 * This reducer reproduces only those two phases. There is no requeue at all, so
 * a collapse here cannot be futex semantics: it is fork admission or /proc.
 *
 * Two suspected costs, both structural:
 *   1. A shared-futex wait KEEPS its HVF vCPU lease when the pool looks spare
 *      (`vcpu_loop/threads.rs:490` -> `should_keep_vcpu_for_blocking_wait`,
 *      `vcpu_loop/mod.rs:137`), while the PRIVATE futex path reclaims
 *      unconditionally (`threads.rs:263`) with a comment describing this exact
 *      workload. So the first ~budget waiters strand the pool and the fork loop
 *      serializes on one circulating slot.
 *   2. /proc/<pid>/stat rebuilds a whole-carrier census per read
 *      (`kernel/core.rs:1095` live_processes, `:1116` oom_score_adj_by_pid) and
 *      then finds the pid by linear scan (`vfs/proc.rs:3403`) — Theta(N) work
 *      per call, issued N times.
 *
 * RED: fork_ms shows a knee near the vCPU budget and/or scan_ms is
 * super-linear in n. GREEN (and Docker): both are linear and small.
 *
 * Build:  aarch64 gcc/musl-gcc -O2 -o ladder shared-futex-fork-ladder.c
 * Run under carrick and under the native-arm64 Docker oracle, one at a time.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Far longer than the phases being timed, so no child can time out and
 * zombify mid-measurement — the zombie is what makes LTP's scan hang, and
 * here we want the phase costs, not the hang. */
#define CHILD_TIMEOUT_SECS 300
#define SCAN_BOUND_MS 20000

static const int LADDER[] = {32, 64, 128, 256};

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Field 3 of /proc/<pid>/stat, i.e. the first char after the ')' that ends comm. */
static int stat_state(int pid) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *close_paren = strrchr(buf, ')');
    if (!close_paren) return -1;
    char *p = close_paren + 1;
    while (*p == ' ') p++;
    return (unsigned char)*p;
}

int main(void) {
    for (unsigned li = 0; li < sizeof LADDER / sizeof LADDER[0]; li++) {
        int n = LADDER[li];
        unsigned int *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (word == MAP_FAILED) { printf("n=%d map=failed\n", n); return 2; }
        *word = 0;

        int *pids = calloc((size_t)n, sizeof(int));
        long t0 = now_ms();
        for (int i = 0; i < n; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                struct timespec to = { CHILD_TIMEOUT_SECS, 0 };
                /* No FUTEX_PRIVATE_FLAG: this is the SHARED wait path. */
                syscall(SYS_futex, word, FUTEX_WAIT, 0u, &to, NULL, 0);
                _exit(0);
            }
            pids[i] = (int)pid;
        }
        long fork_ms = now_ms() - t0;

        /* TST_PROCESS_STATE_WAIT(pid, 'S', 0), bounded so we report not hang. */
        long t1 = now_ms();
        long polls = 0;
        int stuck = 0;
        for (int i = 0; i < n && !stuck; i++) {
            long deadline = now_ms() + SCAN_BOUND_MS;
            for (;;) {
                polls++;
                if (stat_state(pids[i]) == 'S') break;
                if (now_ms() >= deadline) { stuck = pids[i]; break; }
                usleep(1000);
            }
        }
        long scan_ms = now_ms() - t1;

        printf("n=%d fork_ms=%ld scan_ms=%ld polls=%ld stuck_pid=%d\n",
               n, fork_ms, scan_ms, polls, stuck);
        fflush(stdout);

        *word = 1;
        syscall(SYS_futex, word, FUTEX_WAKE, 0x7fffffff, NULL, NULL, 0);
        for (int i = 0; i < n; i++) {
            int st;
            waitpid(pids[i], &st, 0);
        }
        free(pids);
        munmap(word, 4096);
    }
    return 0;
}
