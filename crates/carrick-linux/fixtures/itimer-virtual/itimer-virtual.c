// itimer-virtual: proves ITIMER_VIRTUAL (guest-CPU itimer) fires off REAL guest
// CPU time on the KVM backend, and ONLY while the guest burns CPU.
//
// Two phases, one process:
//
//   Phase 1 (BUSY): install a SIGVTALRM handler that sets `fired`, arm
//   setitimer(ITIMER_VIRTUAL, it_value=50ms), then busy-spin a volatile loop for
//   ~1s of CPU. ITIMER_VIRTUAL counts guest CPU time, so after ~50ms of spinning
//   the timer must fire -> `fired` becomes 1. This is the Task-6 gap: before the
//   un-gate, CPU itimers never fired on KVM and `fired` stayed 0.
//
//   Phase 2 (IDLE): clear `fired`, re-arm the same 50ms ITIMER_VIRTUAL, then
//   nanosleep ~1s consuming NO CPU. Because no guest CPU is burned, the timer
//   must NOT fire -> `fired` stays 0. (A wall-clock fallback would wrongly fire
//   here; the cpu_timer_decision poll must not.)
//
// Prints "cpu-itimer-ok" + exit 0 iff phase 1 fired AND phase 2 did not.
// Otherwise prints a diagnostic and exits non-zero.
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

static volatile sig_atomic_t fired;
static void h(int s) { (void)s; fired = 1; }

static int arm_virtual_50ms(void) {
    struct itimerval it;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 50000; /* 50ms of guest CPU */
    return setitimer(ITIMER_VIRTUAL, &it, 0);
}

int main(void) {
    struct sigaction sa;
    __builtin_memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    if (sigaction(SIGVTALRM, &sa, 0)) return 2;

    /* ---- Phase 1: busy. Expect the timer to fire. ---- */
    fired = 0;
    if (arm_virtual_50ms()) return 3;

    /* Burn ~1s of CPU via a volatile busy-spin. The volatile sink prevents the
     * compiler from eliminating the loop. We break early once the timer fires
     * so the test does not spin longer than necessary, but cap the iteration
     * count so a stuck timer cannot hang the smoke harness. */
    static volatile uint64_t sink;
    for (uint64_t i = 0; i < 4000000000ULL && !fired; i++) {
        sink = i;
    }
    if (!fired) {
        return write(1, "not-fired", 9) == 9 ? 4 : 8;
    }

    /* Disarm before phase 2 so the residual arm cannot leak across. */
    struct itimerval z;
    __builtin_memset(&z, 0, sizeof z);
    setitimer(ITIMER_VIRTUAL, &z, 0);

    /* ---- Phase 2: idle. Expect the timer NOT to fire. ---- */
    fired = 0;
    if (arm_virtual_50ms()) return 5;

    /* Sleep ~1s consuming no CPU. nanosleep is restarted across any spurious
     * wake so we sleep the full second. */
    struct timespec req = {1, 0};
    while (nanosleep(&req, &req) == -1) {
        /* keep sleeping out the remainder */
    }

    /* Disarm. */
    setitimer(ITIMER_VIRTUAL, &z, 0);

    if (fired) {
        return write(1, "fired-idle", 10) == 10 ? 6 : 9;
    }

    return write(1, "cpu-itimer-ok", 13) == 13 ? 0 : 7;
}
