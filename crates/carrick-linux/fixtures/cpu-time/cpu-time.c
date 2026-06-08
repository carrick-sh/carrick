// cpu-time: verifies that guest CPU time is accounted by the KVM backend.
//
// Burns ~100ms of CPU via a volatile busy-spin, then calls times(2) to read
// tms_utime + tms_stime. If any CPU time was charged, prints "cpu-ok" and
// exits 0; otherwise prints "cpu-zero" and exits 1.
//
// The check uses times(2) rather than getrusage because times(2) is simpler
// (no struct padding, just four clock_t fields) and sufficient to prove that
// carrick_host::guest_cpu::begin_active/finish_active are wiring up the KVM
// run loop correctly. On a working KVM backend with the guest_cpu wrap in
// place, tms_utime will be > 0 after 100ms of busy execution.
#include <sys/times.h>
#include <unistd.h>
#include <stdint.h>

int main(void) {
    /* Busy-spin for ~100ms of CPU time. The volatile prevents the compiler
     * from eliminating the loop; the counter itself has no side-effects. */
    static volatile uint64_t sink;
    /* Spin count calibrated conservatively: 500M simple increments at even
     * 1 GHz takes 500ms, so 30M is well under 100ms on any KVM host. We just
     * need enough CPU time that times(2) reports at least 1 clock tick. */
    for (uint64_t i = 0; i < 30000000ULL; i++) {
        sink = i;
    }

    struct tms t;
    if (times(&t) == (clock_t)-1)
        return 2;

    if (t.tms_utime > 0 || t.tms_stime > 0) {
        return write(1, "cpu-ok", 6) == 6 ? 0 : 3;
    } else {
        return write(1, "cpu-zero", 8) == 8 ? 1 : 3;
    }
}
