#!/usr/sbin/dtrace -qs
/*
 * hvpatch-inotify09-hotpath.d — attribute the four LTP inotify09 services.
 *
 * WHAT IT MEASURES
 * ----------------
 * For Linux inotify_add_watch (27), inotify_rm_watch (28), lseek (62), and
 * write (64), counts completed Carrick service windows, sums their reported
 * duration, and counts Darwin syscalls issued inside each window. The capture
 * is bounded at ten seconds because inotify09 intentionally sustains the loop.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified from carrick-observability/probes.rs and
 * hvpatch-phase4-service-lowering.d on Darwin/arm64, 2026-09-20.
 * service-begin carries guest pid, tid, ASID, and Linux syscall number;
 * service carries the same identity plus duration_ns; service-clear retires
 * the thread-local join state.
 *
 * PERTURBATION
 * ------------
 * HIGH. Three USDT probes fire around each selected service and every Darwin
 * syscall inside it updates an aggregation. Only counts, same-instrument
 * ratios, and rankings are citable; elapsed time and absolute service latency
 * from this capture are diagnostic. A nested or mismatched service join makes
 * the receipt incomplete and invalidates its host-syscall attribution.
 */

#pragma D option quiet
#pragma D option aggsize=32m
#pragma D option dynvarsize=16m

inline int BOUND_SECONDS = 10;

dtrace:::BEGIN
{
    seconds = 0;
    selected = 0;
    errors = 0;
    nested = 0;
    mismatch = 0;
    stack_samples = 0;
    self->active = (int32_t)0;
    self->nr = (uint64_t)0;
    self->guest_pid = (int32_t)0;
    self->guest_tid = (int32_t)0;
    self->asid = (uint32_t)0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64)/
{
    nested = nested || self->active;
    self->active = 1;
    self->guest_pid = (int32_t)arg0;
    self->guest_tid = (int32_t)arg1;
    self->asid = (uint32_t)arg2;
    self->nr = (uint64_t)arg3;
    selected++;
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->active/
{
    @host_syscalls[self->nr, probefunc] = count();
}

syscall::fstat64:entry
/(pid == $target || progenyof($target)) && self->active && stack_samples < 8/
{
    printf("INOTIFYHOT1|stack|nr=%llu|host=fstat64\n", self->nr);
    ustack(24);
    stack_samples++;
}

syscall::lseek:entry
/(pid == $target || progenyof($target)) && self->nr == 64 && stack_samples < 8/
{
    printf("INOTIFYHOT1|stack|nr=64|host=lseek\n");
    ustack(24);
    stack_samples++;
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64)/
{
    this->matches = self->active &&
        self->guest_pid == (int32_t)arg0 &&
        self->guest_tid == (int32_t)arg1 &&
        self->asid == (uint32_t)arg2 &&
        self->nr == (uint64_t)arg3;
    mismatch = mismatch || !this->matches;
    @service_count[(uint64_t)arg3] = count();
    @service_duration_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64)/
{
    this->matches = self->active && self->nr == (uint64_t)arg3;
    mismatch = mismatch || !this->matches;
    self->active = 0;
    self->guest_pid = 0;
    self->guest_tid = 0;
    self->asid = 0;
    self->nr = 0;
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-1s
{
    seconds++;
}

profile:::tick-1s
/seconds >= BOUND_SECONDS/
{
    exit(errors == 0 && selected > 0 && !nested && !mismatch ? 0 : 2);
}

dtrace:::END
{
    this->complete = errors == 0 && selected > 0 && !nested && !mismatch;
    printf("INOTIFYHOT1|bound_s=%d|selected=%d|nested=%d|mismatch=%d|errors=%d|complete=%d\n",
        BOUND_SECONDS, selected, nested, mismatch, errors, this->complete);
    printa("INOTIFYHOT1|nr=%llu|services=%@d\n", @service_count);
    printa("INOTIFYHOT1|nr=%llu|duration_ns=%@d\n", @service_duration_ns);
    printa("INOTIFYHOT1|nr=%llu|host=%s|count=%@d\n", @host_syscalls);
}
