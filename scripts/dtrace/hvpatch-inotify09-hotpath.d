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
 * Host entry/return pairs report elapsed timestamp and on-CPU vtimestamp
 * deltas. Service CPU uses the same vtimestamp clock. Wall time includes
 * tracing perturbation; do not label wall-minus-CPU as pure scheduler delay.
 * The ten-second boundary may censor windows: reconcile begins, completions,
 * clears and open_services, and host counts, returns and open_hosts before
 * comparing populations. complete=1 validates joins, not zero censoring.
 * EL1-only syscalls and VM entry/return outside these service windows are not
 * measured by this script.
 * Join failures emit up to sixteen identity-bearing diagnostics before the
 * existing completeness check rejects the capture; never interpret their
 * aggregate timings as an accepted ranking.
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
    host_mismatch = 0;
    stack_samples = 0;
    join_diagnostics = 0;
    begin_diagnostics = 0;
    self->active = (int32_t)0;
    self->nr = (uint64_t)0;
    self->guest_pid = (int32_t)0;
    self->guest_tid = (int32_t)0;
    self->asid = (uint32_t)0;
    self->host_active = (int32_t)0;
    self->host_name = "";
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64)/
{
    nested = nested || self->active == 1;
    self->active = 1;
    self->guest_pid = (int32_t)arg0;
    self->guest_tid = (int32_t)arg1;
    self->asid = (uint32_t)arg2;
    self->nr = (uint64_t)arg3;
    self->service_cpu_start = vtimestamp;
    @service_begins[self->nr] = count();
    @open_services[self->nr] = sum(1);
    selected++;
    if (begin_diagnostics < 16) {
        printf("INOTIFYHOT1|begin_state|host_pid=%d|host_tid=%d|raw_pid=%d|raw_tid=%d|raw_asid=%u|raw_nr=%llu|active=%d|stored_pid=%d|stored_tid=%d|stored_asid=%u|stored_nr=%llu\n",
            pid, tid, (int32_t)arg0, (int32_t)arg1, (uint32_t)arg2,
            (uint64_t)arg3, self->active, self->guest_pid, self->guest_tid,
            self->asid, self->nr);
        begin_diagnostics++;
    }
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->active == 1/
{
    host_mismatch = host_mismatch || self->host_active == 1;
    self->host_active = 1;
    self->host_name = probefunc;
    self->host_start = timestamp;
    self->host_cpu_start = vtimestamp;
    @host_syscalls[self->nr, probefunc] = count();
    @open_hosts[self->nr, probefunc] = sum(1);
}

syscall:::return
/(pid == $target || progenyof($target)) && self->host_active == 1/
{
    host_mismatch = host_mismatch || self->active != 1 || self->host_name != probefunc;
    @host_returns[self->nr, probefunc] = count();
    @host_wall_ns[self->nr, probefunc] = sum(timestamp - self->host_start);
    @host_cpu_ns[self->nr, probefunc] = sum(vtimestamp - self->host_cpu_start);
    @open_hosts[self->nr, probefunc] = sum(-1);
    self->host_active = 2;
}

syscall::fstat64:entry
/(pid == $target || progenyof($target)) && self->active == 1 && stack_samples < 8/
{
    printf("INOTIFYHOT1|stack|nr=%llu|host=fstat64\n", self->nr);
    ustack(24);
    stack_samples++;
}

syscall::lseek:entry
/(pid == $target || progenyof($target)) && self->active == 1 && self->nr == 64 && stack_samples < 8/
{
    printf("INOTIFYHOT1|stack|nr=64|host=lseek\n");
    ustack(24);
    stack_samples++;
}

carrick*:::hvpatch-syscall-service,
carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64) &&
 (self->active != 1 || self->guest_pid != (int32_t)arg0 ||
  self->guest_tid != (int32_t)arg1 || self->asid != (uint32_t)arg2 ||
  self->nr != (uint64_t)arg3) && join_diagnostics < 16/
{
    printf("INOTIFYHOT1|join_failure|phase=%s|host_pid=%d|host_tid=%d|active=%d|expected_pid=%d|expected_tid=%d|expected_asid=%u|expected_nr=%llu|observed_pid=%d|observed_tid=%d|observed_asid=%u|observed_nr=%llu\n",
        probename, pid, tid, self->active, self->guest_pid, self->guest_tid,
        self->asid, self->nr, (int32_t)arg0, (int32_t)arg1,
        (uint32_t)arg2, (uint64_t)arg3);
    join_diagnostics++;
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64)/
{
    this->matches = self->active == 1 &&
        self->guest_pid == (int32_t)arg0 &&
        self->guest_tid == (int32_t)arg1 &&
        self->asid == (uint32_t)arg2 &&
        self->nr == (uint64_t)arg3;
    mismatch = mismatch || !this->matches;
    host_mismatch = host_mismatch || self->host_active == 1;
    @service_count[(uint64_t)arg3] = count();
    @service_duration_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
    @service_cpu_ns[(uint64_t)arg3] = sum(vtimestamp - self->service_cpu_start);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 27 || (uint64_t)arg3 == 28 ||
  (uint64_t)arg3 == 62 || (uint64_t)arg3 == 64)/
{
    this->matches = self->active == 1 && self->nr == (uint64_t)arg3;
    mismatch = mismatch || !this->matches;
    /* Keep allocated thread-local state; zero-clearing every event caused
     * lost join state in sustained captures. Two means inactive. */
    self->active = 2;
    @service_clears[(uint64_t)arg3] = count();
    @open_services[(uint64_t)arg3] = sum(-1);
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
    exit(errors == 0 && selected > 0 && !nested && !mismatch && !host_mismatch ? 0 : 2);
}

dtrace:::END
{
    this->complete = errors == 0 && selected > 0 && !nested && !mismatch && !host_mismatch;
    printf("INOTIFYHOT1|host_mismatch=%d|boundary_censored=1\n", host_mismatch);
    printf("INOTIFYHOT1|bound_s=%d|selected=%d|nested=%d|mismatch=%d|errors=%d|complete=%d\n",
        BOUND_SECONDS, selected, nested, mismatch, errors, this->complete);
    printa("INOTIFYHOT1|nr=%llu|services=%@d\n", @service_count);
    printa("INOTIFYHOT1|nr=%llu|duration_ns=%@d\n", @service_duration_ns);
    printa("INOTIFYHOT1|nr=%llu|host=%s|count=%@d\n", @host_syscalls);
    printa("INOTIFYHOT1|nr=%llu|begins=%@d\n", @service_begins);
    printa("INOTIFYHOT1|nr=%llu|clears=%@d\n", @service_clears);
    printa("INOTIFYHOT1|nr=%llu|open_services=%@d\n", @open_services);
    printa("INOTIFYHOT1|nr=%llu|service_cpu_ns=%@d\n", @service_cpu_ns);
    printa("INOTIFYHOT1|nr=%llu|host=%s|returns=%@d\n", @host_returns);
    printa("INOTIFYHOT1|nr=%llu|host=%s|wall_ns=%@d\n", @host_wall_ns);
    printa("INOTIFYHOT1|nr=%llu|host=%s|cpu_ns=%@d\n", @host_cpu_ns);
    printa("INOTIFYHOT1|nr=%llu|host=%s|open_hosts=%@d\n", @open_hosts);
}
