#!/usr/sbin/dtrace -qs
/*
 * Attribute the outer runtime work between a loaded hvpatch exec image and
 * publication to the Linux guest.
 *
 * Provider ABI declared by carrick-observability for Darwin/arm64:
 * carrick*:::hvpatch-exec-runtime-stage carries four scalar CTF arguments:
 *   uint32_t phase       (0=proc state, 1=close-on-exec, 2=sibling drain,
 *                         3=topology-lock acquisition, 4=engine replacement,
 *                         5=runtime publication; append-only)
 *   uint64_t elapsed_ns
 *   uint64_t image_regions
 *   uint64_t mapped_bytes
 * Phase 4 encloses the separate non-overlapping
 * hvpatch-exec-replace-stage inner ledger; do not sum the two ledgers as peer
 * stages. The lifecycle join retains Linux guest PID, TID, and ASID rather
 * than confusing them with the Darwin host PID.
 *
 * Perturbation: six low-frequency scalar USDT firings per successful exec plus
 * the existing lifecycle pair. No syscall, scheduler, or fault provider is
 * armed. A valid cold-build capture has six records for each of 67 completed
 * execs, with no join/phase/coverage errors. Zero events is invalid evidence.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    begins = 0;
    completes = 0;
    events = 0;
    join_errors = 0;
    phase_errors = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{
    begins++;
    self->guest_pid = (int)arg1;
    self->guest_tid = (int)arg3;
    self->guest_asid = (uint32_t)arg4;
}

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && arg0 <= 5 && self->guest_pid > 0/
{
    events++;
    @stage_count[(uint32_t)arg0] = count();
    @stage_total_ns[(uint32_t)arg0] = sum((uint64_t)arg1);
    @stage_max_ns[(uint32_t)arg0] = max((uint64_t)arg1);
    printf("HVPATCH4RUNTIME|stage|host_pid=%d|guest_pid=%d|guest_tid=%d|asid=%u|phase=%u|elapsed_ns=%llu|regions=%llu|mapped_bytes=%llu\n",
        pid, self->guest_pid, self->guest_tid, self->guest_asid,
        (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3);
}

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && arg0 > 5/
{
    phase_errors++;
}

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->guest_pid <= 0/
{
    join_errors++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 &&
 self->guest_pid == (int)arg1/
{
    completes++;
    self->guest_pid = 0;
    self->guest_tid = 0;
    self->guest_asid = 0;
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    this->coverage_errors = begins != completes || events != completes * 6;
    printf("HVPATCH4RUNTIME|summary|begins=%d|completes=%d|events=%d|join_errors=%d|phase_errors=%d|coverage_errors=%d|empty=%d|bounded=%d|errors=%d\n",
        begins, completes, events, join_errors, phase_errors,
        this->coverage_errors, events == 0, bounded, errors);
    printa("HVPATCH4RUNTIME|stage-count|phase=%u|count=%@d\n", @stage_count);
    printa("HVPATCH4RUNTIME|stage-total-ns|phase=%u|ns=%@d\n", @stage_total_ns);
    printa("HVPATCH4RUNTIME|stage-max-ns|phase=%u|ns=%@d\n", @stage_max_ns);
}
