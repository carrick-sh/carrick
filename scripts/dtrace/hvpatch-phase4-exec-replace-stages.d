#!/usr/sbin/dtrace -qs
/*
 * Attribute the unaccounted host stages inside one-VM hvpatch exec replacement.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-exec-replace-stage exposes scalar CTF types
 * (uint32_t phase, uint64_t elapsed_ns, uint64_t mapping_count,
 * uint64_t mapped_bytes). Stable phase ordinals are 0=alias cleanup,
 * 1=drop old host backings, 2=page-table manager/reset metadata, 3=map new
 * host backings, 4=vCPU register publication, 5=vDSO/mailbox publication,
 * 6=lookup/create immutable private-file artifacts.
 * The script joins the event on its host thread to hvpatch-guest-lifecycle
 * phase 6, preserving Linux guest PID, TID and ASID rather than confusing
 * them with the Darwin tracer PID.
 *
 * Perturbation: six low-frequency USDT firings per successful exec plus the
 * existing lifecycle pair. No syscall, scheduler, or VM-fault provider is
 * armed. Same-instrument ratios are citable; untraced timing remains the
 * performance gate. Zero stage events is an error, never a zero-cost result.
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

carrick*:::hvpatch-exec-replace-stage
/(pid == $target || progenyof($target)) && arg0 <= 6 && self->guest_pid > 0/
{
    events++;
    @stage_count[arg0] = count();
    @stage_total_ns[arg0] = sum(arg1);
    @stage_max_ns[arg0] = max(arg1);
    printf("HVPATCH4REPLACE|stage|host_pid=%d|guest_pid=%d|guest_tid=%d|asid=%u|phase=%u|elapsed_ns=%llu|mappings=%llu|mapped_bytes=%llu\n",
        pid, self->guest_pid, self->guest_tid, self->guest_asid,
        (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3);
}

carrick*:::hvpatch-exec-replace-stage
/(pid == $target || progenyof($target)) && arg0 > 6/
{
    phase_errors++;
}

carrick*:::hvpatch-exec-replace-stage
/(pid == $target || progenyof($target)) && self->guest_pid <= 0/
{
    join_errors++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 && self->guest_pid == (int)arg1/
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
    printf("HVPATCH4REPLACE|summary|begins=%d|completes=%d|events=%d|join_errors=%d|phase_errors=%d|empty=%d|bounded=%d|errors=%d\n",
        begins, completes, events, join_errors, phase_errors, events == 0,
        bounded, errors);
    printa("HVPATCH4REPLACE|stage-count|phase=%u|count=%@d\n", @stage_count);
    printa("HVPATCH4REPLACE|stage-total-ns|phase=%u|ns=%@d\n", @stage_total_ns);
    printa("HVPATCH4REPLACE|stage-max-ns|phase=%u|ns=%@d\n", @stage_max_ns);
}
