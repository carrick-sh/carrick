#!/usr/sbin/dtrace -qs
/*
 * Attribute and validate the six outer runtime stages between a loaded
 * HVPatch exec image and publication to the Linux guest.
 *
 * Provider ABI qualified from carrick-observability on Darwin/arm64:
 * carrick*:::hvpatch-exec-runtime-stage carries four scalars:
 *   uint32_t phase       (0=proc state, 1=close-on-exec, 2=sibling drain,
 *                         3=topology lock, 4=engine replacement,
 *                         5=publication; append-only)
 *   uint64_t elapsed_ns
 *   uint64_t image_regions
 *   uint64_t mapped_bytes
 *
 * Phase 4 encloses the separate non-overlapping
 * hvpatch-exec-replace-stage inner ledger. The lifecycle join keeps Linux
 * guest PID/TID/ASID distinct from Darwin host PID/TID.
 *
 * Perturbation: six low-frequency scalar USDT firings per successful exec,
 * plus begin/complete lifecycle records. No syscall, scheduler, fault, or
 * instruction-hot-path provider is armed. This producer and its strict Rust
 * consumer reject zero events, a missing ordinal, a duplicate phase, an
 * unbalanced begin/complete, timeout, provider errors, DTrace drops, libdtrace
 * consumer drops, interruption, or nonzero target exit.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    exec_sequence = 0;
    begins = 0;
    completes = 0;
    events = 0;
    phase0 = 0;
    phase1 = 0;
    phase2 = 0;
    phase3 = 0;
    phase4 = 0;
    phase5 = 0;
    join_errors = 0;
    phase_errors = 0;
    duplicate_errors = 0;
    completion_errors = 0;
    lifecycle_errors = 0;
    bounded = 0;
    errors = 0;
    drops = 0;
    target_exited = 0;
    target_exit_seen = 0;
    target_exit_code = -1;
    target_exit_reason = 0;
    printf("HVPATCH4RUNTIME|header|version=1\n");
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{
    begins++;
    exec_sequence++;
    self->exec_sequence = exec_sequence;
    self->active = 1;
    self->guest_pid = (int)arg1;
    self->guest_tid = (int)arg3;
    self->guest_asid = (uint32_t)arg4;
    self->event_count = 0;
    self->phase_mask = 0;
    printf("HVPATCH4RUNTIME|begin|host_pid=%d|host_tid=%d|exec_sequence=%u|guest_pid=%d|guest_tid=%d|asid=%u\n",
        pid, tid, self->exec_sequence, self->guest_pid, self->guest_tid,
        self->guest_asid);
}

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 <= 5/
{
    this->bit = (uint64_t)1 << (uint32_t)arg0;
    duplicate_errors += (self->phase_mask & this->bit) != 0;
    self->phase_mask |= this->bit;
    self->event_count++;
    events++;
    printf("HVPATCH4RUNTIME|stage|host_pid=%d|host_tid=%d|exec_sequence=%u|guest_pid=%d|guest_tid=%d|asid=%u|phase=%u|elapsed_ns=%llu|regions=%llu|mapped_bytes=%llu\n",
        pid, tid, self->exec_sequence, self->guest_pid, self->guest_tid,
        self->guest_asid, (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3);
}

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 == 0/
{ phase0++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 == 1/
{ phase1++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 == 2/
{ phase2++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 == 3/
{ phase3++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 == 4/
{ phase4++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && self->active && arg0 == 5/
{ phase5++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && arg0 > 5/
{ phase_errors++; }

carrick*:::hvpatch-exec-runtime-stage
/(pid == $target || progenyof($target)) && !self->active/
{ join_errors++; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 &&
 (!self->active || self->guest_pid != (int)arg1)/
{ completion_errors++; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 && self->active &&
 self->guest_pid == (int)arg1/
{
    completion_errors += self->event_count != 6 || self->phase_mask != 63;
    completes++;
    printf("HVPATCH4RUNTIME|complete|host_pid=%d|host_tid=%d|exec_sequence=%u|guest_pid=%d|guest_tid=%d|asid=%u\n",
        pid, tid, self->exec_sequence, self->guest_pid, self->guest_tid,
        self->guest_asid);
    self->active = 0;
    self->guest_pid = 0;
    self->guest_tid = 0;
    self->guest_asid = 0;
    self->event_count = 0;
    self->phase_mask = 0;
    self->exec_sequence = 0;
}

dtrace:::DROP
{
    drops++;
}

dtrace:::ERROR
{
    errors++;
    exit(3);
}

syscall::exit:entry
/pid == $target/
{
    target_exit_seen = 1;
    target_exit_code = (int)arg0;
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    target_exit_reason = arg0;
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    this->valid = begins > 0 && begins == completes && events == completes * 6 &&
        phase0 == completes && phase1 == completes && phase2 == completes &&
        phase3 == completes && phase4 == completes && phase5 == completes &&
        join_errors == 0 && phase_errors == 0 && duplicate_errors == 0 &&
        completion_errors == 0 && lifecycle_errors == 0 && bounded == 0 &&
        errors == 0 && drops == 0 && target_exited == 1 &&
        target_exit_seen == 1 && target_exit_code == 0;
    printf("HVPATCH4RUNTIME|summary|status=%s|begins=%d|completes=%d|events=%d|phase0=%d|phase1=%d|phase2=%d|phase3=%d|phase4=%d|phase5=%d|join_errors=%d|phase_errors=%d|duplicate_errors=%d|completion_errors=%d|lifecycle_errors=%d|empty=%d|bounded=%d|errors=%d|drops=%d|target_exited=%d|target_exit_seen=%d|target_exit_code=%d|target_exit_reason=%d\n",
        this->valid ? "ok" : "error", begins, completes, events, phase0, phase1,
        phase2, phase3, phase4, phase5, join_errors, phase_errors,
        duplicate_errors, completion_errors, lifecycle_errors, events == 0,
        bounded, errors, drops, target_exited, target_exit_seen, target_exit_code,
        target_exit_reason);
}
