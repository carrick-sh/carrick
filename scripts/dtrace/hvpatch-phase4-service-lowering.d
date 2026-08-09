#!/usr/sbin/dtrace -qs
/*
 * Attribute the Darwin lowering of the Phase 4 selected Linux service family:
 * openat (56), newfstatat (79), and mmap (222). This is the narrow follow-up to
 * hvpatch-phase4-whole-cpu.d, not an independent performance benchmark.
 *
 * WHAT IT MEASURES
 * ----------------
 * `hvpatch-syscall-service-begin` arms a host-thread window only for the three
 * selected Linux syscall numbers. While armed, this consumer counts every
 * Darwin syscall, Mach trap, and `vminfo:::as_fault` event.
 * `hvpatch-syscall-service` validates the completed window and retains the
 * runtime's duration; the distinct `hvpatch-syscall-service-clear` marker then
 * retires thread-local state. Every row carries the Linux syscall number;
 * per-task rows additionally retain Linux PID/TID/ASID.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on macOS 27.0 arm64 on 2026-08-09:
 * - carrick*:::hvpatch-syscall-service-begin is four scalar CTF values:
 *   (int32_t guest_pid, int32_t guest_tid, uint32_t asid, uint64_t nr).
 * - carrick*:::hvpatch-syscall-service is five scalar CTF values:
 *   (int32_t guest_pid, int32_t guest_tid, uint32_t asid, uint64_t nr,
 *   uint64_t duration_ns).
 * - carrick*:::hvpatch-syscall-service-clear repeats the four begin scalars
 *   after completion, solely to retire consumer join state deterministically.
 * - syscall:::entry and mach_trap:::entry expose the Darwin operation in
 *   `probefunc`.
 * - vminfo:::as_fault arg2 is the exact 16-KiB host-page base on this build.
 *
 * Linux PID/TID/ASID are multiplexed identities. DTrace pid/tid remain Darwin
 * host identities and are used only to bind host work to the active service.
 * A migrated or malformed window is a capture error, not an unattributed row.
 *
 * PERTURBATION
 * ------------
 * HIGH. Three service probes fire for every host-dispatched Linux syscall;
 * selected windows additionally count every Darwin syscall/Mach trap/fault.
 * Only same-instrument counts, amplification ratios, and rankings are citable.
 * Retain a behavior candidate only with untraced ABBA.
 */

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=64m
#pragma D option dynvarsize=32m

dtrace:::BEGIN
{
    started = timestamp;
    target_exited = 0;
    root_seen = 0;
    timed_out = 0;
    saw_selected = 0;
    saw_nested = 0;
    saw_orphan = 0;
    saw_mismatch = 0;
    errors = 0;
    /* Type thread-local service state before predicates first read it. */
    self->service_active = (int32_t)0;
    self->service_guest_pid = (int32_t)0;
    self->service_guest_tid = (int32_t)0;
    self->service_asid = (uint32_t)0;
    self->service_nr = (uint64_t)0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 56 || (uint64_t)arg3 == 79 || (uint64_t)arg3 == 222)/
{
    this->nested = self->service_active != 0;
    saw_nested = saw_nested || this->nested;
    @service_begin_state[this->nested, (uint64_t)arg3] = count();
    self->service_active = 1;
    self->service_guest_pid = (int32_t)arg0;
    self->service_guest_tid = (int32_t)arg1;
    self->service_asid = (uint32_t)arg2;
    self->service_nr = (uint64_t)arg3;
    saw_selected = 1;
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->service_active/
{
    @host_syscall_count[self->service_nr, probefunc] = count();
    @host_syscall_task[
        self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr, probefunc] = count();
}

mach_trap:::entry
/(pid == $target || progenyof($target)) && self->service_active/
{
    @mach_count[self->service_nr, probefunc] = count();
}

vminfo:::as_fault
/(pid == $target || progenyof($target)) && self->service_active/
{
    @fault_count[self->service_nr] = count();
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 56 || (uint64_t)arg3 == 79 || (uint64_t)arg3 == 222)/
{
    this->active = self->service_active != 0;
    this->identity_match = self->service_guest_pid == (int32_t)arg0 &&
        self->service_guest_tid == (int32_t)arg1 &&
        self->service_asid == (uint32_t)arg2 &&
        self->service_nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @service_end_state[this->active, this->identity_match, (uint64_t)arg3] = count();
    @service_duration_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 56 || (uint64_t)arg3 == 79 || (uint64_t)arg3 == 222)/
{
    this->active = self->service_active != 0;
    this->identity_match = self->service_guest_pid == (int32_t)arg0 &&
        self->service_guest_tid == (int32_t)arg1 &&
        self->service_asid == (uint32_t)arg2 &&
        self->service_nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @service_clear_state[this->active, this->identity_match, (uint64_t)arg3] = count();
    self->service_active = 0;
    self->service_guest_pid = 0;
    self->service_guest_tid = 0;
    self->service_asid = 0;
    self->service_nr = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    root_seen = 1;
}

proc:::lwp-exit
/(pid == $target || progenyof($target)) && self->service_active/
{
    printf("HVPATCH4LOWER|error=thread-exit-active|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu\n",
        pid, tid, self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr);
    exit(2);
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCH4LOWER|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_selected && root_seen ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    timed_out = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCH4LOWER|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|saw_selected=%d|saw_nested=%d|saw_orphan=%d|saw_mismatch=%d|errors=%d\n",
        root_seen && !timed_out && saw_selected && !saw_nested && !saw_orphan &&
            !saw_mismatch && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, saw_selected, saw_nested, saw_orphan,
        saw_mismatch, errors);
    printa("HVPATCH4LOWER|service-begin|nested=%d|nr=%llu|count=%@d\n",
        @service_begin_state);
    printa("HVPATCH4LOWER|service-end|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @service_end_state);
    printa("HVPATCH4LOWER|service-clear|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @service_clear_state);
    printa("HVPATCH4LOWER|service-duration-ns|nr=%llu|value=%@d\n",
        @service_duration_ns);
    printf("HVPATCH4LOWER|section=host-syscalls\n");
    printa("HVPATCH4LOWER|host-syscall|nr=%llu|host=%s|count=%@d\n",
        @host_syscall_count);
    printf("HVPATCH4LOWER|section=host-tasks\n");
    trunc(@host_syscall_task, 160);
    printa("HVPATCH4LOWER|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @host_syscall_task);
    printf("HVPATCH4LOWER|section=mach-traps\n");
    printa("HVPATCH4LOWER|mach|nr=%llu|host=%s|count=%@d\n", @mach_count);
    printa("HVPATCH4LOWER|faults|nr=%llu|count=%@d\n", @fault_count);
}
