#!/usr/sbin/dtrace -qs
/* Node madvise request shape and host lowering, bounded to 90 seconds.
 * Reuses the locally qualified service-window ABI and closure checks from
 * hvpatch-fstat-service-lowering.d. Syscall args ABI is number,arg0..arg3;
 * canonical madvise=233, arg1=length, arg2=advice. Qualify by matching
 * request counts to closed service windows on this host before citing.
 * Counts requested bytes, NOT actual bytes cleared or unique pages.
 * Concurrent windows use per-CPU DTrace aggregation counters. Shared scalar
 * ++ counters lost updates in the first Node capture (2533 vs 2534) and are
 * not closure authority. The capture reader must reconcile aggregate counts.
 * HIGH perturbation: per-service probes plus host syscall/Mach/fault events.
 * Durations are diagnostic only. Use carrick trace --require-script-exit;
 * CLI checks consumer drops, this script checks errors and exact window closure.
 * vminfo as_fault arg2 is host-page base on the qualified Darwin arm64 lane.
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
    saw_host_syscall = 0;
    saw_mach_trap = 0;
    saw_fault = 0;
    saw_nested = 0;
    saw_orphan = 0;
    saw_mismatch = 0;
    errors = 0;
    /* Type thread-local service state before predicates first read it. The
     * values initialize only the BEGIN thread; every worker transitions from
     * an implicit zero to active=1 on its first selected begin, then stays
     * allocated as inactive=2 between windows. */
    self->service_active = (int32_t)0;
    self->service_guest_pid = (int32_t)0;
    self->service_guest_tid = (int32_t)0;
    self->service_asid = (uint32_t)0;
    self->service_nr = (uint64_t)0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 233/
{
    this->nested = self->service_active == 1;
    saw_nested = saw_nested || this->nested;
    @service_begin_state[this->nested, (uint64_t)arg3] = count();
    self->service_active = 1;
    self->service_guest_pid = (int32_t)arg0;
    self->service_guest_tid = (int32_t)arg1;
    self->service_asid = (uint32_t)arg2;
    self->service_nr = (uint64_t)arg3;
    saw_selected = 1;
    @windows["begin"] = count();
}

/* args ABI is (number, arg0, arg1, arg2, arg3). */
carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == 233 && self->service_active == 1/
{
    @request_count[(uint64_t)arg3, (uint64_t)arg2] = count();
    @requested_bytes[(uint64_t)arg3] = sum((uint64_t)arg2);
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->service_active == 1/
{
    saw_host_syscall = 1;
    @host_syscall_count[self->service_nr, probefunc] = count();
    @host_syscall_task[self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr, probefunc] = count();
}

mach_trap:::entry
/(pid == $target || progenyof($target)) && self->service_active == 1/
{
    saw_mach_trap = 1;
    @mach_count[self->service_nr, probefunc] = count();
    @mach_task[self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr, probefunc] = count();
}

vminfo:::as_fault
/(pid == $target || progenyof($target)) && self->service_active == 1/
{
    saw_fault = 1;
    @fault_count[self->service_nr] = count();
    @fault_task[self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr] = count();
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 233/
{
    this->active = self->service_active == 1;
    this->identity_match = self->service_guest_pid == (int32_t)arg0 &&
        self->service_guest_tid == (int32_t)arg1 &&
        self->service_asid == (uint32_t)arg2 &&
        self->service_nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @service_end_state[this->active, this->identity_match, (uint64_t)arg3] = count();
    @service_duration_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
    @windows["end"] = count();
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 233/
{
    this->active = self->service_active == 1;
    this->identity_match = self->service_guest_pid == (int32_t)arg0 &&
        self->service_guest_tid == (int32_t)arg1 &&
        self->service_asid == (uint32_t)arg2 &&
        self->service_nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @service_clear_state[this->active, this->identity_match, (uint64_t)arg3] = count();
    @windows["clear"] = count();
    /* Retain every slot to avoid per-fstat dynamic-variable allocation churn.
     * Identity values are consulted only while active==1 and are overwritten by
     * the next begin on this worker. */
    self->service_active = 2;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    root_seen = 1;
}

proc:::lwp-exit
/(pid == $target || progenyof($target)) && self->service_active == 1/
{
    printf("HVPATCHMADVISESHAPE|error=thread-exit-active|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu\n",
        pid, tid, self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr);
    exit(2);
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCHMADVISESHAPE|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_selected && root_seen && !saw_nested && !saw_orphan &&
        !saw_mismatch && !errors ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    timed_out = 1;
    exit(4);
}

dtrace:::END
{
    printa("HVPATCHMADVISESHAPE|windows|kind=%s|count=%@d\n", @windows);
    printa("HVPATCHMADVISESHAPE|request|advice=%llu|length=%llu|count=%@d\n", @request_count);
    printa("HVPATCHMADVISESHAPE|requested-bytes|advice=%llu|bytes=%@d\n", @requested_bytes);
    printf("HVPATCHMADVISESHAPE|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|saw_selected=%d|saw_host_syscall=%d|saw_mach_trap=%d|saw_fault=%d|saw_nested=%d|saw_orphan=%d|saw_mismatch=%d|errors=%d\n",
        root_seen && !timed_out && saw_selected && !saw_nested && !saw_orphan &&
        !saw_mismatch && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, saw_selected, saw_host_syscall, saw_mach_trap, saw_fault,
        saw_nested, saw_orphan, saw_mismatch, errors);
    printa("HVPATCHMADVISESHAPE|service-begin|nested=%d|nr=%llu|count=%@d\n",
        @service_begin_state);
    printa("HVPATCHMADVISESHAPE|service-end|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @service_end_state);
    printa("HVPATCHMADVISESHAPE|service-clear|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @service_clear_state);
    printa("HVPATCHMADVISESHAPE|service-duration-ns|nr=%llu|value=%@d\n",
        @service_duration_ns);
    printf("HVPATCHMADVISESHAPE|section=host-syscalls\n");
    printa("HVPATCHMADVISESHAPE|host-syscall|nr=%llu|host=%s|count=%@d\n",
        @host_syscall_count);
    printf("HVPATCHMADVISESHAPE|section=host-tasks\n");
    trunc(@host_syscall_task, 160);
    printa("HVPATCHMADVISESHAPE|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @host_syscall_task);
    printf("HVPATCHMADVISESHAPE|section=mach-traps\n");
    printa("HVPATCHMADVISESHAPE|mach|nr=%llu|host=%s|count=%@d\n", @mach_count);
    printf("HVPATCHMADVISESHAPE|section=mach-tasks\n");
    trunc(@mach_task, 160);
    printa("HVPATCHMADVISESHAPE|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @mach_task);
    printf("HVPATCHMADVISESHAPE|section=faults\n");
    printa("HVPATCHMADVISESHAPE|faults|nr=%llu|count=%@d\n", @fault_count);
    printf("HVPATCHMADVISESHAPE|section=fault-tasks\n");
    trunc(@fault_task, 160);
    printa("HVPATCHMADVISESHAPE|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|count=%@d\n",
        @fault_task);
}
