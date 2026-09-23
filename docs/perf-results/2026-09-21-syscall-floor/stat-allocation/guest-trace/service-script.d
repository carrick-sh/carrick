#!/usr/sbin/dtrace -qs
/*
 * Attribute the Darwin lowering inside Linux AArch64 fstat (80) HVPatch
 * service windows. This is a diagnostic follow-up to
 * hvpatch-phase4-service-lowering.d, not a performance benchmark.
 *
 * WHAT IT MEASURES
 * ----------------
 * `hvpatch-syscall-service-begin` arms a host-thread window only for fstat.
 * While armed, this consumer counts every Darwin syscall, Mach trap, and
 * `vminfo:::as_fault` event. `hvpatch-syscall-service` validates the completed
 * window and retains the runtime duration; the distinct
 * `hvpatch-syscall-service-clear` marker then retires thread-local state.
 * Every aggregate keeps the Linux syscall number, and host work also keeps the
 * multiplexed Linux PID/TID/ASID identity. A zero host-syscall, Mach-trap, or
 * fault population is a measured result for a completed fstat window; a zero
 * fstat-window population is invalid evidence.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * The service-probe scalar ABI was live-qualified on local Darwin/arm64 on
 * 2026-09-13 against candidate-4 `dba576...`, using the invalid-fstat reducer
 * and its zero-iteration control under strict custom-script CLI exit handling:
 * both summaries were `status=ok`, with 50,115 matching begin/end/clear
 * windows, no errors/nesting/orphans/mismatches, 222 identical host-syscall
 * counts, and no Mach traps. The exact comparison receipt is
 * `maininvalid-fstat-service-comparison.json`. The qualified ABI is:
 * - carrick*:::hvpatch-syscall-service-begin is
 *   (int32_t guest_pid, int32_t guest_tid, uint32_t asid, uint64_t nr).
 * - carrick*:::hvpatch-syscall-service is that identity plus
 *   uint64_t duration_ns.
 * - carrick*:::hvpatch-syscall-service-clear repeats the four begin scalars
 *   and is solely the consumer's retirement boundary.
 * - syscall:::entry and mach_trap:::entry name the Darwin operation in
 *   `probefunc`; vminfo:::as_fault arg2 is the 16-KiB host-page base on the
 *   previously qualified arm64 Darwin lane.
 *
 * The first candidate-4 capture was rejected: its raw
 * `maininvalid-fstat-candidate4-service-lowering.raw` recorded 50,115 begin
 * aggregates but only 49,343 begin-window counters, plus 771 orphan end/clear
 * markers and one identity mismatch. The prior script cleared five `self->`
 * slots to zero after every window, which plausibly churned DTrace dynamic
 * variables at this rate. This revision retains every worker's slots and uses
 * active=1 only while a window is armed, active=2 after retirement. The later
 * clean capture above qualified this revised allocation lifecycle; the failed
 * first capture remains historical evidence and is not used for attribution.
 *
 * Linux PID/TID/ASID are multiplexed guest identities. DTrace pid/tid remain
 * Darwin host identities and only join host work to the active window. A
 * nested, orphaned, mismatched, or thread-exited active window is a capture
 * error, never unattributed work.
 *
 * PERTURBATION
 * ------------
 * HIGH. Every fstat service probe fires three times and selected windows count
 * every Darwin syscall, Mach trap, and fault. Counts, same-instrument shares,
 * and ranks are diagnostic evidence; elapsed wall time and duration values are
 * not performance measurements. macOS exposes no `dtrace:::DROP` provider, so
 * this script cannot observe libdtrace loss itself. For custom `--script`
 * captures, Carrick's CLI rejects every consumer-drop category and interruption
 * before returning success. A retained capture MUST therefore use
 * `--require-script-exit`, require CLI exit 0 and this raw summary's `status=ok`,
 * and inspect retained stderr for actual errors. Normal auto-sudo warnings and
 * `TRACECHILD1` diagnostics alone are expected, so stderr must not be rejected
 * wholesale. The script itself fails closed on its DTrace error, timeout, or
 * zero fstat service windows. Retain any behavior candidate only with an
 * untraced same-binary ABBA.
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
    begin_windows = 0;
    end_windows = 0;
    clear_windows = 0;
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
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 80/
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
    begin_windows++;
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
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 80/
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
    end_windows++;
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 80/
{
    this->active = self->service_active == 1;
    this->identity_match = self->service_guest_pid == (int32_t)arg0 &&
        self->service_guest_tid == (int32_t)arg1 &&
        self->service_asid == (uint32_t)arg2 &&
        self->service_nr == (uint64_t)arg3;
    saw_orphan = saw_orphan || !this->active;
    saw_mismatch = saw_mismatch || (this->active && !this->identity_match);
    @service_clear_state[this->active, this->identity_match, (uint64_t)arg3] = count();
    clear_windows++;
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
    printf("HVPATCHFSTATLOWER|error=thread-exit-active|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu\n",
        pid, tid, self->service_guest_pid, self->service_guest_tid,
        self->service_asid, self->service_nr);
    exit(2);
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCHFSTATLOWER|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_selected && root_seen && begin_windows == end_windows &&
        end_windows == clear_windows && !saw_nested && !saw_orphan &&
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
    printf("HVPATCHFSTATLOWER|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|saw_selected=%d|begin_windows=%d|end_windows=%d|clear_windows=%d|saw_host_syscall=%d|saw_mach_trap=%d|saw_fault=%d|saw_nested=%d|saw_orphan=%d|saw_mismatch=%d|errors=%d\n",
        root_seen && !timed_out && saw_selected && !saw_nested && !saw_orphan &&
        !saw_mismatch && begin_windows == end_windows &&
            end_windows == clear_windows && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, saw_selected, begin_windows,
        end_windows, clear_windows, saw_host_syscall, saw_mach_trap, saw_fault,
        saw_nested, saw_orphan, saw_mismatch, errors);
    printa("HVPATCHFSTATLOWER|service-begin|nested=%d|nr=%llu|count=%@d\n",
        @service_begin_state);
    printa("HVPATCHFSTATLOWER|service-end|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @service_end_state);
    printa("HVPATCHFSTATLOWER|service-clear|active=%d|identity_match=%d|nr=%llu|count=%@d\n",
        @service_clear_state);
    printa("HVPATCHFSTATLOWER|service-duration-ns|nr=%llu|value=%@d\n",
        @service_duration_ns);
    printf("HVPATCHFSTATLOWER|section=host-syscalls\n");
    printa("HVPATCHFSTATLOWER|host-syscall|nr=%llu|host=%s|count=%@d\n",
        @host_syscall_count);
    printf("HVPATCHFSTATLOWER|section=host-tasks\n");
    trunc(@host_syscall_task, 160);
    printa("HVPATCHFSTATLOWER|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @host_syscall_task);
    printf("HVPATCHFSTATLOWER|section=mach-traps\n");
    printa("HVPATCHFSTATLOWER|mach|nr=%llu|host=%s|count=%@d\n", @mach_count);
    printf("HVPATCHFSTATLOWER|section=mach-tasks\n");
    trunc(@mach_task, 160);
    printa("HVPATCHFSTATLOWER|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|host=%s|count=%@d\n",
        @mach_task);
    printf("HVPATCHFSTATLOWER|section=faults\n");
    printa("HVPATCHFSTATLOWER|faults|nr=%llu|count=%@d\n", @fault_count);
    printf("HVPATCHFSTATLOWER|section=fault-tasks\n");
    trunc(@fault_task, 160);
    printa("HVPATCHFSTATLOWER|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|count=%@d\n",
        @fault_task);
}
