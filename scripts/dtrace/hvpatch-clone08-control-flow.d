/*
 * hvpatch-clone08-control-flow.d — why does LTP clone08 stop after case 3?
 *
 * Question: after the CLONE_PARENT_SETTID|CLONE_VM case, does Carrick return
 * the controller to a different Linux process identity, terminate the wrong
 * logical task, or otherwise skip the getpid guard that precedes case 4?
 *
 * Provider ABI qualified on Darwin/arm64 from carrick-observability/probes.rs
 * and the live-qualified vfork-smash-signal-injections.d at this source:
 *   hvpatch-syscall-service-begin(arg0=Linux pid, arg1=Linux tid,
 *     arg2=ASID, arg3=Linux syscall number)
 *   hvpatch-syscall-args(arg0=number, arg1..arg4=guest args 0..3)
 *   syscall-return(arg0=number, arg1=name, arg2=signed return, arg3=errno)
 *   hvpatch-syscall-service-clear repeats pid/tid/ASID/number in arg0..arg3
 *   hvpatch-guest-lifecycle-identity(arg0=Linux pid, arg1=TaskSerial,
 *     arg2=parent TaskSerial, arg3=MmId)
 *   hvpatch-guest-lifecycle(arg0=phase, arg1=Linux pid, arg2=Linux ppid,
 *     arg3=Linux tid, arg4=ASID), where phases 0..6 are root, fork, exec,
 *     thread-start, thread-exit, process-exit, exec-begin.
 *
 * Selected arm64 syscall numbers: exit=93, exit_group=94, getpid=172,
 * clone=220, wait4=260. Output protocol: CLONE08CF1.
 *
 * Perturbation: per-event printf on only these five syscalls and lifecycle
 * events. Diagnostic only; timing from this capture is not citable.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/hvpatch-clone08-control-flow.d \
 *     --trace-out <out> -- run --fs host localhost:5050/ltp:arm64 \
 *     /bin/sh -c /opt/ltp/testcases/bin/clone08
 */
#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("CLONE08CF1|header|version=1\n");
    selected_returns = 0;
    lifecycle_events = 0;
    errors = 0;
    started = timestamp;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 (arg3 == 93 || arg3 == 94 || arg3 == 172 || arg3 == 220 || arg3 == 260)/
{
    self->linux_pid = (int32_t)arg0;
    self->linux_tid = (int32_t)arg1;
    self->asid = (uint32_t)arg2;
    self->nr = (uint64_t)arg3;
    printf("CLONE08CF1|begin|ts=%llu|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu\n",
        timestamp, tid, self->linux_pid, self->linux_tid, self->asid,
        self->nr);
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && self->nr != 0 &&
 (uint64_t)arg0 == self->nr/
{
    printf("CLONE08CF1|args|ts=%llu|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, tid, self->linux_pid, self->linux_tid, self->asid,
        self->nr, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr != 0 &&
 (uint64_t)arg0 == self->nr/
{
    selected_returns++;
    printf("CLONE08CF1|return|ts=%llu|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu|name=%s|ret=%lld|errno=%d\n",
        timestamp, tid, self->linux_pid, self->linux_tid, self->asid,
        self->nr, copyinstr(arg1), (int64_t)arg2, (int32_t)arg3);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && self->nr != 0 &&
 (uint64_t)arg3 == self->nr/
{
    self->linux_pid = 0;
    self->linux_tid = 0;
    self->asid = 0;
    self->nr = 0;
}

carrick*:::hvpatch-guest-lifecycle-identity
/pid == $target || progenyof($target)/
{
    self->life_pid = (int32_t)arg0;
    self->task_serial = (uint64_t)arg1;
    self->parent_serial = (uint64_t)arg2;
    self->mm = (uint64_t)arg3;
}

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{
    lifecycle_events++;
    printf("CLONE08CF1|lifecycle|ts=%llu|host_tid=%d|phase=%u|linux_pid=%d|linux_ppid=%d|linux_tid=%d|asid=%u|task_serial=%llu|parent_serial=%llu|mm=%llu|identity_match=%d\n",
        timestamp, tid, (uint32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (int32_t)arg3, (uint32_t)arg4, self->task_serial,
        self->parent_serial, self->mm, self->life_pid == (int32_t)arg1);
    self->life_pid = 0;
    self->task_serial = 0;
    self->parent_serial = 0;
    self->mm = 0;
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
    printf("CLONE08CF1|error=timeout\n");
    exit(0);
}

dtrace:::END
{
    printf("CLONE08CF1|summary|selected_returns=%d|lifecycle_events=%d|errors=%d\n",
        selected_returns, lifecycle_events, errors);
    if (selected_returns == 0)
        printf("CLONE08CF1|error=no-selected-syscall-return\n");
}
