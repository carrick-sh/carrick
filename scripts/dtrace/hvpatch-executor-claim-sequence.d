/*
 * hvpatch-executor-claim-sequence.d — which settlement bumped a blocked
 * thread's execution generation past the +2 window `resume_continuation`
 * tolerates, and what guest activity surrounded it?
 *
 * Question (2026-09-01, `vforkexecthread` residual): the exec thread (tid 3)
 * parks its first nanosleep at execution generation 1 and is resumed by a
 * lease at generation 4, so one settlement more than park+wake happened
 * before `ResumeBlocked` serviced the continuation. The failure lands at
 * ~50 ms, the moment the leader (tid 2) issues clone(CLONE_VM|CLONE_VFORK),
 * so this script prints EVERY executor claim and Load/Save/Switch event with
 * its ThreadSerial and generation, interleaved with the begin/return of the
 * clone/exec/nanosleep/exit family, so the extra settlement can be placed.
 *
 * Provider ABI qualified on Darwin/arm64 from carrick-observability/probes.rs
 * (macOS 27.0, hvpatch-fork-child-dispatch.d qualified the same probes live
 * on 2026-08-25):
 *   hvpatch-executor-claim(arg0=TaskSerial, arg1=ThreadSerial, arg2=executor,
 *     arg3=ExecutionGeneration, arg4=validated ASID generation)
 *   hvpatch-executor-lifecycle(arg0=executor, arg1=phase, arg2=ThreadSerial,
 *     arg3=ExecutionGeneration, arg4=ASID generation); phases 0..5 are
 *     Create, Load, Save, Switch, Destroy, InvalidateAsid.
 *   hvpatch-syscall-service-begin(arg0=Linux pid, arg1=Linux tid, arg2=ASID,
 *     arg3=Linux syscall number)
 *   syscall-return(arg0=number, arg1=name, arg2=signed return, arg3=errno)
 *   hvpatch-syscall-service-clear repeats pid/tid/ASID/number in arg0..arg3
 *   hvpatch-fork-quiesce(arg0=parent pid, arg1=forking tid,
 *     arg2=initial siblings, arg3=poll iterations, arg4=elapsed ns)
 *   hvpatch-guest-lifecycle(arg0=phase, arg1=Linux pid, arg2=Linux ppid,
 *     arg3=Linux tid, arg4=ASID), phases 0..6 root, fork, exec, thread-start,
 *     thread-exit, process-exit, exec-begin.
 *   hvpatch-scheduler-wake(arg0=ThreadSerial, arg1=kind 0=Wake/1=Control,
 *     arg2=found state 0..6 Uninitialized, Runnable, Running, SwitchingOut,
 *     Blocked, Exited, Failed; arg3=found generation (0 when the state
 *     carries none), arg4=queued/kicked generation, 0 when the wake produced
 *     no scheduler action). Fires AFTER the transition, from the waking
 *     host thread, so `host_tid` here names the WAKER — that is the
 *     attribution this script exists to capture (added 2026-09-01).
 *   hvpatch-lease-settle(arg0=ThreadSerial, arg1=settlement 0..4 Runnable,
 *     Blocked, BlockedContinuation, Exited, ExecInvalidated; arg2=flags
 *     WakePending=1|ControlPending=2|ContinuationReady=4;
 *     arg3=settling lease generation, arg4=successor generation).
 *
 * Selected arm64 syscall numbers: exit=93, exit_group=94, nanosleep=101,
 * clock_nanosleep=115, clone=220, execve=221, wait4=260, futex=98.
 * Output protocol: EXECCLAIMSEQ1.
 *
 * Perturbation: per-event printf on every executor claim/lifecycle event,
 * every scheduler wake and lease settlement, and on the selected syscalls; order and identity are citable, timing is
 * not. The consumer exits on the traced root's proc:::exit or a 60 s
 * watchdog, never by external detach.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/hvpatch-executor-claim-sequence.d \
 *     --trace-out <out> -- run --platform linux/arm64 --fs host ... \
 *     docker.io/library/ubuntu:24.04 /tmp/carrick-init
 */
#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("EXECCLAIMSEQ1|header|version=1\n");
    claims = 0;
    lifecycle = 0;
    wakes = 0;
    settles = 0;
    errors = 0;
    started = timestamp;
}

carrick*:::hvpatch-executor-claim
/pid == $target || progenyof($target)/
{
    claims++;
    printf("EXECCLAIMSEQ1|claim|ts=%llu|host_tid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu\n",
        timestamp, tid, (uint64_t)arg0, (uint64_t)arg1, (uint32_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-executor-lifecycle
/pid == $target || progenyof($target)/
{
    lifecycle++;
    printf("EXECCLAIMSEQ1|lifecycle|ts=%llu|host_tid=%d|executor=%u|phase=%u|thread_serial=%llu|generation=%llu|asid_generation=%llu\n",
        timestamp, tid, (uint32_t)arg0, (uint32_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-scheduler-wake
/pid == $target || progenyof($target)/
{
    wakes++;
    printf("EXECCLAIMSEQ1|wake|ts=%llu|host_tid=%d|thread_serial=%llu|kind=%u|found_state=%u|found_generation=%llu|queued_generation=%llu\n",
        timestamp, tid, (uint64_t)arg0, (uint32_t)arg1, (uint32_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-lease-settle
/pid == $target || progenyof($target)/
{
    settles++;
    printf("EXECCLAIMSEQ1|settle|ts=%llu|host_tid=%d|thread_serial=%llu|settlement=%u|flags=%u|lease_generation=%llu|successor_generation=%llu\n",
        timestamp, tid, (uint64_t)arg0, (uint32_t)arg1, (uint32_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-fork-quiesce
/pid == $target || progenyof($target)/
{
    printf("EXECCLAIMSEQ1|quiesce|ts=%llu|host_tid=%d|parent_pid=%d|forking_tid=%d|initial_siblings=%u|poll_iterations=%llu|elapsed_ns=%llu\n",
        timestamp, tid, (int32_t)arg0, (int32_t)arg1, (uint32_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{
    printf("EXECCLAIMSEQ1|guest|ts=%llu|host_tid=%d|phase=%u|linux_pid=%d|linux_ppid=%d|linux_tid=%d|asid=%u\n",
        timestamp, tid, (uint32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (int32_t)arg3, (uint32_t)arg4);
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 (arg3 == 93 || arg3 == 94 || arg3 == 98 || arg3 == 101 || arg3 == 115 ||
  arg3 == 220 || arg3 == 221 || arg3 == 260)/
{
    self->linux_pid = (int32_t)arg0;
    self->linux_tid = (int32_t)arg1;
    self->nr = (uint64_t)arg3;
    printf("EXECCLAIMSEQ1|begin|ts=%llu|host_tid=%d|linux_pid=%d|linux_tid=%d|nr=%llu\n",
        timestamp, tid, self->linux_pid, self->linux_tid, self->nr);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr != 0 &&
 (uint64_t)arg0 == self->nr/
{
    printf("EXECCLAIMSEQ1|return|ts=%llu|host_tid=%d|linux_pid=%d|linux_tid=%d|nr=%llu|name=%s|ret=%lld|errno=%d\n",
        timestamp, tid, self->linux_pid, self->linux_tid, self->nr,
        copyinstr(arg1), (int64_t)arg2, (int32_t)arg3);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && self->nr != 0 &&
 (uint64_t)arg3 == self->nr/
{
    self->linux_pid = 0;
    self->linux_tid = 0;
    self->nr = 0;
}

dtrace:::ERROR
{
    errors++;
}

/* The traced root is the carrier; its exit ends the capture. */
proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 60 * 1000000000/
{
    printf("EXECCLAIMSEQ1|error=timeout\n");
    exit(0);
}

dtrace:::END
{
    printf("EXECCLAIMSEQ1|summary|claims=%d|lifecycle=%d|wakes=%d|settles=%d|errors=%d\n",
        claims, lifecycle, wakes, settles, errors);
    if (claims == 0)
        printf("EXECCLAIMSEQ1|error=no-executor-claim\n");
}
