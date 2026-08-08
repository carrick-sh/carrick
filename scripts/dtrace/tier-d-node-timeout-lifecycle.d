/*
 * Sparse Tier-D lifecycle for the Node app-smoke timeout/rc125 race.
 *
 * WHAT IT MEASURES
 * ----------------
 * The launch-owned process tree's Linux wait4/waitid, signal-send, and exit
 * syscalls, together with Carrick's signal publication/delivery and terminal
 * error probes.  For a completed wait4 it also reads the four-byte Linux wait
 * status from the guest pointer.  The exact question is whether GNU timeout
 * receives ECHILD/EINTR, a wrong child pid, or a wrong wait status before it
 * chooses exit status 125; if none occurs, the remaining failure is inside the
 * Node process's own shutdown rather than Carrick's child-reaping boundary.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified live on Darwin/arm64 on 2026-08-08 against the signed Carrick
 * binary. `syscall-entry` is (uint64 nr, char *name, uint64 args_host_ptr),
 * where args_host_ptr names six u64 Linux arguments. `syscall-return` is
 * (uint64 nr, char *name, int64 retval, int32 errno). `signal-publish` is
 * (int32 target_guest_tid, int32 Linux_signum, int32 kind), and
 * `signal-deliver` is (int32 delivering_guest_tid, int32 Linux_signum_or_zero).
 * `native-tierd-unsupported` is (uint32 pid, uint64 nr, char *detail), with
 * UINT64_MAX denoting a driver error outside syscall service. `proc:::create`
 * exposes the new host pid as args[0]->pr_pid. On this XNU build proc:::exit's
 * arg0 is an opaque value observed as 1 for every thread exit; it is not a wait
 * status and is recorded only as lifecycle timing.
 *
 * PERTURBATION
 * ------------
 * LOW: the script prints only sparse process/wait/signal/exit events, not the
 * hot futex stream. It remains mechanism evidence, never elapsed-time or
 * failure-rate authority. Descendant pids are retained after the outer target
 * exits and the fixed 18 s bound lets an 8 s guest timeout leave an observable
 * orphan tail without killing the DTrace consumer early (fasttrap detach is a
 * known hazard).
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    tracked[$target] = 1;
    printf("TDL1|begin|wall=%Y|target=%d\n", walltimestamp, $target);
}

dtrace:::ERROR
{
    errors++;
    printf("TDL1|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
}

proc:::create
/tracked[pid]/
{
    tracked[args[0]->pr_pid] = 1;
    printf("TDL1|proc-create|ts=%d|parent=%d|child=%d\n",
        timestamp, pid, args[0]->pr_pid);
}

proc:::exit
/tracked[pid]/
{
    printf("TDL1|proc-exit|ts=%d|pid=%d|tid=%d|opaque_arg0=%d\n",
        timestamp, pid, tid, (int)arg0);
    @proc_exits[pid] = count();
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
}

carrick*:::syscall-entry
/tracked[pid] && arg0 == 260/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    self->wait4_active = 1;
    self->wait4_target = (int64_t)this->args[0];
    self->wait4_statusp = this->args[1];
    self->wait4_options = this->args[2];
    printf("TDL1|wait4-entry|ts=%d|pid=%d|tid=%d|target=%d|statusp=%#x|options=%#x\n",
        timestamp, pid, tid, self->wait4_target, self->wait4_statusp,
        self->wait4_options);
}

carrick*:::syscall-return
/tracked[pid] && arg0 == 260 && self->wait4_active &&
    (int64_t)arg2 > 0 && self->wait4_statusp != 0/
{
    this->status = *(int *)copyin(self->wait4_statusp, 4);
    printf("TDL1|wait4-return|ts=%d|pid=%d|tid=%d|target=%d|options=%#x|ret=%d|errno=%d|status=%#x\n",
        timestamp, pid, tid, self->wait4_target, self->wait4_options,
        (int64_t)arg2, (int)arg3, this->status);
    @wait4_returns[pid, (int64_t)arg2, (int)arg3, this->status] = count();
    self->wait4_active = 0;
    self->wait4_target = 0;
    self->wait4_statusp = 0;
    self->wait4_options = 0;
}

carrick*:::syscall-return
/tracked[pid] && arg0 == 260 && self->wait4_active &&
    !((int64_t)arg2 > 0 && self->wait4_statusp != 0)/
{
    printf("TDL1|wait4-return|ts=%d|pid=%d|tid=%d|target=%d|options=%#x|ret=%d|errno=%d|status=NA\n",
        timestamp, pid, tid, self->wait4_target, self->wait4_options,
        (int64_t)arg2, (int)arg3);
    @wait4_no_status[pid, (int64_t)arg2, (int)arg3] = count();
    self->wait4_active = 0;
    self->wait4_target = 0;
    self->wait4_statusp = 0;
    self->wait4_options = 0;
}

carrick*:::syscall-entry
/tracked[pid] && arg0 == 95/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    self->waitid_active = 1;
    self->waitid_type = this->args[0];
    self->waitid_id = this->args[1];
    self->waitid_options = this->args[3];
    printf("TDL1|waitid-entry|ts=%d|pid=%d|tid=%d|idtype=%d|id=%d|options=%#x\n",
        timestamp, pid, tid, self->waitid_type, self->waitid_id,
        self->waitid_options);
}

carrick*:::syscall-return
/tracked[pid] && arg0 == 95 && self->waitid_active/
{
    printf("TDL1|waitid-return|ts=%d|pid=%d|tid=%d|idtype=%d|id=%d|options=%#x|ret=%d|errno=%d\n",
        timestamp, pid, tid, self->waitid_type, self->waitid_id,
        self->waitid_options, (int64_t)arg2, (int)arg3);
    @waitid_returns[pid, (int64_t)arg2, (int)arg3] = count();
    self->waitid_active = 0;
    self->waitid_type = 0;
    self->waitid_id = 0;
    self->waitid_options = 0;
}

carrick*:::syscall-entry
/tracked[pid] && (arg0 == 93 || arg0 == 94 || arg0 == 129 || arg0 == 131)/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    printf("TDL1|control-entry|ts=%d|pid=%d|tid=%d|nr=%d|name=%s|a0=%d|a1=%d|a2=%d\n",
        timestamp, pid, tid, arg0, copyinstr(arg1), (int64_t)this->args[0],
        (int64_t)this->args[1], (int64_t)this->args[2]);
    @control_entries[pid, arg0] = count();
}

carrick*:::syscall-return
/tracked[pid] && (arg0 == 129 || arg0 == 131)/
{
    printf("TDL1|control-return|ts=%d|pid=%d|tid=%d|nr=%d|name=%s|ret=%d|errno=%d\n",
        timestamp, pid, tid, arg0, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

carrick*:::signal-publish
/tracked[pid]/
{
    printf("TDL1|signal-publish|ts=%d|pid=%d|tid=%d|target-guest-tid=%d|signum=%d|kind=%d\n",
        timestamp, pid, tid, (int)arg0, (int)arg1, (int)arg2);
    @signals[pid, "publish", (int)arg1] = count();
}

carrick*:::signal-deliver
/tracked[pid]/
{
    printf("TDL1|signal-deliver|ts=%d|pid=%d|tid=%d|guest-tid=%d|signum=%d\n",
        timestamp, pid, tid, (int)arg0, (int)arg1);
    @signals[pid, "deliver", (int)arg1] = count();
}

carrick*:::native-tierd-unsupported
/tracked[pid]/
{
    printf("TDL1|native-tierd-unsupported|ts=%d|pid=%d|tid=%d|reported-pid=%d|nr=%d|detail=%s\n",
        timestamp, pid, tid, (uint32_t)arg0, arg1, copyinstr(arg2));
    @runtime_errors[pid, "native-tierd-unsupported"] = count();
}

carrick*:::unhandled-syscall
/tracked[pid]/
{
    printf("TDL1|unhandled-syscall|ts=%d|pid=%d|tid=%d|nr=%d|name=%s\n",
        timestamp, pid, tid, arg0, copyinstr(arg1));
    @runtime_errors[pid, "unhandled-syscall"] = count();
}

tick-1s
{
    seconds++;
}

tick-1s
/target_exited/
{
    target_exit_grace++;
}

tick-1s
/target_exit_grace >= 3/
{
    exit(0);
}

tick-1s
/seconds >= 18/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printf("TDL1|end|wall=%Y|timed-out=%d|errors=%d\n",
        walltimestamp, timed_out, errors);
    printf("TDL1|wait4-returns-with-status\n");
    printa("  pid=%d ret=%d errno=%d status=%#x %@d\n", @wait4_returns);
    printf("TDL1|wait4-returns-no-status\n");
    printa("  pid=%d ret=%d errno=%d %@d\n", @wait4_no_status);
    printf("TDL1|waitid-returns\n");
    printa("  pid=%d ret=%d errno=%d %@d\n", @waitid_returns);
    printf("TDL1|control-entries\n");
    printa("  pid=%d nr=%d %@d\n", @control_entries);
    printf("TDL1|signals\n");
    printa("  pid=%d phase=%s signum=%d %@d\n", @signals);
    printf("TDL1|proc-exits\n");
    printa("  pid=%d %@d\n", @proc_exits);
    printf("TDL1|runtime-errors\n");
    printa("  pid=%d kind=%s %@d\n", @runtime_errors);
}
