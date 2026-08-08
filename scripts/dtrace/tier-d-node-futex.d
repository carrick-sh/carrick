/*
 * Ordered Tier-D futex lifecycle for the Node nested-exec shutdown failure.
 *
 * Measures every Linux futex entry, its resolved Carrick route, and the
 * matching syscall return for the launch-owned Carrick process tree.  The
 * timestamped stream answers whether a stuck Node child missed a WAKE, was
 * left on a requeued address, or never issued the expected wake at all.
 * It also records guest `exit`/`exit_group` requests so an ordinary guest
 * status is distinguishable from Carrick's terminal-error paths.
 *
 * Provider ABI qualified live on this Darwin host against the signed Carrick
 * binary on 2026-08-08 (`dtrace -lv -c <carrick --version>`):
 *
 *   futex-route:    uint32 pid, uint64 guest_addr, int32 op,
 *                   int32 shared, uint64 host_addr
 *   syscall-return: uint64 nr, char *name, int64 retval, int32 errno
 *   guest-exit:     uint32 pid, int32 code
 *   unhandled-syscall: uint64 nr, char *name, uint64 args_host_ptr
 *   partial-syscall:   uint64 nr, char *name, uint64 args_host_ptr,
 *                      char *detail
 *   unknown-syscall-flags: uint64 nr, char *name, uint32 argument,
 *                          uint64 flags
 *   native-tierd-unsupported: uint32 pid, uint64 nr, char *detail
 *                   (`nr == UINT64_MAX` means a driver error outside syscall
 *                   service)
 *   signal-publish: int32 target_guest_tid, int32 Linux_signum, int32 kind
 *   signal-deliver: int32 delivering_guest_tid, int32 Linux_signum_or_zero
 *   signal-inject:  int32 Linux_signum, uint64 saved_pc, uint64 new_sp,
 *                   uint64 handler
 *   signal-unsupported: int32 Linux_signum, char *detail
 *   proc:::signal-send: args[1] is psinfo_t *, args[2] is host signum
 *   proc:::exit:    int opaque_arg0 (observed as 1 for every exit on this
 *                   host; it is process-lifecycle evidence, not exit status)
 *
 * `syscall-entry` arg2 is Carrick's host pointer to six u64 syscall args (the
 * established provider contract used by syscalls.d), so copyin is valid.
 *
 * PERTURBATION: HIGH for a futex-heavy process.  This prints one entry, route,
 * and return line per futex and is diagnostic sequencing evidence only.  It
 * is never wall-time or failure-rate authority.  The in-script 20 s bound is
 * paired with a longer host-side bound so END always publishes its census.
 * When the outer target exits, the trace remains armed for a three-second
 * descendant grace window: rc125 may orphan the Node process, and ending at
 * `$target` would erase precisely the post-wrapper lifecycle under test.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("TDF1|begin|wall=%Y|target=%d\n", walltimestamp, $target);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 98/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    self->futex_active = 1;
    self->futex_routed = 0;
    self->futex_addr = this->args[0];
    self->futex_raw_op = this->args[1];
    printf("TDF1|entry|ts=%d|pid=%d|tid=%d|addr=%#x|raw_op=%#x|val=%d|arg3=%#x|uaddr2=%#x|val3=%d\n",
        timestamp, pid, tid, this->args[0], this->args[1],
        (uint32_t)this->args[2], this->args[3], this->args[4],
        (uint32_t)this->args[5]);
    @entries[pid] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 93 || arg0 == 94)/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    printf("TDF1|guest-exit-request|ts=%d|pid=%d|tid=%d|nr=%d|code=%d\n",
        timestamp, pid, tid, arg0, (int)this->args[0]);
    @requested_exits[pid, arg0, (int)this->args[0]] = count();
}

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    self->futex_routed = 1;
    self->futex_addr = arg1;
    self->futex_op = (int)arg2;
    self->futex_shared = (int)arg3;
    self->futex_host = arg4;
    printf("TDF1|route|ts=%d|pid=%d|tid=%d|addr=%#x|op=%d|shared=%d|host=%#x\n",
        timestamp, pid, tid, arg1, (int)arg2, (int)arg3, arg4);
    @routes[pid, (int)arg2, (int)arg3] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 98 && self->futex_active/
{
    printf("TDF1|return|ts=%d|pid=%d|tid=%d|addr=%#x|raw_op=%#x|routed=%d|op=%d|shared=%d|host=%#x|ret=%d|errno=%d\n",
        timestamp, pid, tid, self->futex_addr, self->futex_raw_op,
        self->futex_routed, self->futex_op, self->futex_shared,
        self->futex_host, (int64_t)arg2, (int)arg3);
    @returns[pid, self->futex_op, (int64_t)arg2, (int)arg3] = count();
    self->futex_active = 0;
    self->futex_routed = 0;
    self->futex_addr = 0;
    self->futex_raw_op = 0;
    self->futex_op = 0;
    self->futex_shared = 0;
    self->futex_host = 0;
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("TDF1|guest-exit|ts=%d|pid=%d|tid=%d|reported_pid=%d|code=%d\n",
        timestamp, pid, tid, (uint32_t)arg0, (int)arg1);
    @guest_exits[pid, (int)arg1] = count();
}

carrick*:::unhandled-syscall
/pid == $target || progenyof($target)/
{
    printf("TDF1|unhandled-syscall|ts=%d|pid=%d|tid=%d|nr=%d|name=%s|args_host=%#x\n",
        timestamp, pid, tid, arg0, stringof(arg1), arg2);
    @runtime_errors[pid, "unhandled-syscall"] = count();
}

carrick*:::partial-syscall
/pid == $target || progenyof($target)/
{
    printf("TDF1|partial-syscall|ts=%d|pid=%d|tid=%d|nr=%d|name=%s|args_host=%#x|detail=%s\n",
        timestamp, pid, tid, arg0, stringof(arg1), arg2, stringof(arg3));
    @runtime_errors[pid, "partial-syscall"] = count();
}

carrick*:::unknown-syscall-flags
/pid == $target || progenyof($target)/
{
    printf("TDF1|unknown-syscall-flags|ts=%d|pid=%d|tid=%d|nr=%d|name=%s|argument=%d|flags=%#x\n",
        timestamp, pid, tid, arg0, stringof(arg1), (uint32_t)arg2, arg3);
    @runtime_errors[pid, "unknown-syscall-flags"] = count();
}

carrick*:::native-tierd-unsupported
/pid == $target || progenyof($target)/
{
    printf("TDF1|native-tierd-unsupported|ts=%d|pid=%d|tid=%d|reported_pid=%d|nr=%d|detail=%s\n",
        timestamp, pid, tid, (uint32_t)arg0, arg1, stringof(arg2));
    @runtime_errors[pid, "native-tierd-unsupported"] = count();
}

carrick*:::signal-publish
/pid == $target || progenyof($target)/
{
    printf("TDF1|signal-publish|ts=%d|pid=%d|tid=%d|target_guest_tid=%d|signum=%d|kind=%d\n",
        timestamp, pid, tid, (int)arg0, (int)arg1, (int)arg2);
    @signals[pid, "publish", (int)arg1] = count();
}

carrick*:::signal-deliver
/pid == $target || progenyof($target)/
{
    printf("TDF1|signal-deliver|ts=%d|pid=%d|tid=%d|guest_tid=%d|signum=%d\n",
        timestamp, pid, tid, (int)arg0, (int)arg1);
    @signals[pid, "deliver", (int)arg1] = count();
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
    printf("TDF1|signal-inject|ts=%d|pid=%d|tid=%d|signum=%d|saved_pc=%#x|new_sp=%#x|handler=%#x\n",
        timestamp, pid, tid, (int)arg0, arg1, arg2, arg3);
    @signals[pid, "inject", (int)arg0] = count();
}

carrick*:::signal-unsupported
/pid == $target || progenyof($target)/
{
    printf("TDF1|signal-unsupported|ts=%d|pid=%d|tid=%d|signum=%d|detail=%s\n",
        timestamp, pid, tid, (int)arg0, stringof(arg1));
    @runtime_errors[pid, "signal-unsupported"] = count();
}

proc:::signal-send
/pid == $target || progenyof($target)/
{
    printf("TDF1|host-signal-send|ts=%d|sender=%d|target=%d|signum=%d\n",
        timestamp, pid, args[1]->pr_pid, args[2]);
    @host_signals[pid, args[1]->pr_pid, args[2]] = count();
}

proc:::exit
/pid == $target || progenyof($target)/
{
    printf("TDF1|proc-exit|ts=%d|pid=%d|tid=%d|opaque_arg0=%d\n",
        timestamp, pid, tid, (int)arg0);
    @proc_exits[pid, (int)arg0] = count();
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
}

tick-1s
{
    secs++;
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
/secs >= 20/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printf("TDF1|end|wall=%Y|timed_out=%d\n", walltimestamp, timed_out);
    printf("TDF1|entries\n");
    printa("  pid=%d %@d\n", @entries);
    printf("TDF1|routes\n");
    printa("  pid=%d op=%d shared=%d %@d\n", @routes);
    printf("TDF1|returns\n");
    printa("  pid=%d op=%d ret=%d errno=%d %@d\n", @returns);
    printf("TDF1|guest-exits\n");
    printa("  pid=%d code=%d %@d\n", @guest_exits);
    printf("TDF1|guest-exit-requests\n");
    printa("  pid=%d nr=%d code=%d %@d\n", @requested_exits);
    printf("TDF1|proc-exits\n");
    printa("  pid=%d raw_status=%d %@d\n", @proc_exits);
    printf("TDF1|runtime-errors\n");
    printa("  pid=%d kind=%s %@d\n", @runtime_errors);
    printf("TDF1|signals\n");
    printa("  pid=%d phase=%s signum=%d %@d\n", @signals);
    printf("TDF1|host-signals\n");
    printa("  sender=%d target=%d signum=%d %@d\n", @host_signals);
}
