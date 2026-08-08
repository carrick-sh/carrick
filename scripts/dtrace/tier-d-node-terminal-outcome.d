/*
 * Minimal Tier-D terminal-outcome discriminator for intermittent Node rc125.
 *
 * WHAT IT MEASURES
 * ----------------
 * Counts guest exit(93)/exit_group(94) requests by host pid and requested
 * code, and prints only Carrick's fail-closed `native-tierd-unsupported`
 * events. The outer app harness already reports PASS versus rc125; this trace
 * answers the one remaining binary question without tracing wait/futex hot
 * paths: did the Node process itself request 125, or did Carrick terminate it
 * through an internal error path?
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified live on Darwin/arm64 on 2026-08-08 against the signed Carrick
 * binary. `syscall-entry` is (uint64 nr, char *name, uint64 args_host_ptr),
 * where args_host_ptr names six u64 Linux arguments.
 * `native-tierd-unsupported` is (uint32 pid, uint64 nr, char *detail), with
 * UINT64_MAX denoting a driver error outside syscall service.
 * `native-tierd-exception` is (uint32 phase, uint32 host_pid, uint64 a,
 * uint64 b, uint64 c, uint64 d); recovery-result phase 6 carries
 * (status, recovery-kind, fault-pc, fault-address) in a..d.
 * `proc:::create` exposes the child host pid as args[0]->pr_pid.
 *
 * PERTURBATION
 * ------------
 * MINIMAL: two syscall numbers update aggregations; there is no per-syscall,
 * futex, wait, signal, or process-lifecycle stream. A terminal error prints
 * once because losing its detail would defeat the script's purpose. The
 * trace stays armed for three seconds after the outer target exits so an
 * orphaned descendant can publish its terminal event naturally.
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    tracked[$target] = 1;
    printf("TDTO1|begin|wall=%Y|target=%d\n", walltimestamp, $target);
}

dtrace:::ERROR
{
    @probe_errors = count();
}

proc:::create
/tracked[pid]/
{
    tracked[args[0]->pr_pid] = 1;
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
}

carrick*:::syscall-entry
/tracked[pid] && (arg0 == 93 || arg0 == 94)/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    @guest_exit_requests[pid, arg0, (int)this->args[0]] = count();
}

carrick*:::native-tierd-unsupported
/tracked[pid]/
{
    printf("TDTO1|native-tierd-unsupported|ts=%d|pid=%d|tid=%d|reported-pid=%d|nr=%d|detail=%s\n",
        timestamp, pid, tid, (uint32_t)arg0, arg1, copyinstr(arg2));
    @terminal_errors[pid, arg1] = count();
}

carrick*:::native-tierd-exception
/tracked[pid] && arg0 == 6 && arg2 != 0/
{
    printf("TDTO1|mach-recovery-failure|ts=%d|pid=%d|wire-pid=%d|status=%d|kind=%d|pc=%#x|address=%#x\n",
        timestamp, pid, (uint32_t)arg1, (int)arg2, (int)arg3, arg4, arg5);
    @mach_recovery_failures[pid, (int)arg2, (int)arg3] = count();
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
    printf("TDTO1|guest-exit-requests\n");
    printa("  pid=%d nr=%d code=%d %@d\n", @guest_exit_requests);
    printf("TDTO1|terminal-errors\n");
    printa("  pid=%d nr=%d %@d\n", @terminal_errors);
    printf("TDTO1|mach-recovery-failures\n");
    printa("  pid=%d status=%d kind=%d %@d\n", @mach_recovery_failures);
    printf("TDTO1|probe-errors\n");
    printa("  %@d\n", @probe_errors);
    printf("TDTO1|end|wall=%Y|timed-out=%d\n", walltimestamp, timed_out);
}
