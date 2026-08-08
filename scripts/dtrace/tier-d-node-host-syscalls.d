#pragma D option quiet
#pragma D option aggsize=32m
#pragma D option dynvarsize=16m

/*
 * tier-d-node-host-syscalls.d -- count Darwin calls from one Tier-D Node tree.
 *
 * WHAT IT MEASURES
 * ----------------
 * Count-only syscall and Mach-trap entries for the launch-owned `$target`
 * process tree.  `proc:::create` follows Carrick's host fork/reexec children;
 * the capture ends only after the whole tree exits.  No Carrick USDT/pid
 * provider is enabled, so this screen does not arm fasttrap in the tracees or
 * trigger per-exec DOF-provider work.  It deliberately records no stacks,
 * arguments, return probes, timestamps, or user PCs.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. `proc:::create` exposes the child
 * PID as `args[0]->pr_pid`; `syscall:::entry` and `mach_trap:::entry` expose
 * the host operation name as `probefunc`.
 *
 * PERTURBATION
 * ------------
 * LOW-TO-MODERATE. Every host syscall/Mach-trap entry crosses a kernel DTrace
 * probe, but actions are count-only aggregations and no tracee fasttrap probe
 * is enabled. Counts rank amplification candidates; elapsed time from this
 * capture is not performance evidence. A valid capture exits naturally with
 * nonzero syscall counts, no DTrace errors, and no live tracked process.
 *
 * Usage:
 *   CARRICK_NATIVE_DIRECT=1 carrick trace \
 *     --script scripts/dtrace/tier-d-node-host-syscalls.d \
 *     --trace-out /tmp/tier-d-node-host-syscalls.out -- run ...
 */

dtrace:::BEGIN
{
    started = timestamp;
    seconds = 0;
    live = 1;
    completed = 0;
    timed_out = 0;
    probe_errors = 0;
    tracked[$target] = 1;
}

dtrace:::ERROR
{
    probe_errors++;
    printf("TIERDHOST1|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
    tracked[args[0]->pr_pid] = 1;
    live++;
    @process_creates = count();
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
    live--;
    @process_exits = count();
}

proc:::exit
/completed == 0 && live == 0/
{
    completed = 1;
    exit(0);
}

syscall:::entry
/tracked[pid]/
{
    @host_syscall[probefunc] = count();
    @pid_syscall[pid] = count();
}

mach_trap:::entry
/tracked[pid]/
{
    @mach_trap[probefunc] = count();
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 20/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printf("TIERDHOST1|section=host-syscalls\n");
    printa("TIERDHOST1|host=%s|count=%@d\n", @host_syscall);
    printf("TIERDHOST1|section=mach-traps\n");
    printa("TIERDHOST1|mach=%s|count=%@d\n", @mach_trap);
    printf("TIERDHOST1|section=processes\n");
    printa("TIERDHOST1|pid=%d|syscalls=%@d\n", @pid_syscall);
    printa("TIERDHOST1|process-creates=%@d\n", @process_creates);
    printa("TIERDHOST1|process-exits=%@d\n", @process_exits);
    printf("TIERDHOST1|complete|natural=%d|timed-out=%d|probe-errors=%d|live=%d|elapsed-ns=%d\n",
        completed, timed_out, probe_errors, live, timestamp - started);
}
