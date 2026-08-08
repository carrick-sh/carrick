/*
 * tier-d-mach-server-lifecycle.d — prove whether Tier D's process-wide
 * Mach-exception receiver exits before a guest thread wedges on a protected
 * page fault.
 *
 * Provider ABI qualified live on this host (2026-08-08):
 * `dtrace -lvn mach_trap::mach_msg2_trap:return` exposes no typed arguments,
 * but a joined user stack plus healthy server captures prove `arg0` is the
 * Mach return code. `0` is success and `MACH_RCV_TIMED_OUT` (`0x10004003`) is
 * the generic server's normal zero-timeout combined-send/receive result, so
 * both are filtered. `proc:::fault` exposes `(int, siginfo_t *)`;
 * `proc:::signal-send` exposes the target `psinfo_t *` in args[1] and host
 * signal in args[2]. `proc:::lwp-exit` fires in the exiting LWP and permits
 * `ustack()`.
 *
 * This uses kernel providers only: no pid/USDT/fasttrap probes are armed, so
 * it is safe for a continuing tracee.  It records low-frequency Mach-message
 * returns and LWP exits, but the result remains attribution evidence rather
 * than performance evidence.
 *
 * Usage (start before the Carrick descendants of interest):
 *   sudo dtrace -q -s scripts/dtrace/tier-d-mach-server-lifecycle.d \
 *     > /tmp/tier-d-mach-server-lifecycle.out
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option ustackframes=32

dtrace:::BEGIN
{
    printf("TDMACHL1|event=begin|time=%Y\n", walltimestamp);
}

mach_trap::mach_msg2_trap:return
/execname == "carrick" && arg0 != 0 && arg0 != 0x10004003/
{
    printf("TDMACHL1|event=mach-msg2-return|ts=%d|pid=%d|tid=%d|a0=%#x|a1=%#x|a2=%#x|a3=%#x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
    ustack();
}

proc:::fault
/execname == "carrick"/
{
    printf("TDMACHL1|event=proc-fault|ts=%d|pid=%d|tid=%d|fault=%d|signum=%d|code=%d|address=%#x\n",
        timestamp, pid, tid, args[0], args[1]->si_signo,
        args[1]->si_code, (uintptr_t)args[1]->si_addr);
    ustack();
}

proc:::signal-send
/args[1]->pr_fname == "carrick"/
{
    printf("TDMACHL1|event=signal-send|ts=%d|sender=%d|target=%d|signum=%d\n",
        timestamp, pid, args[1]->pr_pid, args[2]);
}

proc:::lwp-exit
/execname == "carrick"/
{
    printf("TDMACHL1|event=lwp-exit|ts=%d|pid=%d|tid=%d\n",
        timestamp, pid, tid);
    ustack();
}

tick-60s
{
    printf("TDMACHL1|event=bound|seconds=60\n");
    exit(0);
}

dtrace:::END
{
    printf("TDMACHL1|event=end|time=%Y\n", walltimestamp);
}
