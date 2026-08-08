/*
 * tier-d-mach-exception.d — follow the native Tier-D Mach-exception channel
 * from thread-port installation through dynamic-code recovery.
 *
 * Provider ABI qualified from Carrick's generated USDT declaration:
 * native-tierd-exception(phase, host_pid, a, b, c, d), all copied scalars.
 * Phases: 1=install, 2=fork-child rebind, 3=Mach handler entry,
 * 5=recovery service entry, 6=recovery service result, 7=private-breakpoint
 * reply, 8=exception-port lookup miss, 9=breakpoint PC/instruction/pending
 * state, 10=Linux architectural system-register reply
 * (a=PC,b=instruction,c=value,d=destination GPR), 11=uninstall lifecycle
 * summary (a=installs,b=fork rebinds,c=exception entries,d=recovery
 * services), 12=uninstall exception-kind summary (a=bad access,
 * b=breakpoint,c=bad instruction,d=sysreg emulations), and 13=uninstall
 * outcome summary (a=execute switches,b=write switches,c=failures,
 * d=last status), and 14=exception-server return
 * (a=mach_msg_server status,b=prior restart count,c=receive port set,
 * d=1 when the observed receive-buffer failure will be retried),
 * 15=guest AArch64 instruction-cache publication
 * (a=start,b=end,c=1 when the half-open range belongs to one live Tier-D
 * MAP_JIT mapping,d=reserved), and 16=dynamic far-veneer exception route
 * (a=1 site-to-veneer or 2 veneer-to-successor,b=fault PC,c=redirect PC,
 * d=private UDF instruction). The
 * uninstall summaries deliberately fire after the early
 * exec/DOF-attachment race and before registration teardown. Live `dtrace -lvn
 * proc:::signal-send` qualifies args[1] as `psinfo_t *`; its Darwin
 * target-pid member is pr_pid.
 *
 * The clauses arm the shared Tier-D USDT site. Phase 15 can fire once per
 * guest cache publication, so a JIT-heavy workload may be materially
 * perturbed even though guest instructions and syscall service are not
 * instrumented. This is attribution only: elapsed time is not performance
 * evidence. Let carrick trace reach normal process exit; do not abort the
 * consumer while a recovery trampoline is live.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/tier-d-mach-exception.d \
 *     --trace-out /tmp/tier-d-mach-exception.out -- run ...
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("TIERDMACH1|event=begin|target=%d|time=%Y\n", $target,
        walltimestamp);
}

carrick*:::native-tierd-exception
/pid == $target || progenyof($target)/
{
    events++;
    printf("TIERDMACH1|event=mach|pid=%d|wire-pid=%d|phase=%d|a=%#x|b=%#x|c=%#x|d=%#x\n",
        pid, (int)arg1, (int)arg0, arg2, arg3, arg4, arg5);
}

proc:::signal-send
/pid == $target || progenyof($target)/
{
    printf("TIERDMACH1|event=signal-send|sender=%d|target=%d|signal=%d\n",
        pid, args[1]->pr_pid, args[2]);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 30 && events == 0/
{
    printf("TIERDMACH1|event=error|reason=zero-firing-mach-probes|seconds=%d\n",
        seconds);
    exit(2);
}

tick-1s
/seconds >= 30 && events != 0/
{
    printf("TIERDMACH1|event=bound|seconds=%d|events=%d\n", seconds,
        events);
    exit(0);
}

dtrace:::END
{
    printf("TIERDMACH1|event=end|time=%Y\n", walltimestamp);
}
