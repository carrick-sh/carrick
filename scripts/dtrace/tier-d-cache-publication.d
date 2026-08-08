/*
 * tier-d-cache-publication.d — correlate Tier-D dynamic execute faults with
 * the exact AArch64 cache-publication ranges emitted by the guest runtime.
 *
 * Provider ABI qualified from Carrick's generated USDT declarations:
 * native-tierd-exception(phase, host_pid, a, b, c, d), all copied scalars.
 * This script consumes only:
 *   phase 3: a=Mach exception, b=code[0], c=fault PC, d=code[1]/fault address
 *   phase 6: a=service status, b=recovery kind (1=execute,2=write),
 *            c=fault PC, d=fault address
 *   phase 15: a=published start, b=published end, c=1 when the range belongs
 *             to one live Tier-D MAP_JIT mapping, d=reserved
 * native-tierd-unsupported(host_pid, syscall, detail) is the terminal named
 * refusal. The five-second bound is longer than the canonical Node app run
 * and makes a zero-publication capture an explicit error.
 *
 * Phase 15 can fire hundreds of times in one short Node process. Enabling
 * this USDT site is materially perturbing and the result is attribution only;
 * no elapsed time from this capture is performance evidence. Let the bounded
 * trace finish normally so fasttrap detach cannot leak a breakpoint into a
 * continuing guest.
 *
 * Usage:
 *   carrick trace --forward-env CARRICK_NATIVE_DIRECT=1 \
 *     --script scripts/dtrace/tier-d-cache-publication.d \
 *     --trace-out /tmp/tier-d-cache-publication.out -- run ...
 */

#pragma D option quiet
#pragma D option strsize=512
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("TIERDPUB1|event=begin|target=%d|time=%Y\n", $target,
        walltimestamp);
}

carrick*:::native-tierd-exception
/(pid == $target || progenyof($target)) && arg0 == 3/
{
    exceptions++;
    printf("TIERDPUB1|event=exception|pid=%d|wire-pid=%d|exception=%d|code=%#x|pc=%#x|address=%#x\n",
        pid, (int)arg1, (int)arg2, arg3, arg4, arg5);
}

carrick*:::native-tierd-exception
/(pid == $target || progenyof($target)) && arg0 == 6/
{
    services++;
    printf("TIERDPUB1|event=service|pid=%d|wire-pid=%d|status=%d|kind=%d|pc=%#x|address=%#x\n",
        pid, (int)arg1, (int)arg2, (int)arg3, arg4, arg5);
}

carrick*:::native-tierd-exception
/(pid == $target || progenyof($target)) && arg0 == 15/
{
    publications++;
    printf("TIERDPUB1|event=publication|pid=%d|wire-pid=%d|start=%#x|end=%#x|contained=%d\n",
        pid, (int)arg1, arg2, arg3, (int)arg4);
}

carrick*:::native-tierd-unsupported
/pid == $target || progenyof($target)/
{
    refusals++;
    printf("TIERDPUB1|event=refusal|pid=%d|wire-pid=%d|syscall=%d|detail=%s\n",
        pid, (int)arg0, (int64_t)arg1, copyinstr(arg2));
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 5 && publications == 0/
{
    printf("TIERDPUB1|event=error|reason=zero-firing-publication-probes|seconds=%d\n",
        seconds);
    exit(2);
}

tick-1s
/seconds >= 5 && publications != 0/
{
    printf("TIERDPUB1|event=bound|seconds=%d|publications=%d|exceptions=%d|services=%d|refusals=%d\n",
        seconds, publications, exceptions, services, refusals);
    exit(0);
}

dtrace:::END
{
    printf("TIERDPUB1|event=end|time=%Y\n", walltimestamp);
}
