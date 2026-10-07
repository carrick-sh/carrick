#!/usr/sbin/dtrace -Zqs
/*
 * WHAT IT MEASURES
 *   Host call stacks at HVPatch Maintenance-class vCPU exits. Use with a
 *   small completed fixture to find the caller that initiates each run.
 *
 * PROVIDER ABI
 *   Qualified on macOS/arm64 from carrick-observability:
 *   vcpu-run-exit(vcpu u64, class u32, esr u64), class 5 = Maintenance.
 *   The traced CLI's VM carrier is the target or its descendant.
 *
 * PERTURBATION
 *   HIGH: ustack(16) at every maintenance exit. Counts and callsites only;
 *   never use traced wall time as a cost or acceptance measurement.
 */
#pragma D option quiet
#pragma D option aggsize=32m

dtrace:::BEGIN
{ seconds = 0; seen = 0; errors = 0; }

carrick*:::vcpu-run-exit
/(pid == $target || progenyof($target)) && arg1 == 5/
{
    seen++;
    @callers[ustack(16)] = count();
}

dtrace:::ERROR
{ errors++; }

tick-1s
{ seconds++; }

tick-1s
/seconds >= 10/
{ exit(seen > 0 && errors == 0 ? 0 : 1); }

dtrace:::END
{
    printf("MAINTCALL1|summary|seen=%d|errors=%d|seconds=%d\n", seen, errors, seconds);
    printa(@callers);
}
