#!/usr/sbin/dtrace -qs
/*
 * hvpatch-guest-syscall-mix.d — rank host-serviced Linux syscalls by number.
 *
 * WHAT IT MEASURES
 * ----------------
 * Counts `hvpatch-syscall-service-begin` events by Linux syscall number for a
 * bounded HVPatch run. This distinguishes a guest busy in real EL1 execution
 * from one repeatedly returning to Carrick for syscall service, without the
 * per-event output of hvpatch-guest-syscall-flow.d.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified from carrick-observability/probes.rs and
 * hvpatch-guest-syscall-flow.d on Darwin/arm64, 2026-09-20.
 * hvpatch-syscall-service-begin arg3 is the u64 Linux syscall number.
 *
 * PERTURBATION
 * ------------
 * MEDIUM on syscall-dense workloads. One aggregation update occurs per host
 * service and no per-event text is emitted. Counts are diagnostic; elapsed
 * time under this script is not performance evidence. The ten-second bound
 * prevents a wedged or intentionally long workload from running indefinitely.
 */

#pragma D option quiet

inline int BOUND_SECONDS = 10;

dtrace:::BEGIN
{
    seconds = 0;
    services = 0;
    errors = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    services++;
    @by_nr[(uint64_t)arg3] = count();
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-1s
{
    seconds++;
}

profile:::tick-1s
/seconds >= BOUND_SECONDS/
{
    printf("GSFMIX1|bound_s=%d|services=%d|errors=%d|complete=1\n",
        BOUND_SECONDS, services, errors);
    printa("GSFMIX1|nr=%llu|count=%@d\n", @by_nr);
    exit(errors == 0 && services > 0 ? 0 : 2);
}
