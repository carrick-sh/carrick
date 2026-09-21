#!/usr/sbin/dtrace -qs
/*
 * hvpatch-raw-clock-el1.d — prove eligible raw clock syscalls avoid host service.
 *
 * WHAT IT MEASURES
 * ----------------
 * Counts HVPatch syscall-service admissions for Linux clock_gettime (arm64
 * syscall 113) and all other syscalls. Run it with the clockcoherence probe:
 * that probe issues two raw CLOCK_MONOTONIC calls and two raw CLOCK_REALTIME
 * calls. The eligible EL1 path therefore yields exactly two host clock
 * services; four means the monotonic calls still exited to Carrick.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified from carrick-observability/probes.rs and
 * hvpatch-guest-syscall-flow.d on Darwin/arm64, 2026-09-20.
 * hvpatch-syscall-service-begin arg3 is the u64 Linux syscall number.
 * hvpatch-guest-lifecycle arg0 is the lifecycle phase.
 *
 * PERTURBATION
 * ------------
 * LOW. Two scalar increments per host-serviced syscall and no per-event
 * printing. Counts are citable; timings from this capture are not.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    clock_services = 0;
    other_services = 0;
    lifecycle_events = 0;
    errors = 0;
    completed = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (uint64_t)arg3 == 113/
{
    clock_services++;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (uint64_t)arg3 != 113/
{
    other_services++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target))/
{
    lifecycle_events++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (uint32_t)arg0 == 5/
{
    completed = 1;
    printf("RAWCLOCK1|clock_host_services=%d|other_host_services=%d|lifecycle=%d|errors=%d|complete=1\n",
        clock_services, other_services, lifecycle_events, errors);
    exit(errors == 0 ? 0 : 2);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
/completed == 0/
{
    printf("RAWCLOCK1|clock_host_services=%d|other_host_services=%d|lifecycle=%d|errors=%d|complete=0\n",
        clock_services, other_services, lifecycle_events, errors);
}
