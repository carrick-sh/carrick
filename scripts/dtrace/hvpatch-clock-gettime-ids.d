#!/usr/sbin/dtrace -qs
/*
 * hvpatch-clock-gettime-ids.d — histogram host-serviced clock_gettime (arm64
 * Linux nr 113) and clock_getres (114) by Linux clock id.
 *
 * WHAT IT MEASURES
 * ----------------
 * Every Linux clock_gettime/clock_getres that reached Carrick's host-side
 * syscall service (vDSO fast path and the EL1 raw-clock handler did NOT absorb
 * it), keyed by the clock id (syscall arg0). Also counts total host services so
 * the clock share is visible. Ids: 0 REALTIME, 1 MONOTONIC, 2 PROCESS_CPUTIME,
 * 3 THREAD_CPUTIME, 4 MONOTONIC_RAW, 5 REALTIME_COARSE, 6 MONOTONIC_COARSE,
 * 7 BOOTTIME, 8/9 *_ALARM, 11 TAI; negative = dynamic cpuclock (pid/tid
 * encoded, printed as signed).
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * hvpatch-syscall-args fires only when the identity-bearing
 * hvpatch-syscall-service-begin fired on the same host thread (see
 * carrick-observability probes.rs hvpatch_syscall_service_begin); its ABI is
 * (number, arg0, arg1, arg2, arg3). Qualified from the source 2026-09-30; a
 * zero total means the probe did not fire, not that nothing happened.
 *
 * PERTURBATION
 * ------------
 * LOW-MEDIUM: one aggregation update per host service, no per-event output.
 * Counts are citable; elapsed time is not. 120 s bound in-script.
 */

#pragma D option quiet

inline int BOUND_SECONDS = 120;

dtrace:::BEGIN
{
    secs = 0;
    total = 0;
    begins = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    begins++;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target))/
{
    total++;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == 113/
{
    @gettime[(int64_t)(int32_t)arg1] = count();
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == 114/
{
    @getres[(int64_t)(int32_t)arg1] = count();
}

/* The traced carrick process ending closes the window (guest forks are not
 * host processes under HVPATCH, so $target is the whole run). */
proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1s
{
    secs++;
}

profile:::tick-1s
/secs >= BOUND_SECONDS/
{
    exit(0);
}

dtrace:::END
{
    printf("host_service_begins %d\nhost_services_with_args %d\n", begins, total);
    printf("clock_gettime by clock id (arg0):\n");
    printa("  id %d : %@d\n", @gettime);
    printf("clock_getres by clock id (arg0):\n");
    printa("  id %d : %@d\n", @getres);
}
