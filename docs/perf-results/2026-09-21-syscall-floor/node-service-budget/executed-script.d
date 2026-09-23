#!/usr/sbin/dtrace -qs
/* Aggregate host syscall-service elapsed time; not CPU or critical-path time.
 * Concurrent service intervals can overlap. Waits and instrumentation are
 * included; sums are diagnostic and must not be subtracted from wall time.
 * Candidate interventions require separate untraced paired workload timing.
 * Count host-serviced requests, argument events and closed service windows.
 * ABI: begin/service arg3=Linux nr; args arg0=Linux nr; qualified from
 * carrick-observability/probes.rs and live counts on this host before use.
 * MEDIUM perturbation: USDT aggregates per request; no uninstrumented timing claims.
 * Aggregate counters avoid cross-CPU scalar increment loss. Root exit and
 * caller-verified workload markers establish completion; exit/nanosleep may
 * legitimately omit service-end and must remain visible as unmatched rows.
 * Run with carrick trace --require-script-exit. CLI detects dropped records.
 */
#pragma D option quiet
#pragma D option aggsize=16m
#pragma D option dynvarsize=16m
BEGIN { seconds = 0; seen = 0; errors = 0; root_exited = 0; }
carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{ seen = 1; @begin[(uint64_t)arg3] = count(); }
carrick*:::hvpatch-syscall-args
/pid == $target || progenyof($target)/
{ @args[(uint64_t)arg0] = count(); }
carrick*:::hvpatch-syscall-service
/pid == $target || progenyof($target)/
{
    @end[(uint64_t)arg3] = count();
    @duration[(uint64_t)arg3] = sum((uint64_t)arg4);
    @maximum[(uint64_t)arg3] = max((uint64_t)arg4);
    @by_task[(int32_t)arg0, (int32_t)arg1, (uint64_t)arg3] = sum((uint64_t)arg4);
}
proc:::exit /pid == $target/ { root_exited = 1; }
dtrace:::ERROR { errors = 1; }
tick-1s { seconds++; }
tick-1s /seconds >= 10/
{
    printf("SERVICEBUDGET1|seen=%d|errors=%d|root_exited=%d\n", seen, errors, root_exited);
    printa("SERVICEBUDGET1|begin|nr=%llu|count=%@d\n", @begin);
    printa("SERVICEBUDGET1|args|nr=%llu|count=%@d\n", @args);
    printa("SERVICEBUDGET1|end|nr=%llu|count=%@d\n", @end);
    printa("SERVICEBUDGET1|duration|nr=%llu|ns=%@d\n", @duration);
    printa("SERVICEBUDGET1|maximum|nr=%llu|ns=%@d\n", @maximum);
    printa("SERVICEBUDGET1|task|pid=%d|tid=%d|nr=%llu|ns=%@d\n", @by_task);
    exit(seen && !errors && root_exited ? 0 : 2);
}
