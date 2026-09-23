#!/usr/sbin/dtrace -qs
/* Complete-run inotify09 population census (not timing evidence).
 * Unlike the small fixture's fixed ten-second bound, stop on root completion
 * or reject at forty seconds. A traced LTP time-limit exit is a different
 * workload population from an untraced loop-limit completion; retain that fact.
 * HIGH perturbation: three aggregates per host-serviced syscall. No Linux
 * implementation source copied. Derived from hvpatch-syscall-population.d.
 * Count host-serviced requests, argument events and closed service windows.
 * ABI: begin/service arg3=Linux nr; args arg0=Linux nr; qualified from
 * carrick-observability/probes.rs and live counts on this host before use.
 * MEDIUM perturbation: three USDT aggregates per request, no timing claims.
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
{ @end[(uint64_t)arg3] = count(); }
proc:::exit /pid == $target/ { root_exited = 1; }
dtrace:::ERROR { errors = 1; }
tick-1s { seconds++; }
tick-1s /root_exited || seconds >= 40/
{
    printf("SYSCALLPOP1|seen=%d|errors=%d|root_exited=%d\n", seen, errors, root_exited);
    printa("SYSCALLPOP1|begin|nr=%llu|count=%@d\n", @begin);
    printa("SYSCALLPOP1|args|nr=%llu|count=%@d\n", @args);
    printa("SYSCALLPOP1|end|nr=%llu|count=%@d\n", @end);
    exit(seen && !errors && root_exited ? 0 : 2);
}
