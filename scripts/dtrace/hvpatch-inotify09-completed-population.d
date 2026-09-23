#!/usr/sbin/dtrace -qs
/* Complete-run inotify09 host-service census, not timing evidence.
 * Stop on root completion or reject at forty seconds. A traced LTP time-limit
 * exit is a different population from loop-limit completion; the caller must
 * verify TPASS and "Exceeded execution loops" in the workload's own output.
 *
 * ABI: service-begin/service arg3=Linux nr; args arg0=Linux nr. Qualified live
 * on Apple M4, macOS 27.2 (26B5086k), 2026-09-22, via carrick trace.
 * Baseline SHA256 dcb0e51088f176b8e28dc71bc004b2d1dd024bd35fcdc8cbf563f50f47ac2955:
 * exactly 3,000,000 begins/args/ends for EACH of add_watch(27) and rm_watch(28);
 * lseek(62)=1, write(64)=32, clock_gettime(113)=1, all with closed windows.
 * Receipt: docs/perf-results/2026-09-21-syscall-floor/seek-header/.
 *
 * Counts cover kernel host service, NOT every guest syscall or HVF exit.
 * EL1 and engine fast paths bypass these probes. A low write/seek count does
 * not establish no I/O, no execution cost, or absence from the critical path.
 * HIGH perturbation: three USDT aggregations per request, no timing claims.
 * Aggregates avoid cross-CPU scalar increment loss. Root exit and workload
 * markers establish completion. Exits/waits may omit service-end on other
 * paths; retain unmatched rows rather than silently dropping them.
 * Use carrick trace --profile hvpatch-inotify09-population --trace-out FILE.
 * Rust binds the template digest, rejects drops/interruption/missing exit and
 * verifies every begin/argument/end row plus the pinned 3-million-pair count.
 * The caller must still check the LTP verdict; this is not a semantic pass.
 * Derived from hvpatch-syscall-population.d; no Linux source copied.
 */
#pragma D option quiet
#pragma D option aggsize=16m
#pragma D option dynvarsize=16m
BEGIN
{
    seconds = 0; seen = 0; errors = 0; root_exited = 0;
    printf("SYSCALLPOP1|header|program_sha256=/* CARRICK_SYSCALLPOP_PROGRAM_SHA256 */\n");
}
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
