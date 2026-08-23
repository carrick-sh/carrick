/*
 * Signal-publication attribution: WHO publishes each guest-visible signal,
 * with the user stack at the publication point.
 *
 * (a) What it measures: every carrick*:::signal-publish firing (arg0 = target
 *     tid or 0 for process-directed, arg1 = Linux signum, arg2 = route tag),
 *     printed with a 16-frame user stack — answering "which code path
 *     published SIGALRM/SIGCHLD/... and therefore owns the wake obligation".
 *     The kernel-graph publishers document "the caller owns wakeup/kick
 *     routing"; a signal that lands in the task pending set while its target
 *     stays parked (the waitrestart hang shape) means the publisher on this
 *     stack skipped that duty.
 * (b) Provider ABI facts (qualified live on macOS 26/arm64, 2026-08-23):
 *     carrick*:::signal-publish exists in carrick-runtime's probes; use
 *     dtrace -Z / carrick trace -s so it arms before the carrier registers
 *     DOF. HVPatch guest tasks share one carrier pid; per-task attribution
 *     comes from the printed stack, not from pid/tid.
 * (c) Perturbation: one firing per published signal — negligible except in
 *     signal storms; safe on hang investigations.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("signal-publish attribution started at %Y\n", walltimestamp);
}

carrick*:::signal-publish
/pid == $target || progenyof($target)/
{
    printf("[publish] target_tid=%d signum=%d route=%d\n",
        (int)arg0, (int)arg1, (int)arg2);
    ustack(16);
}

tick-1s { secs++; }
tick-1s /secs >= 30/ { timed_out = 1; exit(0); }

dtrace:::END
{
    printf("trace_timed_out=%d\n", timed_out);
}
