#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=16m
#pragma D option dynvarsize=16m

/*
 * Where does WALL time go across a whole Carrick process tree?
 *
 * Carrick's own DSR profile accounts for on-CPU phases inside the run loop, so a
 * cost that is neither CPU nor a tracked phase is invisible to it. Measured on
 * the fork benchmark, that blind spot is ~76% of the wall clock: the parent
 * blocks ~3.65 ms per fork while consuming 3.1 ms of CPU across the WHOLE run,
 * and the child burns only ~0.94 ms. So the time is OFF-CPU, and off-CPU time is
 * attributable only by the stack that blocked.
 *
 * This is deliberately kernel-provider only (`sched`, `profile`) so it is safe on
 * a continuing process and needs no USDT, no pid provider, and no rebuild. It
 * follows the whole tree (pid set + proctitle admission), because a guest fork
 * makes a NEW host process and per-pid tracing would lose the children under study.
 *
 * Slowdown is accepted: this measures where time goes, not how fast we are.
 *
 * Reads:
 *   off-cpu ns by blocking stack  -- WHY we wait (the actionable one)
 *   off-cpu ns by pid            -- parent vs children split
 *   on-cpu samples by stack      -- where CPU actually goes
 *   sleep/wakeup counts          -- voluntary blocks vs preemption
 */

/*
 * Cost note: `sched:::off-cpu` fires on EVERY context switch machine-wide, so the
 * predicate runs at ~100k/s on a busy box. `progenyof()` walks the process tree
 * on each hit and is far too expensive here — a first attempt with it never even
 * reached the guest's first instruction in 4 minutes. Instead track a pid SET,
 * seeded with $target and extended on proc:::create, so the hot predicate is a
 * single O(1) associative lookup. This also naturally EXCLUDES unrelated carrick
 * processes (e.g. a conformance gate running concurrently), which an
 * `execname == "carrick"` filter would have swept in.
 */
dtrace:::BEGIN
{
    printf("offcpu-attribution: target=%d\n", $target);
    start = timestamp;
    track[$target] = 1;
}

/* A guest fork makes a NEW host process; follow it into the tracked set. */
proc:::create
/track[curpsinfo->pr_pid]/
{
    track[args[0]->pr_pid] = 1;
}

/*
 * Identity guard. MEASURED on macOS: `curpsinfo->pr_psargs` for these processes
 * is literally "carrick" -- the exec argv only. Carrick's `carrick:<run-id>:`
 * proctitle rewrite (what `ps` shows and `scripts/sudo/kill.sh` scopes on) never
 * reaches psargs here, so a run-id match against psargs finds NOTHING and cannot
 * scope a measurement to one run. Scoping therefore comes from the pid set above;
 * this strstr only asserts the process really is carrick, so an unrelated pid that
 * somehow entered the set cannot silently contribute samples.
 */
/*
 * Off-CPU: stamp the moment this thread leaves the CPU. `curlwpsinfo->pr_state`
 * distinguishes a voluntary block (SSLEEP) from involuntary preemption (SRUN) —
 * conflating them would blame our code for the scheduler merely rotating us.
 */
sched:::off-cpu
/track[pid] && strstr(curpsinfo->pr_psargs, "carrick") != NULL/
{
    self->off_ts = timestamp;
    self->off_state = curlwpsinfo->pr_state;
}

sched:::on-cpu
/self->off_ts/
{
    this->delta = timestamp - self->off_ts;

    /* Voluntary blocks only: this is the latency we are hunting. */
    @off_by_stack[ustack(24)] = sum(this->delta);
    @off_by_pid[pid] = sum(this->delta);
    @off_total = sum(this->delta);
    @off_hist = quantize(this->delta / 1000);

    self->off_ts = 0;
    self->off_state = 0;
}

/* On-CPU sampling: the other half of the wall clock. */
profile-197
/track[pid]/
{
    @on_by_stack[ustack(24)] = count();
    @on_by_pid[pid] = count();
    @on_samples = count();
}

/* Voluntary sleeps vs wakeups: a large sleep count with tiny CPU means a
 * handshake/round-trip pattern rather than real work. */
sched:::sleep
/track[pid]/
{
    @sleeps[pid] = count();
}

sched:::wakeup
/track[pid]/
{
    @wakeups[pid] = count();
}

dtrace:::END
{
    printf("\n=== wall ns traced: %d ===\n", timestamp - start);

    printf("\n=== off-CPU ns TOTAL ===\n");
    printa("%@d\n", @off_total);

    printf("\n=== on-CPU samples TOTAL (197Hz) ===\n");
    printa("%@d\n", @on_samples);

    printf("\n=== off-CPU ns by pid ===\n");
    printa("  pid %-8d %@d\n", @off_by_pid);

    printf("\n=== sleeps by pid ===\n");
    printa("  pid %-8d %@d\n", @sleeps);

    printf("\n=== wakeups by pid ===\n");
    printa("  pid %-8d %@d\n", @wakeups);

    printf("\n=== off-CPU duration distribution (microseconds) ===\n");
    printa("%@d\n", @off_hist);

    printf("\n=== TOP off-CPU BLOCKING STACKS (ns) ===\n");
    trunc(@off_by_stack, 12);
    printa("%@d%k\n", @off_by_stack);

    printf("\n=== TOP on-CPU STACKS (samples) ===\n");
    trunc(@on_by_stack, 10);
    printa("%@d%k\n", @on_by_stack);
}
