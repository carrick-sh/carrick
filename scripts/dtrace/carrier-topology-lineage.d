#pragma D option quiet
#pragma D option dynvarsize=16m
#pragma D option bufsize=8m
#pragma D option strsize=256

/*
 * Fail-closed host-process lineage ledger for Carrick's carrier topology gate.
 *
 * (a) WHAT IT MEASURES. Every Darwin process born anywhere below the exact
 *     `carrick trace` target, from the target's birth until the last tracked
 *     descendant exits. Each child owns its own `tracked[]` row, so it remains
 *     attributable after its parent exits and launchd reparents it. The
 *     controller validates the ordered CREATE/EXEC/EXIT ledger against the
 *     arm's exact carrier-birth budget; process-title snapshots are not birth
 *     authority.
 *
 * (b) PROVIDER ABI FACTS. Qualified on Darwin/arm64: on `proc:::create`, `pid`
 *     is the creating parent and `args[0]->pr_pid` is the new child PID.
 *     `proc:::exec-success` fires in the successfully replaced process and the
 *     built-in `execname` is its new basename. `proc:::exit` fires in the
 *     exiting PID. These are kernel-provider events, so they follow children;
 *     no pid-provider probe is used.
 *
 * (c) PERTURBATION. Low but non-zero: three process-lifecycle providers plus a
 *     one-second safety tick. This is a correctness census, never a performance
 *     measurement. Any DTrace ERROR, tick truncation, consumer drop, missing
 *     summary, or non-zero live count invalidates the arm.
 */

dtrace:::BEGIN
{
	tracked[$target] = 1;
	live = 1;
	births = 0;
	exits = 0;
	errors = 0;
	seconds = 0;
	complete = 0;
	printf("CTOP1|BEGIN|target=%d\n", $target);
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
	this->child = args[0]->pr_pid;
	tracked[this->child] = 1;
	live++;
	births++;
	printf("CTOP1|CREATE|parent=%d|child=%d|time_ns=%llu\n",
	    pid, this->child, timestamp);
}

proc:::exec-success
/tracked[pid] && pid != $target/
{
	printf("CTOP1|EXEC|pid=%d|name=%s|time_ns=%llu\n",
	    pid, execname, timestamp);
}

proc:::exit
/tracked[pid]/
{
	tracked[pid] = 0;
	live--;
	exits++;
	printf("CTOP1|EXIT|pid=%d|time_ns=%llu|live=%d\n",
	    pid, timestamp, live);
}

dtrace:::ERROR
{
	errors++;
	printf("CTOP1|ERROR|cpu=%d|epid=%d\n", cpu, arg1);
	exit(2);
}

tick-1s
{
	seconds++;
}

tick-100ms
/live == 0 && !complete/
{
	complete = 1;
	exit(0);
}

tick-1s
/seconds >= 120 && !complete/
{
	printf("CTOP1|TRUNCATED|seconds=%d|live=%d\n", seconds, live);
	exit(3);
}

dtrace:::END
{
	printf("CTOP1|SUMMARY|target=%d|births=%d|exits=%d|live=%d|complete=%d|errors=%d\n",
	    $target, births, exits, live, complete, errors);
}
