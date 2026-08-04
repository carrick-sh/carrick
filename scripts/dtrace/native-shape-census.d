#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option bufsize=16m
#pragma D option dynvarsize=64m

/*
 * Classify sampled user-mode instruction words across a native-DSR guest
 * process tree by emitted-code shape.
 *
 * The DSR emitter owns two physical registers the guest never sees: x28 is
 * the DsrContext pointer (all guest x28 uses are virtualized into context
 * slots) and x18 is an internal scratch. Any sampled word that stores or
 * loads through x28, any 64-bit UBFM writing x18, the exact `cbz x18, +8`
 * aperture check, NZCV system-register moves, LDAR generation-guard loads
 * and x17 exit materializations are therefore DSR-inserted overhead with
 * certainty, while remaining words are (approximately) the guest's own
 * computation plus inserted arithmetic that shares generic encodings. The
 * split is a lower bound on emitted-code overhead residency.
 *
 * Samples are proportional under uniform tracing overhead; absolute times
 * from a traced run are never wall evidence.
 *
 * Provider ABI qualified live on macOS 26A5388g (2026-08-03):
 * `proc:::create`, `proc:::exit`, and `profile-997` all list on this host;
 * successful captures on this host qualified `proc:::create` child identity as
 * `args[0]->pr_pid`, `proc:::exit` arg0 as the CLD_* exit reason, profile arg1
 * as the sampled PC, and carrick's `dsr-cache-bounds` arguments as the exact
 * half-open JIT-cache range [arg0, arg1).
 * The 997 Hz sampling plus aggregation is perturbing; use it only for
 * same-instrument attribution ratios, never absolute timing.
 *
 * The exact JIT predicate below is load-bearing. A 2026-08-03 trusted-route
 * capture using the older "not main Mach-O/shared-cache" approximation admitted
 * 9,296 host-text samples after self-reexec and 20 samples from the orchestrator
 * PID. Those samples correctly failed the offline snapshot join. Cache bounds
 * are inherited across fork until the child publishes its own range, matching
 * the native-jit-aware profiler's already-qualified lifecycle contract.
 *
 * HAZARD (2026-07-28, unexplained): enabling the copyin clause below against
 * a live native-DSR guest killed the guest 2/2 times within about a second
 * of guest start ("DSR could not read guest instruction at <wild address>"),
 * with zero recorded copyin errors, while the same script without copyin and
 * untraced runs were clean. Until that interaction is root-caused, prefer
 * the PC-histogram + retirement code-snapshot pipeline and leave the copyin
 * clause commented out.
 */

dtrace:::BEGIN
{
	tracked[$target] = 1;
	jit_start[$target] = (uint64_t)0;
	jit_end[$target] = (uint64_t)0;
	copyin_errors = 0;
	bounded = 0;
	target_completed = 0;
	target_exit_reason = 0;
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
	jit_start[args[0]->pr_pid] = jit_start[pid];
	jit_end[args[0]->pr_pid] = jit_end[pid];
}

proc:::exit
/tracked[pid] && pid != $target/
{
	tracked[pid] = 0;
	jit_start[pid] = (uint64_t)0;
	jit_end[pid] = (uint64_t)0;
}

proc:::exit
/pid == $target/
{
	target_completed = 1;
	target_exit_reason = arg0;
	exit(0);
}

carrick*:::dsr-cache-bounds
/(pid == $target || progenyof($target))/
{
	tracked[pid] = 1;
	jit_start[pid] = arg0;
	jit_end[pid] = arg1;
}

profile-997
/tracked[pid] && arg1 != 0/
{
	@total = count();
	@region[(jit_end[pid] != 0 && arg1 >= jit_start[pid] &&
	    arg1 < jit_end[pid]) ? "jit" : "non-jit"] = count();
}

/*
 * Word classification happens OFFLINE: sampled PCs recorded here join
 * against the per-process JIT code snapshots that
 * CARRICK_DSR_CODE_SNAPSHOT_DIR writes at guest-process retirement. The
 * copyin-based in-probe classifier this replaced is preserved in git
 * history; see the HAZARD note above before resurrecting it.
 */
profile-997
/tracked[pid] && arg1 != 0 && jit_end[pid] != 0 &&
    arg1 >= jit_start[pid] && arg1 < jit_end[pid]/
{
	@pc[pid, arg1] = count();
}

dtrace:::ERROR
{
	copyin_errors++;
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 120/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("SHAPE1|section=totals\n");
	printa("SHAPE1|samples=%@d\n", @total);
	printf("SHAPE1|copyin-errors=%d\n", copyin_errors);
	printf("SHAPE1|section=region\n");
	printa("SHAPE1|region=%s|count=%@d\n", @region);
	printf("SHAPE1|section=pc\n");
	printa("PC %d 0x%x %@d\n", @pc);
	printf("SHAPE1|complete|bounded=%d|target_completed=%d|target_exit_reason=%d\n",
	    bounded, target_completed, target_exit_reason);
}
