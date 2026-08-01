#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option aggsize=128m
#pragma D option dynvarsize=64m

/*
 * Directional native on-CPU ownership profile.
 *
 * Aggregate sampled (pid, user-PC) pairs without unwinding them, retain the
 * process-owned private/shared translated-range announcements, and join the
 * two streams offline with scripts/perf/native_pc_range_directional.py. The
 * deliberately load-bounded 197 Hz rate reduces observer work on fork-heavy
 * native workloads; this remains directional evidence, not a timing gate.
 * This deliberately is not a lossless DSRPROF2 capture or a timing gate.
 *
 * Run with dtrace -c and an exact CARRICK_RUN_ID. The target-exit clause
 * normally closes the capture; the 90-second tick is only a bounded fallback.
 */

dtrace:::BEGIN
{
	printf("PCPROFILE1|config|sample_hz=197\n");
	elapsed = 0;
	target_exit = 0;
	timed_out = 0;
	tracked[(pid_t)0] = 0;
	current_epoch[(pid_t)0] = (uint64_t)0;
	private_start[(pid_t)0] = (uint64_t)0;
	private_end[(pid_t)0] = (uint64_t)0;
}

carrick*:::host-translated-range-reset
/(pid == $target || progenyof($target))/
{
	tracked[pid] = 1;
	current_epoch[pid] = (uint64_t)arg0;
	private_start[pid] = (uint64_t)0;
	private_end[pid] = (uint64_t)0;
	printf("PCPROFILE1|reset|pid=%d|epoch=%d\n", pid, arg0);
}

carrick*:::host-translated-private-range
/(pid == $target || progenyof($target))/
{
	tracked[pid] = 1;
	current_epoch[pid] = (uint64_t)arg0;
	private_start[pid] = (uint64_t)arg2;
	private_end[pid] = (uint64_t)arg3;
	printf("PCPROFILE1|range|kind=private|pid=%d|epoch=%d|sequence=%d|start=%#x|end=%#x\n",
	    pid, arg0, arg1, arg2, arg3);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target))/
{
	tracked[pid] = 1;
	current_epoch[pid] = (uint64_t)arg0;
	printf("PCPROFILE1|range|kind=shared|pid=%d|epoch=%d|sequence=%d|start=%#x|end=%#x\n",
	    pid, arg0, arg1, arg3, arg4);
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
	current_epoch[args[0]->pr_pid] = current_epoch[pid];
	private_start[args[0]->pr_pid] = private_start[pid];
	private_end[args[0]->pr_pid] = private_end[pid];
}

/*
 * Symbolize only samples outside the current private cache. Bind every leaf
 * to its exact (pid, epoch, PC), so the analyzer can exclude shared translated
 * PCs before trusting or aggregating named host symbols. Record the matching
 * PC histogram entry in this same clause: a translated-range reset on another
 * thread can otherwise change current_epoch between two profile clauses. The
 * PC/range join is the ownership authority; symbol text alone never does.
 */
profile-197
/tracked[pid] && current_epoch[pid] != (uint64_t)0 && arg0 == 0 &&
 (private_end[pid] == (uint64_t)0 ||
 uregs[R_PC] < private_start[pid] || uregs[R_PC] >= private_end[pid])/
{
	@outside_user_pc[(pid_t)pid, current_epoch[pid],
	    (uint64_t)uregs[R_PC]] = count();
	@outside_leaf[(pid_t)pid, current_epoch[pid],
	    (uint64_t)uregs[R_PC], umod(uregs[R_PC]),
	    usym(uregs[R_PC])] = count();
}

profile-197
/tracked[pid] && current_epoch[pid] != (uint64_t)0 && arg0 == 0 &&
 private_end[pid] != (uint64_t)0 &&
 uregs[R_PC] >= private_start[pid] && uregs[R_PC] < private_end[pid]/
{
	@private_user_pc[(pid_t)pid, current_epoch[pid],
	    (uint64_t)uregs[R_PC]] = count();
}

profile-197
/tracked[pid] && current_epoch[pid] != (uint64_t)0 && arg0 != 0/
{
	@kernel_pid[(pid_t)pid, current_epoch[pid]] = count();
}

proc:::exit
/pid == $target/
{
	target_exit++;
	exit(0);
}

proc:::exit
/tracked[pid]/
{
	tracked[pid] = 0;
	current_epoch[pid] = (uint64_t)0;
	private_start[pid] = (uint64_t)0;
	private_end[pid] = (uint64_t)0;
}

tick-1s
{
	elapsed++;
}

tick-1s
/elapsed >= 90/
{
	timed_out = 1;
	exit(0);
}

END
{
	printa("PCPROFILE1|sample|kind=user|pid=%d|epoch=%d|pc=%#x|count=%@u\n",
	    @outside_user_pc);
	printa("PCPROFILE1|sample|kind=user|pid=%d|epoch=%d|pc=%#x|count=%@u\n",
	    @private_user_pc);
	printa("PCPROFILE1|sample|kind=kernel|pid=%d|epoch=%d|count=%@u\n",
	    @kernel_pid);
	printa("PCLEAF2|pid=%d|epoch=%d|pc=%#x|module=%A|symbol=%A|count=%@u\n",
	    @outside_leaf);
	printf("PCPROFILE1|completion|target_exit=%d|timed_out=%d\n",
	    target_exit, timed_out);
}
