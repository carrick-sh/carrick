#pragma D option quiet
#pragma D option bufsize=256m
#pragma D option aggsize=256m
#pragma D option dynvarsize=96m
#pragma D option ustackframes=40

/*
 * On-CPU profile that CLASSIFIES the program counter before deciding whether to
 * unwind it.
 *
 * `ustack()` cannot walk translated frames: JIT'd guest code uses x29 as a guest
 * register, so there is no frame-pointer chain to follow. Worse, dtrace does not
 * report that as an error -- it scans and snaps each word to the nearest
 * preceding symbol, emitting plausible nonsense. Unwinding JIT samples therefore
 * costs buffer space and aggregation slots to produce garbage, which is why an
 * earlier unclassified profile landed only 24% of on-CPU time in usable stacks.
 *
 * `carrick*:::dsr-cache-bounds` publishes each process's JIT cache host-VA range
 * once at creation, so a sampled PC can be classified with two compares and the
 * unwinder is invoked ONLY for host frames.
 *
 * Tracking uses `dsr-cache-capacity`/`dsr-cache-bounds`, which fire once per
 * process. Never track on `dsr-cache-event`: it fires per cache event (136M+ on
 * a shared-translation go-build), which makes the tracer itself a dominant cost.
 */

carrick*:::dsr-cache-capacity { tracked[pid] = 1; }
carrick*:::dsr-cache-bounds
{
	tracked[pid] = 1;
	jit_start[pid] = arg0;
	jit_end[pid] = arg1;
}
proc:::create /tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
	/*
	 * The bounds MUST be inherited, not just the tracking flag. carrick forks a
	 * real host process per guest `clone(2)` -- ~50 for one go-build -- and the
	 * child inherits the parent's address space, JIT cache mapping included,
	 * until it builds its own (which re-fires `dsr-cache-bounds` and overwrites
	 * these). Without this, every forked child has bounds of zero and its
	 * translated samples are misclassified as host code.
	 */
	jit_start[args[0]->pr_pid] = jit_start[pid];
	jit_end[args[0]->pr_pid] = jit_end[pid];
}
proc:::exit   /tracked[pid]/ { tracked[pid] = 0; }

profile-997 /tracked[pid]/ { @all = count(); }
profile-997 /tracked[pid] && arg0 != 0/ { @kernel = count(); }

/* User sample inside this process's JIT cache: classify, never unwind. */
profile-997
/tracked[pid] && arg0 == 0 && jit_end[pid] != 0 &&
 uregs[R_PC] >= jit_start[pid] && uregs[R_PC] < jit_end[pid]/
{
	@jit = count();
}

/* User sample in host code: this one has frame pointers, so unwind it. */
profile-997
/tracked[pid] && arg0 == 0 &&
 (jit_end[pid] == 0 || uregs[R_PC] < jit_start[pid] || uregs[R_PC] >= jit_end[pid])/
{
	@host = count();
	@hoststack[ustack()] = count();
	@hostleaf[umod(uregs[R_PC]), usym(uregs[R_PC])] = count();
}

tick-1s { elapsed++; }
tick-1s /elapsed >= 60/ { exit(0); }

END
{
	printa("BUCKET all=%@u\n", @all);
	printa("BUCKET kernel=%@u\n", @kernel);
	printa("BUCKET jit=%@u\n", @jit);
	printa("BUCKET host=%@u\n", @host);
	/*
	 * Truncate generously, then aggregate by NAME offline. dtrace keys
	 * `usym`/`ustack` on (pid, address), so ~50 guest processes running the same
	 * binary fragment one hot symbol into ~50 separate aggregation entries. A
	 * small `trunc` therefore discards nearly all of the signal and leaves a
	 * ranking that is an artifact of process count.
	 */
	printf("\n===== HOST LEAVES =====\n");
	trunc(@hostleaf, 4000);
	printa("LEAF %A %A  %@u\n", @hostleaf);
	printf("\n===== HOST STACKS =====\n");
	trunc(@hoststack, 600);
	printa("%k  %@u\n", @hoststack);
}
