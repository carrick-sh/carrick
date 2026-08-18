#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-wait-roundtrip.d — partition the guest fork()+_exit()+waitpid()
 * ROUND TRIP into its three consecutive host intervals, with ONE instrument.
 *
 * The two existing fork ledgers (hvpatch-phase4-fork-runtime-stages.d and
 * hvpatch-phase4-fork-process-spec-stages.d) both stop at the parent's fork
 * critical section. They cannot say whether fork or the child's exit/teardown
 * dominates a fork-and-reap workload, because they never observe the exit half.
 * This script closes that gap by joining the two halves on the CHILD's Linux
 * pid, so the split is measured by one instrument and the shares are citable
 * against each other.
 *
 * Partition per iteration i, all on the shared-VM carrier:
 *   fork    = the parent's fork critical section
 *             (hvpatch-fork-runtime-stage phase 9 carries its own elapsed_ns)
 *   child   = fork-return .. child process-exit publication
 *             (child boot, guest run, sibling drain, Kernel exit publication,
 *             stage-2 retirement, ASID/bank retirement, vCPU destroy)
 *   reap    = child process-exit publication .. the NEXT fork's critical
 *             section starting — i.e. the parent noticing the zombie,
 *             returning from wait4, and re-entering fork
 * `iter` is fork_start(i+1) - fork_start(i) and equals fork+child+reap up to
 * the probe firings themselves.
 *
 * Provider ABI qualified live on Darwin/arm64 (macOS 27.0, 2026-08-18) against
 * this tree's carrick-observability declarations:
 *   carrick*:::hvpatch-fork-runtime-stage
 *     arg0 uint32_t phase (9 = cumulative parent critical section; it ENCLOSES
 *          phases 0..8 and must never be summed with them)
 *     arg1 int32_t parent_pid, arg2 int32_t child_pid,
 *     arg3 int32_t forking_tid, arg4 uint64_t elapsed_ns
 *   carrick*:::hvpatch-guest-lifecycle
 *     arg0 uint32_t phase (5 = ProcessExit, fired only AFTER Kernel status,
 *          descriptor teardown and backend root-slot/ASID retirement commit),
 *     arg1 int32_t pid, arg2 int32_t ppid, arg3 int32_t tid, arg4 uint32_t asid
 *   carrick*:::hvpatch-topology-lock
 *     arg0 uint32_t operation (7 = ProcessRetire), arg1 uint32_t phase
 *     (0 requested, 1 acquired, 2 released), arg2 int32_t guest_pid,
 *     arg3 int32_t guest_tid, arg4 uint64_t elapsed_ns (wait on acquired,
 *     hold on released)
 * The Linux identities ride the probe arguments; DTrace's own pid/tid stay
 * Darwin's. The predicate follows Carrick descendants because a raw HVPatch
 * run may place the VM carrier in a child of the launched process.
 *
 * Perturbation: three low-frequency scalar USDT firings per fork+exit cycle
 * plus the topology pair. Only SAME-INSTRUMENT ratios (fork vs child vs reap)
 * are citable; the absolute microseconds are inflated and the untraced
 * reducer remains the performance gate. A valid capture has `pairs` equal to
 * the guest's fork count minus one and zero orphan/error counters.
 */

#pragma D option quiet
#pragma D option dynvarsize=16m

dtrace:::BEGIN
{
	started = timestamp;
	pairs = 0;
	orphan_exits = 0;
	errors = 0;
	bounded = 0;
	last_exit_ts = 0;
	last_fork_start = 0;
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 == 9/
{
	this->child = (int)arg2;
	this->end = timestamp;
	this->start = this->end - (uint64_t)arg4;
	fork_end[this->child] = this->end;
	@fork_ns = sum((uint64_t)arg4);
	@fork_hist = quantize((uint64_t)arg4);
	@fork_n = count();
}

/*
 * Second clause: the reap and whole-iteration terms need the PREVIOUS
 * iteration's anchors, so they are read before the assignment above would
 * overwrite them. DTrace evaluates clauses for one probe firing in program
 * order, so this clause runs after the one above; both read their own copies.
 */
carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 == 9 && last_exit_ts != 0/
{
	this->start2 = timestamp - (uint64_t)arg4;
	@reap_ns = sum(this->start2 - last_exit_ts);
	@reap_hist = quantize(this->start2 - last_exit_ts);
	@reap_n = count();
	@iter_ns = sum(this->start2 - last_fork_start);
	@iter_n = count();
	pairs++;
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 == 9/
{
	last_fork_start = timestamp - (uint64_t)arg4;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 5 && fork_end[(int)arg1] != 0/
{
	this->child = (int)arg1;
	@child_ns = sum(timestamp - fork_end[this->child]);
	@child_hist = quantize(timestamp - fork_end[this->child]);
	@child_n = count();
	last_exit_ts = timestamp;
	fork_end[this->child] = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 5 && fork_end[(int)arg1] == 0/
{
	orphan_exits++;
}

/* Stage-2 / ASID retirement is the largest named sub-interval of `child`. */
carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 == 7 && arg1 == 1/
{
	@retire_wait_ns = sum((uint64_t)arg4);
	@retire_wait_n = count();
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 == 7 && arg1 == 2/
{
	@retire_hold_ns = sum((uint64_t)arg4);
	@retire_hold_hist = quantize((uint64_t)arg4);
	@retire_hold_n = count();
}

dtrace:::ERROR
{
	errors++;
}

proc:::exit
/pid == $target/
{
	exit(0);
}

profile:::tick-1sec
/timestamp - started > 300 * 1000000000/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCHFORKWAIT|summary|pairs=%d|orphan_exits=%d|bounded=%d|errors=%d\n",
	    pairs, orphan_exits, bounded, errors);
	printa("HVPATCHFORKWAIT|fork-n|%@u\n", @fork_n);
	printa("HVPATCHFORKWAIT|fork-ns|%@u\n", @fork_ns);
	printa("HVPATCHFORKWAIT|child-n|%@u\n", @child_n);
	printa("HVPATCHFORKWAIT|child-ns|%@u\n", @child_ns);
	printa("HVPATCHFORKWAIT|reap-n|%@u\n", @reap_n);
	printa("HVPATCHFORKWAIT|reap-ns|%@u\n", @reap_ns);
	printa("HVPATCHFORKWAIT|iter-n|%@u\n", @iter_n);
	printa("HVPATCHFORKWAIT|iter-ns|%@u\n", @iter_ns);
	printa("HVPATCHFORKWAIT|retire-wait-n|%@u\n", @retire_wait_n);
	printa("HVPATCHFORKWAIT|retire-wait-ns|%@u\n", @retire_wait_ns);
	printa("HVPATCHFORKWAIT|retire-hold-n|%@u\n", @retire_hold_n);
	printa("HVPATCHFORKWAIT|retire-hold-ns|%@u\n", @retire_hold_ns);
	printf("HVPATCHFORKWAIT|fork-hist\n");
	printa(@fork_hist);
	printf("HVPATCHFORKWAIT|child-hist\n");
	printa(@child_hist);
	printf("HVPATCHFORKWAIT|reap-hist\n");
	printa(@reap_hist);
	printf("HVPATCHFORKWAIT|retire-hold-hist\n");
	printa(@retire_hold_hist);
}
