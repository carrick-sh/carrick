/*
 * syscall-amplification.d — where do carrick's HOST macOS syscalls come from?
 *
 * A single host/guest ratio is not actionable: it cannot distinguish "this Linux
 * syscall is expensive to emulate" from "carrick burns syscalls on its own
 * bookkeeping". So attribute every host syscall to the work in flight on that
 * thread, in three buckets:
 *
 *   linux:<name>   host syscalls issued while SERVICING a guest Linux syscall.
 *                  This is emulation amplification -- the honest "how many macOS
 *                  calls does one Linux call cost" number, per syscall.
 *   trap:<kind>    host syscalls issued while servicing a non-syscall guest exit
 *                  (fault, sensitive instruction, translation).
 *   carrick-only   host syscalls with NO guest work in flight: pure runtime
 *                  overhead -- schedulers, pumps, watchdogs, cross-thread
 *                  signalling. A large bucket here means the cost is OURS, and
 *                  no amount of per-syscall emulation tuning will touch it.
 *
 * MEASURED CONTEXT (go-build, 90 s): 2,902,383 host syscalls, of which
 * psynch_cvwait 866,678 + psynch_cvsignal 861,759 = 60%. Condvar traffic of that
 * size is the signature of a carrick-only bucket -- which is exactly what this
 * script exists to confirm or refute.
 *
 * Wallclock is NOT preserved; proportions are what this measures.
 *
 * Scope is execname rather than progenyof($target) so an ecosystem-wide gate run
 * is measured as a whole, and so the script can attach to a workload that is
 * already running. NOTE: guest processes keep execname "carrick" even though the
 * proctitle is rewritten to "carrick:<run-id>:" -- DTrace's pr_psargs never sees
 * that rewrite on macOS, so execname is the correct filter here.
 *
 * Run against a workload already in flight (arg1 = seconds to sample):
 *   sudo dtrace -q -s scripts/dtrace/syscall-amplification.d 60
 * Or own the workload:
 *   sudo dtrace -q -s scripts/dtrace/syscall-amplification.d 60 -c "<command>"
 */
#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=32m
#pragma D option aggsize=32m
#pragma D option defaultargs

dtrace:::BEGIN
{
	secs = 0;
	limit = $1 != 0 ? $1 : 60;
	printf("syscall-amplification: sampling carrick processes for %d s\n", limit);
}

/* --- guest Linux syscall window (carrick USDT; arg1 = name) --- */
carrick*:::syscall-entry
{
	self->ctx = strjoin("linux:", copyinstr(arg1));
	self->guest = 1;
	self->n = 0;			/* host syscalls this ONE guest call costs */
	@guest_total = count();
	@guest_by_name[copyinstr(arg1)] = count();
}

carrick*:::syscall-return
/self->guest/
{
	/* The COMPLETION path: how many host syscalls this instance actually cost.
	 * A mean hides the shape -- one guest read() costing 1 host call almost
	 * always and 40 occasionally is a completely different bug from one
	 * costing 8 every time. */
	@amp_dist[self->ctx] = quantize(self->n);
	@amp_sum[self->ctx] = sum(self->n);
	self->ctx = 0;
	self->guest = 0;
	self->n = 0;
}

/* --- every real macOS syscall carrick issues, bucketed by what it is FOR --- */
syscall:::entry
/execname == "carrick"/
{
	@host_total = count();
	@host_by_fn[probefunc] = count();
	@bucket[self->guest ? self->ctx : "carrick-only"] = count();
	@pair[self->guest ? self->ctx : "carrick-only", probefunc] = count();
	/* Which thread is generating it: a storm concentrated on one tid is a
	 * different problem from one spread across every guest thread. */
	@by_thread[pid, tid, self->guest ? "guest-work" : "carrick-only"] = count();
	self->n++;
}

/* Bound the window so the script always reaches END and flushes its
 * aggregations. A dtrace that never exits also leaks a root process that
 * cannot be reaped without a password. */
tick-1s { secs++; }
tick-1s /secs >= limit/ { exit(0); }

END
{
	printf("\n==== SYSCALL AMPLIFICATION ====\n");
	printf("GUEST_LINUX_TOTAL = "); printa("%@d\n", @guest_total);
	printf("HOST_MACOS_TOTAL  = "); printa("%@d\n", @host_total);

	printf("\n---- host syscalls BY BUCKET (the actionable split) ----\n");
	printa("  %-30s %@10d\n", @bucket);

	printf("\n---- top host syscalls overall ----\n");
	trunc(@host_by_fn, 12);
	printa("  %-24s %@10d\n", @host_by_fn);

	printf("\n---- top guest Linux syscalls ----\n");
	trunc(@guest_by_name, 12);
	printa("  %-24s %@10d\n", @guest_by_name);

	printf("\n---- top (bucket, host syscall) pairs ----\n");
	trunc(@pair, 20);
	printa("  %-30s %-22s %@10d\n", @pair);

	printf("\n---- host syscalls per guest syscall INSTANCE (total) ----\n");
	trunc(@amp_sum, 10);
	printa("  %-30s %@10d\n", @amp_sum);

	printf("\n---- busiest (pid, tid, bucket) ----\n");
	trunc(@by_thread, 10);
	printa("  pid=%-7d tid=%-8d %-14s %@10d\n", @by_thread);

	printf("\n---- per-instance distribution, top guest syscalls ----\n");
	trunc(@amp_dist, 4);
	printa("  %s%@d\n", @amp_dist);
}
