#pragma D option quiet
#pragma D option dynvarsize=32m
#pragma D option aggsize=32m
#pragma D option bufsize=16m

/*
 * WHICH GUEST SYSCALLS CONSUME THE EXEC-WINDOW DISPATCH TIME?
 *
 * (a) What it measures: per guest-syscall WALL time (timestamp) and ON-CPU
 *     time (vtimestamp) between carrick's USDT `syscall-entry` and
 *     `syscall-return`, aggregated by syscall name across the whole guest
 *     process tree (`progenyof($target)`), plus per-name counts and maxima.
 *     Written for the 2026-08-03 exec-window attribution: the untraced DSR
 *     profile showed ~21 ms of `phase_syscall_dispatch_ns` across ~280
 *     syscalls per `compile -V` exec with no per-syscall split — this script
 *     provides the RANKING. Wall - CPU per name separates blocked-in-host
 *     waits (futex/wait4 park) from dispatch compute.
 *
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-08-03):
 *     `carrick*:::syscall-entry` arg0 = CANONICAL Linux syscall nr, arg1 =
 *     host pointer to the syscall NAME string (copyinstr-able), arg2 = host
 *     address of the 6-u64 arg array. `syscall-return` arg0 = nr, arg1 =
 *     name, arg2 = retval, arg3 = errno. The `pid` provider does NOT follow
 *     fork; these USDT probes re-register in every forked child and DO,
 *     under the `pid == $target || progenyof($target)` predicate.
 *
 * (c) Perturbation: YES, structural. An attached DTrace consumer makes dyld
 *     re-register the binary's DOF section on EVERY guest self-reexec
 *     (measured 9.4 ms traced vs 0.10 ms untraced for that chain segment —
 *     see docs/perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md),
 *     and two probes fire per guest syscall. Totals from this script are NOT
 *     comparable to untraced numbers; only the within-trace ranking and the
 *     per-name wall/CPU RATIOS are citable.
 *
 * Usage:
 *   target/release/carrick trace \
 *     --script scripts/dtrace/exec-window-syscall-latency.d \
 *     --trace-out /tmp/syscall-latency.out -- run --exec-backend native ...
 */

dtrace:::BEGIN
{
	secs = 0;
}

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
	self->wall = timestamp;
	self->cpu = vtimestamp;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->wall/
{
	this->name = copyinstr(arg1);
	@wall[this->name] = sum(timestamp - self->wall);
	@cpu[this->name] = sum(vtimestamp - self->cpu);
	@wallmax[this->name] = max(timestamp - self->wall);
	@calls[this->name] = count();
	self->wall = 0;
	self->cpu = 0;
}

/* Bound the trace: a hung guest must not stream forever. */
tick-1s
{
	secs++;
}

tick-1s
/secs >= 120/
{
	exit(0);
}

dtrace:::END
{
	printf("\n=== per-syscall totals across the guest tree ===\n");
	printf("--- calls ---\n");
	printa("%-24s %@12u\n", @calls);
	printf("--- wall ns ---\n");
	printa("%-24s %@12u\n", @wall);
	printf("--- on-cpu ns ---\n");
	printa("%-24s %@12u\n", @cpu);
	printf("--- wall max ns (single slowest call) ---\n");
	printa("%-24s %@12u\n", @wallmax);
}
