#pragma D option quiet
#pragma D option dynvarsize=32m
#pragma D option aggsize=32m
#pragma D option bufsize=16m

/*
 * TARFILE / VFS MUTATION SYSCALL LATENCY PROFILE
 *
 * (a) What it measures: per guest-syscall wall time (timestamp) and on-CPU time
 *     (vtimestamp) between carrick's USDT `syscall-entry` and `syscall-return`,
 *     aggregated by syscall name across the workload.
 *     Separates wall vs CPU time per syscall name to isolate where tarfile /
 *     filesystem mutation operations spend latency.
 *
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-09-07):
 *     `carrick*:::syscall-entry`: arg0 = canonical Linux syscall nr, arg1 = host
 *     pointer to syscall name string (copyinstr), arg2 = host address of 6-u64
 *     args. `syscall-return`: arg0 = nr, arg1 = name, arg2 = retval, arg3 = errno.
 *     `carrick*:::guest-exit`: fires on guest termination, enabling clean exit.
 *
 * (c) Perturbation: YES, structural. Two USDT probes fire per guest syscall.
 *     Within-trace ranking and per-name wall/CPU ratios are citable; absolute
 *     wall time includes DTrace interception overhead.
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

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
	exit(0);
}

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
