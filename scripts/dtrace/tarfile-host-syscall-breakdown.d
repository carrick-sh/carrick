#pragma D option quiet
#pragma D option dynvarsize=32m
#pragma D option aggsize=32m
#pragma D option bufsize=16m

/*
 * GUEST FS SYSCALL -> HOST SYSCALL AMPLIFICATION BREAKDOWN
 *
 * (a) What it measures: for guest `unlinkat` (nr 35) and `mkdirat` (nr 34),
 *     aggregates which Darwin host syscalls are executed by Carrick per call.
 *
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-09-07):
 *     `carrick*:::syscall-entry`: arg0 = canonical Linux syscall nr.
 *     `syscall:::entry`: Darwin kernel syscall provider.
 *     `carrick*:::guest-exit`: fires on guest termination, enabling clean exit.
 *
 * (c) Perturbation: YES. Host syscall interception adds ~1-2 us per host syscall.
 */

dtrace:::BEGIN
{
	secs = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 34 || arg0 == 35)/
{
	self->in_fs = 1;
	self->guest_nr = arg0;
	@guest_calls[arg0] = count();
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->in_fs/
{
	@host_calls[self->guest_nr, probefunc] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->in_fs/
{
	self->in_fs = 0;
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
	printf("\n=== guest syscall calls ===\n");
	printa("guest nr %-6d: %@12u\n", @guest_calls);
	printf("\n=== host syscalls while servicing guest syscalls ===\n");
	printa("guest nr %-6d host %-24s: %@12u\n", @host_calls);
}
