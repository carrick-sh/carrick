#pragma D option quiet
#pragma D option dynvarsize=32m
#pragma D option aggsize=32m
#pragma D option bufsize=16m

/*
 * HOST OPENAT / FSTATAT CALLER STACKS DURING GUEST UNLINKAT
 *
 * (a) What it measures: user backtraces of host `openat` calls while servicing
 *     guest `unlinkat` (nr 35).
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-09-07):
 *     `carrick*:::syscall-entry`: arg0 = canonical Linux syscall nr.
 *     `syscall::openat:entry`: Darwin kernel openat.
 *     `carrick*:::guest-exit`: fires on guest exit.
 * (c) Perturbation: YES. Sampling user stacks on openat adds overhead.
 */

dtrace:::BEGIN
{
	secs = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 35/
{
	self->in_unlinkat = 1;
}

syscall::openat:entry
/(pid == $target || progenyof($target)) && self->in_unlinkat/
{
	@openat_stacks[ustack(12)] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->in_unlinkat/
{
	self->in_unlinkat = 0;
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
	printf("\n=== host openat ustack during guest unlinkat ===\n");
	printa(@openat_stacks);
}
