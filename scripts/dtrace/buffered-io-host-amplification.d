#pragma D option quiet
#pragma D option dynvarsize=32m
#pragma D option aggsize=32m
#pragma D option bufsize=16m

/*
 * BUFFERED IO GUEST FS -> HOST SYSCALL AMPLIFICATION
 *
 * (a) What it measures: for guest openat (56), fstat (80), newfstatat (79),
 *     getdents64 (61), read (63), write (64), close (57), mmap (222), munmap (215),
 *     mkdirat (34), and unlinkat (35), aggregates which Darwin host syscalls
 *     are executed by Carrick per call.
 *
 * (b) Provider ABI facts (qualified live on macOS 27 / arm64, 2026-09-17):
 *     `carrick*:::syscall-entry`: arg0 = canonical Linux syscall nr.
 *     `syscall:::entry`: Darwin kernel syscall provider.
 *     `proc:::exit`: end only when the root CLI exits. A logical guest-exit
 *     can precede the workload (observed test_bufio startup 2026-09-17), so
 *     exiting on the first guest-exit would capture startup alone.
 *     Counts are diagnostic; no timing claim. Require root exit and zero errors/drops.
 *     Negative control: the CLI currently returns zero even when DTrace exit(2)
 *     rejects a guest exit 7. Consumers MUST require complete=1, errors=0,
 *     calls>0, seen_exit=1, code=0 and successful workload output; CLI status
 *     alone is not acceptance. Nonzero guest exit sets complete=0 below.
 *
 * (c) Perturbation: YES. Every selected guest call and its host calls fire
 *     probes. Overhead is not quantified; never cite traced wall time.
 */

dtrace:::BEGIN
{
	secs = 0; errors = 0; complete = 0; calls = 0; seen_exit = 0; code = -1;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 34 || arg0 == 35 || arg0 == 56 || arg0 == 57 || arg0 == 61 || arg0 == 63 || arg0 == 64 || arg0 == 79 || arg0 == 80 || arg0 == 215 || arg0 == 222)/
{
	calls++;
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

syscall::exit:entry
/pid == $target/
{ seen_exit = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{
 complete = errors == 0 && calls > 0 && seen_exit && code == 0;
 exit(complete ? 0 : 2);
}

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
{
	secs++;
}

tick-1s
/secs >= 30/
{
	exit(4);
}

dtrace:::END
{
	printf("BUFIO|summary|complete=%d|errors=%d|seconds=%d|calls=%d|seen_exit=%d|code=%d\n", complete, errors, secs, calls, seen_exit, code);
	printf("\n=== guest syscall calls ===\n");
	printa("guest nr %-6d: %@12u\n", @guest_calls);
	printf("\n=== host syscalls while servicing guest syscalls ===\n");
	printa("guest nr %-6d host %-24s: %@12u\n", @host_calls);
}
