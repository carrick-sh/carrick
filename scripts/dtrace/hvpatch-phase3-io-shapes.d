/*
 * hvpatch-phase3-io-shapes.d — classify read/write/mmap syscall arguments and
 * outcomes on the cold-build gate before considering guest-side I/O shortcuts.
 *
 * Provider ABI qualified on Darwin/arm64 on 2026-08-08:
 * `carrick*:::syscall-entry` arg0 is canonical nr and arg2 points to six u64
 * arguments; `syscall-return` arg0 is canonical nr, arg2 is the signed return,
 * and arg3 is Linux errno (zero on success). The predicate follows the current
 * Carrick fork/exec tree.
 *
 * Perturbation: one six-word copyin on selected entries plus aggregation on
 * selected returns. Counts and shapes are citable; timing is not. Natural
 * launch-child exit ends the trace, with a 90 s failure bound.
 */

#pragma D option quiet
#pragma D option bufsize=16m

dtrace:::BEGIN
{
	printf("HVPATCH3IO|begin\n");
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 63 || arg0 == 64)/
{
	this->a = (uint64_t *)copyin(arg2, 6 * sizeof(uint64_t));
	@total[arg0] = count();
	@rw_fd[arg0, this->a[0]] = count();
	@rw_size_bucket[arg0,
	    this->a[2] <= 64 ? 0 :
	    this->a[2] <= 4096 ? 1 :
	    this->a[2] <= 65536 ? 2 : 3] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 222/
{
	this->a = (uint64_t *)copyin(arg2, 6 * sizeof(uint64_t));
	@total[arg0] = count();
	@mmap_kind[(this->a[3] & 0x20) != 0, (int64_t)this->a[4]] = count();
	@mmap_size_bucket[this->a[1] <= 4096 ? 0 :
	    this->a[1] <= 65536 ? 1 :
	    this->a[1] <= 1048576 ? 2 : 3] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 63 || arg0 == 64 || arg0 == 222)/
{
	@outcome[arg0, (int)arg3, (int64_t)arg2 == 0 ? 0 :
	    (int64_t)arg2 > 0 ? 1 : 2] = count();
}

proc:::exit
/pid == $target/
{
	exit(0);
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 90/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCH3IO|end|bounded=%d\n", bounded);
	printa("HVPATCH3IO|total|nr=%d|count=%@d\n", @total);
	printa("HVPATCH3IO|rw_fd|nr=%d|fd=%d|count=%@d\n", @rw_fd);
	printa("HVPATCH3IO|rw_size|nr=%d|bucket=%d|count=%@d\n", @rw_size_bucket);
	printa("HVPATCH3IO|mmap_kind|anonymous=%d|fd=%d|count=%@d\n", @mmap_kind);
	printa("HVPATCH3IO|mmap_size|bucket=%d|count=%@d\n", @mmap_size_bucket);
	printa("HVPATCH3IO|outcome|nr=%d|errno=%d|class=%d|count=%@d\n", @outcome);
}
