#pragma D option quiet
#pragma D option dynvarsize=32m
#pragma D option aggsize=32m
#pragma D option bufsize=16m

/*
 * WHAT SHAPE OF GUEST mmap() BURNS THE DISPATCH TIME?
 *
 * (a) What it measures: guest `mmap` (canonical nr 222) wall/on-CPU time and
 *     call counts, aggregated by (prot, flags, length-bucket) across the
 *     whole guest tree. Companion to exec-window-syscall-latency.d, which
 *     found mmap to be ~85% of guest-syscall dispatch time on the
 *     `compile -V` exec window (2026-08-03) without saying WHICH mmaps.
 *     Length is bucketed by power of two (lquantize of log2 would lose the
 *     sum; we key on floor-log2 instead so each row carries its total ns).
 *
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-08-03):
 *     `carrick*:::syscall-entry` arg0 = CANONICAL Linux nr (mmap = 222 on
 *     aarch64), arg2 = HOST address of the 6-u64 argument array — addr,
 *     length, prot, flags, fd, offset in Linux order — safe to `copyin`
 *     from the probe (it is carrick's own SyscallArgs struct, not a guest
 *     VA). `copyin` must happen in the clause body, never the predicate.
 *
 * (c) Perturbation: YES — same structural caveat as
 *     exec-window-syscall-latency.d (DOF re-registration per self-reexec
 *     inflates exec chains several-fold while a consumer is attached).
 *     Only within-trace rankings and ratios are citable.
 *
 * Usage:
 *   target/release/carrick trace --script scripts/dtrace/guest-mmap-shape.d \
 *     --trace-out /tmp/mmap-shape.out -- run --exec-backend hvpatch ...
 */

dtrace:::BEGIN
{
	secs = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 222/
{
	this->a = (uint64_t *)copyin(arg2, 48);
	self->len = this->a[1];
	self->prot = this->a[2];
	self->flags = this->a[3];
	self->fd = (int)this->a[4];
	self->wall = timestamp;
	self->cpu = vtimestamp;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 222 && self->wall/
{
	/* floor(log2(len)) without loops: highest set bit bucket. */
	this->lb = self->len >= 268435456 ? 28 :
	    self->len >= 16777216 ? 24 :
	    self->len >= 4194304 ? 22 :
	    self->len >= 1048576 ? 20 :
	    self->len >= 262144 ? 18 :
	    self->len >= 65536 ? 16 :
	    self->len >= 16384 ? 14 : 12;
	@wall[self->prot, self->flags, self->fd >= 0 ? 1 : 0, this->lb] =
	    sum(timestamp - self->wall);
	@cpu[self->prot, self->flags, self->fd >= 0 ? 1 : 0, this->lb] =
	    sum(vtimestamp - self->cpu);
	@calls[self->prot, self->flags, self->fd >= 0 ? 1 : 0, this->lb] = count();
	@bytes[self->prot, self->flags, self->fd >= 0 ? 1 : 0, this->lb] =
	    sum(self->len);
	self->wall = 0;
	self->cpu = 0;
	self->len = 0;
	self->prot = 0;
	self->flags = 0;
	self->fd = 0;
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
	printf("\nrows: prot flags has_fd log2len -> value\n");
	printf("--- calls ---\n");
	printa("prot=%x flags=%x fd=%d 2^%d %@12u\n", @calls);
	printf("--- wall ns ---\n");
	printa("prot=%x flags=%x fd=%d 2^%d %@12u\n", @wall);
	printf("--- cpu ns ---\n");
	printa("prot=%x flags=%x fd=%d 2^%d %@12u\n", @cpu);
	printf("--- bytes ---\n");
	printa("prot=%x flags=%x fd=%d 2^%d %@12u\n", @bytes);
}
