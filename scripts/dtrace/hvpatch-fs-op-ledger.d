/*
 * hvpatch-fs-op-ledger.d — what does ONE guest fs syscall cost on the HVPatch
 * lane, split into host-kernel time and carrick userspace time?
 *
 * (a) WHAT IT MEASURES. For every guest syscall whose name is in the fs set
 *     below (openat, close, unlinkat, newfstatat, mkdirat, renameat,
 *     fstat, faccessat, readlinkat), keyed by guest syscall name:
 *       @wall        quantize of the service window (syscall-entry -> -return)
 *       @wall_sum    total window ns
 *       @host_n      quantize of host syscalls issued inside ONE window
 *       @host_fn     host syscalls by name inside the window (COUNT)
 *       @host_ns     host-kernel ns by name inside the window (entry->return)
 *       @kern_sum    total host-kernel ns inside windows
 *     wall_sum - kern_sum is carrick's OWN userspace time (path resolution,
 *     cap-std walks, content copies, lock traffic) inside the window; the
 *     split says whether the fix is fewer/cheaper host calls or less Rust.
 *     Host calls with no window in flight are counted in @outside_fn so
 *     bookkeeping outside the service window (fd-table settlement, reactor
 *     nudges) is visible rather than silently excluded.
 *
 * (b) PROVIDER ABI FACTS (qualified on macOS 27 / Apple Silicon, 2026-09-01).
 *     - `carrick*:::syscall-entry` arg1 is the guest syscall NAME as a user
 *       string (copyinstr) and arg2 the ADDRESS of its `SyscallArgs`
 *       (`[u64; 6]`, 48 bytes, `copyin`); `syscall-return` fires on the same
 *       vCPU pthread, so `self->` thread-locals pair them. A creating
 *       `openat` (args[2] & O_CREAT) is keyed `openat(O_CREAT)`.
 *     - Scope is `pid == $target || progenyof($target)`; HVPatch multiplexes
 *       every guest process inside one carrier, so progeny only matters for
 *       the launcher/carrier split.
 *     - `syscall:::entry` on macOS names `fstatat64`, `getattrlist`,
 *       `open_nocancel`, `close_nocancel` -- match on the reported probefunc,
 *       do not assume the Linux spelling.
 *
 * (c) PERTURBATION: YES. Two probes per host syscall plus two per guest
 *     syscall roughly double the per-call cost; absolute microseconds are not
 *     performance numbers. Same-instrument SPLITS (kernel vs user, per-name
 *     shares) are citable. Bounded: exits at $1 seconds (default 120) with an
 *     explicit `section=truncated` marker.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-fs-op-ledger.d -- run ... (auto-sudo)
 *   sudo dtrace -q -s scripts/dtrace/hvpatch-fs-op-ledger.d 60 -c "<command>"
 */
#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=32m
#pragma D option aggsize=32m
#pragma D option strsize=128
#pragma D option defaultargs

dtrace:::BEGIN
{
	secs = 0;
	limit = $1 != 0 ? $1 : 120;
}

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
	this->name = copyinstr(arg1);
	self->fs = (this->name == "openat" || this->name == "close" ||
	    this->name == "unlinkat" || this->name == "newfstatat" ||
	    this->name == "mkdirat" || this->name == "renameat" ||
	    this->name == "fstat" || this->name == "faccessat" ||
	    this->name == "readlinkat") ? 1 : 0;
	/* arg2 is the ADDRESS of the guest's SyscallArgs ([u64; 6]); a creating
	 * openat (Linux O_CREAT = 0x40 in args[2]) is a different operation
	 * from an open of an existing entry and is ledgered under its own key. */
	this->args = (uint64_t *)copyin(arg2, 48);
	this->creat = (this->name == "openat" && (this->args[2] & 0x40) != 0) ? 1 : 0;
	self->guest = self->fs ? (this->creat ? "openat(O_CREAT)" : this->name) : "";
	self->t0 = self->fs ? timestamp : 0;
	self->n = 0;
	self->kern = 0;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->fs/
{
	this->w = timestamp - self->t0;
	@wall[self->guest] = quantize(this->w);
	@wall_sum[self->guest] = sum(this->w);
	@calls[self->guest] = count();
	@host_n[self->guest] = quantize(self->n);
	@kern_sum[self->guest] = sum(self->kern);
	self->fs = 0;
	self->guest = "";
	self->t0 = 0;
	self->n = 0;
	self->kern = 0;
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->fs/
{
	self->n++;
	self->h0 = timestamp;
	self->hfn = probefunc;
	@host_fn[self->guest, probefunc] = count();
}

syscall:::return
/(pid == $target || progenyof($target)) && self->fs && self->h0/
{
	this->k = timestamp - self->h0;
	self->kern += this->k;
	@host_ns[self->guest, self->hfn] = sum(this->k);
	self->h0 = 0;
}

syscall:::entry
/(pid == $target || progenyof($target)) && !self->fs/
{
	@outside_fn[probefunc] = count();
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= limit/
{
	printf("section=truncated after %d s\n", secs);
	exit(2);
}

dtrace:::END
{
	printf("section=calls\n");
	printa("guest=%s calls=%@d\n", @calls);
	printf("section=wall-vs-kernel-ns\n");
	printa("guest=%s wall_ns=%@d\n", @wall_sum);
	printa("guest=%s host_kernel_ns=%@d\n", @kern_sum);
	printf("section=host-fn-count\n");
	printa("guest=%s host=%s count=%@d\n", @host_fn);
	printf("section=host-fn-ns\n");
	printa("guest=%s host=%s ns=%@d\n", @host_ns);
	printf("section=host-per-guest-call\n");
	printa("guest=%s %@d\n", @host_n);
	printf("section=wall-dist\n");
	printa("guest=%s %@d\n", @wall);
	printf("section=outside-window\n");
	printa("host=%s count=%@d\n", @outside_fn);
}
