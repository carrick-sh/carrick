/*
 * hvpatch-syscall-host-tax.d — how many HOST syscalls does carrick issue per
 * GUEST syscall, and which of them are paid unconditionally?
 *
 * (a) WHAT IT MEASURES. Unlike `hvpatch-fs-op-ledger.d`, which filters to the
 *     fs set, this one keys EVERY guest syscall kind, because the costs it is
 *     built for are FLAT taxes — paid on kinds that have no business touching
 *     the host at all (`getpid`, `sched_yield`, `futex` fast paths). Keyed by
 *     guest syscall name:
 *       @calls     guest calls of that kind
 *       @host_sum  total host syscalls issued inside those windows
 *       @host_fn   host syscalls by name inside those windows
 *       @host_ns   host-kernel ns by name inside those windows
 *       @wall_sum  total service-window ns
 *     `host_sum / calls` is the amplification. A kind that carrick services
 *     entirely from its own kernel graph should read 0.00; anything it reads
 *     ABOVE zero across every kind alike is a tax on the whole workload.
 *
 *     @tax_fn/@tax_ns are the same two numbers restricted to the host calls a
 *     tax is made of, so a before/after pair is a single grep. The two the
 *     script was written for:
 *       thread_selfusage — the `CLOCK_THREAD_CPUTIME_ID` read that Darwin
 *                          lowers `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` to.
 *       fstat/fstat64    — the record-lock file-identity read on `close`.
 *     Neither name is special-cased in the aggregation; they are listed in
 *     @tax_fn only so the report shows a zero row rather than an absent one.
 *
 * (b) PROVIDER ABI FACTS (qualified live on macOS 27 / Apple Silicon,
 *     2026-09-08, against a signed release `carrick` from this worktree).
 *     - `carrick*:::syscall-entry` arg1 is the guest syscall NAME as a user
 *       string (`copyinstr`); `syscall-return` fires on the SAME host pthread,
 *       so `self->` thread-locals pair them. Confirmed by the existing
 *       `hvpatch-fs-op-ledger.d`, which this script's window logic follows.
 *     - Scope is `pid == $target || progenyof($target)`: HVPatch multiplexes
 *       every guest process inside one carrier, so progeny only covers the
 *       launcher/carrier split, not guest `fork`.
 *     - macOS spells several syscalls differently from Linux (`fstat64`,
 *       `close_nocancel`, `open_nocancel`); match on the reported `probefunc`
 *       and never assume the Linux name. `thread_selfusage` IS its own
 *       `syscall::` probe on this build — `dtrace -ln 'syscall::thread_selfusage:'`
 *       lists entry+return, and it fires (it is not an alias, unlike the FBT
 *       `vm_fault` trap documented in AGENTS.md).
 *     - Host calls with NO guest window in flight land in @outside_fn. Under
 *       HVPatch that is the reactor, the executor pool and the CLI, and it is
 *       reported rather than dropped so a tax that merely MOVED out of the
 *       window is still visible.
 *
 * (c) PERTURBATION: YES, heavily. Two probes per host syscall and two per
 *     guest syscall on a path whose whole point is that it is cheap: absolute
 *     nanoseconds here are NOT performance numbers, and the wall column exists
 *     only to rank kinds. The COUNTS (@host_sum / @calls, @tax_fn) are exact
 *     and are what a before/after comparison should cite. Measure the wall
 *     cost of a tax with an untraced A/B run of the reducer instead.
 *
 * (d) BOUNDED: exits at $1 seconds (default 120) printing
 *     `section=truncated`, so a session can never outlive its question. A
 *     leaked root dtrace consumer cannot be reaped without a password.
 *
 * Usage:
 *   sudo dtrace -q -s scripts/dtrace/hvpatch-syscall-host-tax.d 90 \
 *        -c "<carrick run ... /reducer getpid 200000>"
 *   carrick trace -s scripts/dtrace/hvpatch-syscall-host-tax.d -- run ...
 * Companion guest reducer: scripts/dtrace/syscall-tax-reducer.rs
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
	/* Seed the tax rows so a FIXED binary reports an explicit zero rather
	 * than an absent line a reader could mistake for "the probe missed". */
	@tax_fn["thread_selfusage"] = sum(0);
	@tax_fn["fstat"] = sum(0);
	@tax_fn["fstat64"] = sum(0);
}

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
	self->guest = copyinstr(arg1);
	self->t0 = timestamp;
	self->n = 0;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->t0/
{
	@calls[self->guest] = count();
	@wall_sum[self->guest] = sum(timestamp - self->t0);
	@host_sum[self->guest] = sum(self->n);
	@host_n[self->guest] = quantize(self->n);
	self->guest = "";
	self->t0 = 0;
	self->n = 0;
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->t0/
{
	self->n++;
	self->h0 = timestamp;
	self->hfn = probefunc;
	@host_fn[self->guest, probefunc] = count();
	@tax_fn[probefunc] = sum(1);
}

syscall:::return
/(pid == $target || progenyof($target)) && self->h0/
{
	this->k = timestamp - self->h0;
	@host_ns[self->guest, self->hfn] = sum(this->k);
	@tax_ns[self->hfn] = sum(this->k);
	self->h0 = 0;
}

syscall:::entry
/(pid == $target || progenyof($target)) && !self->t0/
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
	printf("section=guest-calls\n");
	printa("guest=%s calls=%@d\n", @calls);
	printf("section=host-syscalls-in-window\n");
	printa("guest=%s host_total=%@d\n", @host_sum);
	printf("section=window-wall-ns\n");
	printa("guest=%s wall_ns=%@d\n", @wall_sum);
	printf("section=host-fn-count\n");
	printa("guest=%s host=%s count=%@d\n", @host_fn);
	printf("section=host-fn-ns\n");
	printa("guest=%s host=%s ns=%@d\n", @host_ns);
	printf("section=tax-count\n");
	printa("host=%s in_window=%@d\n", @tax_fn);
	printf("section=tax-kernel-ns\n");
	printa("host=%s ns=%@d\n", @tax_ns);
	printf("section=host-per-guest-call\n");
	printa("guest=%s %@d\n", @host_n);
	printf("section=outside-window\n");
	printa("host=%s count=%@d\n", @outside_fn);
}
