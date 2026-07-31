#!/usr/sbin/dtrace -s
/*
 * Workstream C: attribute the address-space fault term.
 *
 * The go-build reference workload takes ~2.2 M address-space faults, of which
 * ~1.79 M are zero-fill (FIRST touch of anonymous memory), and kernel
 * non-syscall time -- overwhelmingly fault handling -- is the single largest
 * CPU bucket at 30.7%. Emitted JIT code was already measured at only 2.08% of
 * the zfod faults, so the mass is guest address-space setup, paid again per
 * forked guest process.
 *
 * The current Darwin provider ABI was live-qualified on this host/build:
 * `as_fault` and `zfod` arg2 are the exact 16 KiB host-page base.  Preserve
 * that value rather than masking it.  Exact all-page aggregation perturbed the
 * canonical workload and made libdtrace spin in `dtrace_aggregate_snap`, so
 * exact totals are paired with a deterministic 1/64 process+page sample.  The
 * sample is sufficient to rank repeated faults against distinct first touches
 * without pretending to be a lossless census.  COW arg2 is not
 * address-qualified and remains count-only.
 *
 * This stream is directional evidence, never a promotion artifact.  The
 * companion `native_fault_directional.py` reports coverage and completion and
 * permanently marks its output `gating_eligible=false`.
 */
#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=16m

dtrace:::BEGIN
{
	target_exit = 0;
	timed_out = 0;
}

tick-90s
{
	timed_out = 1;
	exit(0);
}

vminfo:::as_fault
/pid == $target || progenyof($target)/
{
	@tas = count();
}

vminfo:::as_fault
/(pid == $target || progenyof($target)) &&
    arg2 != 0 && arg2 < 0x0001000000000000 &&
    (arg2 & 0x3fff) == 0 &&
    (((arg2 >> 14) ^ (pid * 0x9e3779b9)) & 0x3f) == 0/
{
	@as[pid, arg2] = count();
}

vminfo:::as_fault
/(pid == $target || progenyof($target)) &&
    (arg2 == 0 || arg2 >= 0x0001000000000000 || (arg2 & 0x3fff) != 0)/
{
	@invalid_as = count();
}

vminfo:::zfod
/pid == $target || progenyof($target)/
{
	@tzf = count();
}

vminfo:::zfod
/(pid == $target || progenyof($target)) &&
    arg2 != 0 && arg2 < 0x0001000000000000 &&
    (arg2 & 0x3fff) == 0 &&
    (((arg2 >> 14) ^ (pid * 0x9e3779b9)) & 0x3f) == 0/
{
	@zf[pid, arg2] = count();
}

vminfo:::zfod
/(pid == $target || progenyof($target)) &&
    (arg2 == 0 || arg2 >= 0x0001000000000000 || (arg2 & 0x3fff) != 0)/
{
	@invalid_zf = count();
}

vminfo:::cow_fault
/pid == $target || progenyof($target)/
{
	@tcow = count();
}

proc:::exit
/pid == $target/
{
	target_exit = 1;
	exit(0);
}

dtrace:::END
{
	printf("NFAULT1|config|page_sample_modulus=64\n");
	printa("NFAULT1|page|outcome=as_fault|pid=%d|page=%#x|count=%@u\n", @as);
	printa("NFAULT1|page|outcome=zfod|pid=%d|page=%#x|count=%@u\n", @zf);
	printa("NFAULT1|rejected|outcome=as_fault|count=%@u\n", @invalid_as);
	printa("NFAULT1|rejected|outcome=zfod|count=%@u\n", @invalid_zf);
	printa("NFAULT1|total|outcome=as_fault|count=%@u\n", @tas);
	printa("NFAULT1|total|outcome=zfod|count=%@u\n", @tzf);
	printa("NFAULT1|total|outcome=cow_fault|count=%@u\n", @tcow);
	printf("NFAULT1|complete|target_exit=%d|timed_out=%d\n",
	    target_exit, timed_out);
}
