#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=128m
#pragma D option ustackframes=32

/*
 * Focused read(2) caller census for a native Carrick process tree.
 *
 * This drill intentionally stores no per-thread dynamic variables. It is safe
 * to reach for after native-syscall-cpu-directional.d identifies read(2) as an
 * A/B kernel-CPU delta: entry-time host stacks are authoritative because
 * Carrick has restored its host stack before issuing the Darwin syscall.
 */

dtrace:::BEGIN
{
	seconds = 0;
}

syscall::read:entry
/pid == $target || progenyof($target)/
{
	@total = count();
	@requested_bytes = sum(arg2);
	@requested_size[arg2] = count();
	@caller_count[ustack(32)] = count();
	@caller_requested_bytes[ustack(32)] = sum(arg2);
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
/seconds >= 45/
{
	exit(0);
}

dtrace:::END
{
	printf("READCALL1|section=totals\n");
	printa("READCALL1|calls=%@d\n", @total);
	printa("READCALL1|requested_bytes=%@d\n", @requested_bytes);

	printf("READCALL1|section=requested-sizes\n");
	printa("READCALL1|requested_size=%d|calls=%@d\n", @requested_size);

	trunc(@caller_count, 20);
	printf("READCALL1|section=caller-count\n");
	printa("READCALLSTACK1|begin|metric=calls|value=%@d\n%kREADCALLSTACK1|end\n",
	    @caller_count);

	trunc(@caller_requested_bytes, 20);
	printf("READCALL1|section=caller-requested-bytes\n");
	printa("READCALLSTACK1|begin|metric=requested-bytes|value=%@d\n%kREADCALLSTACK1|end\n",
	    @caller_requested_bytes);
}
