#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-psynch-callers.d -- attribute the pthread condition-variable
 * traffic induced by the fork14 fork()+_exit()+waitpid() loop.
 *
 * The broad syscall provider is intentional.  On Darwin/arm64 (macOS 27.0,
 * 2026-09-18), syscall:::entry reports these provider functions as
 * `psynch_cvwait`, `psynch_cvsignal`, and `psynch_cvbroad`; naming those probes
 * directly produced an empty capture through carrick trace on this host.
 * carrick*:::host-image-base publishes the traced Mach-O identity before the
 * guest loads, so the sampled stacks can be symbolized against the exact
 * binary after the run.
 *
 * Perturbation: LOW.  Every matching call increments a scalar and aggregation,
 * but ustack() is sampled only once per 1,024 calls of each kind.  Counts and
 * caller ranks are citable; wall time under this script is not.  A capture
 * with zero total calls or zero sampled stacks is an instrument failure.
 */

#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option dynvarsize=16m
#pragma D option ustackframes=32
#pragma D option strsize=16k

dtrace:::BEGIN
{
	started = timestamp;
	total = 0;
	samples = 0;
	bounded = 0;
	errors = 0;
}

carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
	printf("HVPATCHFORKPSYNCH|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
	    (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

syscall:::entry
/(pid == $target || progenyof($target)) &&
 (probefunc == "psynch_cvwait" || probefunc == "psynch_cvsignal" ||
  probefunc == "psynch_cvbroad")/
{
	total++;
	@by_name[probefunc] = count();
}

syscall:::entry
/(pid == $target || progenyof($target)) && probefunc == "psynch_cvwait" &&
 (waits++ & 1023) == 0/
{
	samples++;
	@callers[probefunc, ustack()] = count();
}

syscall:::entry
/(pid == $target || progenyof($target)) && probefunc == "psynch_cvsignal" &&
 (signals++ & 1023) == 0/
{
	samples++;
	@callers[probefunc, ustack()] = count();
}

syscall:::entry
/(pid == $target || progenyof($target)) && probefunc == "psynch_cvbroad" &&
 (broadcasts++ & 1023) == 0/
{
	samples++;
	@callers[probefunc, ustack()] = count();
}

dtrace:::ERROR
{
	errors++;
}

proc:::exit
/pid == $target/
{
	exit(0);
}

profile:::tick-1sec
/timestamp - started > 300 * 1000000000/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCHFORKPSYNCH|summary|calls=%d|samples=%d|bounded=%d|errors=%d\n",
	    total, samples, bounded, errors);
	printa("HVPATCHFORKPSYNCH|name|%s|%@u\n", @by_name);
	printf("HVPATCHFORKPSYNCH|callers\n");
	trunc(@callers, 32);
	printa("HVPATCHFORKPSYNCH|caller|%s|%@u|%k\n", @callers);
}
