/*
 * Low-perturbation trace: fires ONLY on rare events (EL1-kick resumes and
 * out-of-text signal injections), so guest timing stays near full speed and the
 * SIGURG-vs-trampoline race still reproduces. The heavy per-futex stream
 * (trace-futex-signal.d) slows the guest ~50x and hides the race.
 */
#pragma D option quiet
#pragma D option bufsize=8m

carrick*:::kick-in-kernel
/pid == $target || progenyof($target)/
{
	@kik[arg0] = count();
	kik_total++;
}

tick-1s { secs++; }
tick-1s /secs >= 12/
{
	printf("=== kick_in_kernel total=%d ===\n", kik_total);
	printa("  el1_pc=0x%x %@d\n", @kik);
	exit(0);
}
