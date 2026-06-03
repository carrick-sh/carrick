/*
 * Focused trace for high-concurrency Go signal/fault failures.
 *
 * Keeps hot-path output aggregated so DTrace does not drop records while the
 * Go runtime is sending SIGURG preemption signals.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=64m
#pragma D option aggsize=64m

dtrace:::BEGIN
{
	printf("go-signal trace started at %Y\n", walltimestamp);
}

carrick*:::signal-publish
/pid == $target || progenyof($target)/
{
	@publish[(int)arg0, (int)arg1, (int)arg2] = count();
}

carrick*:::signal-deliver
/pid == $target || progenyof($target)/
{
	@deliver[(int)arg0, (int)arg1] = count();
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
	@inject[(int)arg0, arg1, arg3] = count();
	@inject_sp[(int)arg0, arg2] = count();
}

carrick*:::signal-restore
/pid == $target || progenyof($target)/
{
	@restore[arg0, arg2] = count();
	@restore_sp[arg1] = count();
}

carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{
	printf("FAULT esr=%#x elr=%#x far=%#x lr=%#x sp=%#x tid=%d at %Y\n",
	    arg0, arg1, arg2, arg3, arg4, (int)arg5, walltimestamp);
	@fault[arg0, arg1, arg2, arg3, arg4, (int)arg5] = count();
	exit(0);
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= 8/
{
	exit(0);
}

dtrace:::END
{
	printf("\n==== signal publish ====\n");
	printa("target=%-6d signum=%-3d kind=%-2d %@d\n", @publish);
	printf("\n==== signal deliver ====\n");
	printa("tid=%-6d signum=%-3d %@d\n", @deliver);
	printf("\n==== signal inject pc/handler ====\n");
	trunc(@inject, 80);
	printa("signum=%-3d saved_pc=%#-14x handler=%#-14x %@d\n", @inject);
	printf("\n==== signal inject sp ====\n");
	trunc(@inject_sp, 40);
	printa("signum=%-3d frame_sp=%#-14x %@d\n", @inject_sp);
	printf("\n==== signal restore pc ====\n");
	trunc(@restore, 80);
	printa("saved_pc=%#-14x magic=%#-14x %@d\n", @restore);
	printf("\n==== signal restore sp ====\n");
	trunc(@restore_sp, 40);
	printa("frame_sp=%#-14x %@d\n", @restore_sp);
	printf("\n==== faults ====\n");
	printa("esr=%#-10x elr=%#-14x far=%#-10x lr=%#-14x sp=%#-14x tid=%-6d %@d\n", @fault);
}
