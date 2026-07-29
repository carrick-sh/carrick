#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=32m
#pragma D option aggsize=64m
#pragma D option stackframes=32

/*
 * Whole-tree Darwin kernel CPU attributed to the host syscall that drove it.
 *
 * Syscall elapsed duration includes useful sleep and therefore cannot answer
 * whether a wait mechanism consumes CPU. `profile-997` samples the thread
 * actually executing in the kernel; the syscall provider supplies its typed
 * Darwin operation without requiring a kernel slide or post-run symbolication.
 *
 * Futex reason:
 *   0 = no active guest futex wait
 *   1 = Carrick process-private FutexTable / parking_lot
 *   2 = native shared-futex implementation
 */

dtrace:::BEGIN
{
	seconds = 0;
	tracked[$target] = 1;
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
}

proc:::exit
/tracked[pid] && pid != $target/
{
	tracked[pid] = 0;
}

proc:::exit
/pid == $target/
{
	tracked[pid] = 0;
	exit(0);
}

carrick*:::native-syscall-service-entry
/tracked[pid]/
{
	service_active[pid, tid] = 1;
	futex_wait_kind[pid, tid] = 0;
}

carrick*:::futex-route
/tracked[pid] && service_active[pid, tid] && arg2 == 0/
{
	futex_wait_kind[pid, tid] = arg3 == 0 ? 1 : 2;
}

carrick*:::native-syscall-service-end
/tracked[pid] && service_active[pid, tid]/
{
	service_active[pid, tid] = 0;
	futex_wait_kind[pid, tid] = 0;
}

syscall:::entry
/tracked[pid]/
{
	host_syscall[pid, tid] = probefunc;
	host_reason[pid, tid] = futex_wait_kind[pid, tid];
}

syscall:::return
/tracked[pid] && host_syscall[pid, tid] != 0/
{
	host_syscall[pid, tid] = 0;
	host_reason[pid, tid] = 0;
}

profile-997
/tracked[pid] && arg0 != 0/
{
	@kernel_total = count();
	@kernel_by_syscall[
	    host_syscall[pid, tid] != 0 ? host_syscall[pid, tid] : "non-syscall",
	    host_reason[pid, tid]] = count();
	@kernel_stack[
	    host_syscall[pid, tid] != 0 ? host_syscall[pid, tid] : "non-syscall",
	    host_reason[pid, tid],
	    stack(32)] = count();
}

profile-997
/tracked[pid] && arg1 != 0/
{
	@user_total = count();
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
	printf("SYSCALLCPU1|section=sample-totals\n");
	printa("SYSCALLCPU1|mode=kernel|samples=%@d\n", @kernel_total);
	printa("SYSCALLCPU1|mode=user|samples=%@d\n", @user_total);

	printf("SYSCALLCPU1|section=kernel-by-syscall|legend=reason-0-none,reason-1-private-futex,reason-2-shared-futex\n");
	printa("SYSCALLCPU1|host=%s|reason=%d|samples=%@d\n",
	    @kernel_by_syscall);

	trunc(@kernel_stack, 64);
	printf("SYSCALLCPU1|section=kernel-stacks\n");
	printa("SYSCALLSTACK1|begin|host=%s|reason=%d|samples=%@d\n%kSYSCALLSTACK1|end\n",
	    @kernel_stack);
}
