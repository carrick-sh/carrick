#pragma D option quiet
#pragma D option dynvarsize=256m
#pragma D option bufsize=16m
#pragma D option aggsize=16m

/*
 * Low-overhead, whole-tree Darwin kernel CPU census by active host syscall.
 *
 * This intentionally does not aggregate kernel stacks. The stack-heavy
 * native-syscall-cpu.d is useful for a short qualified investigation, but the
 * canonical Go workload can create enough distinct stack keys to overflow
 * DTrace's dynamic-variable store and silently bias an A/B census. This script
 * keeps only bounded syscall/reason keys and emits machine-readable,
 * directional (never gating) records for paired workload comparison. Host
 * syscall CPU uses vtimestamp, which advances only while the current thread is
 * on-CPU; sleep duration therefore does not masquerade as kernel work.
 *
 * Futex reason:
 *   0 = no active guest futex wait
 *   1 = Carrick process-private FutexTable / parking_lot
 *   2 = native shared-futex implementation
 */

dtrace:::BEGIN
{
	seconds = 0;
	target_exit = 0;
	timed_out = 0;
}

carrick*:::native-syscall-service-entry
/pid == $target || progenyof($target)/
{
	self->futex_wait_kind = 0;
}

carrick*:::futex-route
/(pid == $target || progenyof($target)) && arg2 == 0/
{
	self->futex_wait_kind = arg3 == 0 ? 1 : 2;
}

carrick*:::native-syscall-service-end
/pid == $target || progenyof($target)/
{
	self->futex_wait_kind = 0;
}

syscall:::entry
/pid == $target || progenyof($target)/
{
	self->syscall_vtimestamp = vtimestamp;
}

syscall:::return
/(pid == $target || progenyof($target)) && self->syscall_vtimestamp != 0/
{
	@syscall_cpu[probefunc, self->futex_wait_kind] =
	    sum(vtimestamp - self->syscall_vtimestamp);
	@syscall_calls[probefunc, self->futex_wait_kind] = count();
	self->syscall_vtimestamp = 0;
}

profile-997
/(pid == $target || progenyof($target)) && arg0 != 0/
{
	@kernel_total = count();
}

profile-997
/(pid == $target || progenyof($target)) && arg1 != 0/
{
	@user_total = count();
}

proc:::exit
/pid == $target/
{
	target_exit = 1;
	exit(0);
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 45/
{
	timed_out = 1;
	exit(0);
}

dtrace:::END
{
	printf("SYSCALLCPU2|config|sample_hz=997\n");
	printa("SYSCALLCPU2|total|mode=kernel|samples=%@d\n", @kernel_total);
	printa("SYSCALLCPU2|total|mode=user|samples=%@d\n", @user_total);
	printa("SYSCALLCPU2|syscall-cpu|host=%s|reason=%d|cpu_ns=%@d\n",
	    @syscall_cpu);
	printa("SYSCALLCPU2|syscall-calls|host=%s|reason=%d|calls=%@d\n",
	    @syscall_calls);
	printf("SYSCALLCPU2|complete|target_exit=%d|timed_out=%d\n",
	    target_exit, timed_out);
}
