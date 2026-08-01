#!/usr/sbin/dtrace -s
/*
 * Workstream C: what does the address-space fault term COST, and is that cost
 * contention?
 *
 * The reference go-build takes ~2.25 M `as_fault`s and spends ~28% of guest CPU
 * in the kernel, while named syscalls are only ~9% -- so the kernel time is
 * fault/scheduling, not syscall. A same-binary sweep showed per-fault sys cost
 * roughly DOUBLING (1.8 us -> 3.8 us) as guest threads scale 1 -> 10 while the
 * fault COUNT rose only 14%, which is the signature of serialization rather
 * than of more work.
 *
 * ABI qualified live on this host/build (macOS 27, t8132) before this script
 * was written, because two obvious probe points do not work here:
 *   - `fbt::vm_fault:entry` is LISTED but never fires: on arm64 these faults
 *     are serviced on the fast path and never reach `vm_fault()`. The observed
 *     stack at `as_fault` is
 *     `fleh_synchronous -> sleh_synchronous -> handle_user_abort`.
 *   - `handle_user_abort`, `arm_fast_fault` and `vm_fault_internal` are not
 *     FBT-instrumentable (trap-context functions are blacklisted), so there is
 *     no entry/return pair to time.
 * Hence cost is measured by SAMPLING kernel frames rather than by bracketing,
 * which also localizes the cost to a named kernel function instead of only
 * bounding it.
 *
 * Kernel providers only (`profile`, `vminfo`, `sched`), `execname`-scoped, and
 * launched with plain `-s` -- never `-c`/`-p` against a live native guest, per
 * AGENTS.md.
 *
 * Directional evidence, not a promotion artifact.
 */
#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=32m
#pragma D option bufsize=32m

dtrace:::BEGIN
{
	timed_out = 0;
	printf("NFCOST1|config|kernel_hz=997|scope=execname-carrick\n");
}

tick-120s
{
	timed_out = 1;
	exit(0);
}

/*
 * On-CPU kernel samples. arg0 is the kernel PC and is non-zero only when the
 * sample landed in the kernel; arg1 is the user PC otherwise. Keying on
 * func(arg0) names the kernel function directly, so a serialization primitive
 * shows up by name instead of having to be inferred from a stack shape.
 */
profile-997
/execname == "carrick" && arg0 != 0/
{
	@kern_total = count();
	@kern_by_function[func(arg0)] = count();
}

profile-997
/execname == "carrick" && arg0 == 0/
{
	@user_total = count();
}

/* The fault-path frames themselves, so cost can be divided by fault count. */
profile-997
/execname == "carrick" && arg0 != 0/
{
	@kern_stacks[stack(8)] = count();
}

vminfo:::as_fault  /execname == "carrick"/ { @as_fault = count(); }
vminfo:::zfod      /execname == "carrick"/ { @zfod = count(); }
vminfo:::cow_fault /execname == "carrick"/ { @cow_fault = count(); }

/*
 * Faulting user PC. Three PCs accounted for ~1.1 M of 2.25 M faults in the
 * qualification run, so the term is concentrated, not diffuse. Raw values are
 * preserved; symbolization happens outside because the guest exits before END.
 */
vminfo:::as_fault
/execname == "carrick"/
{
	@fault_pc[uregs[R_PC]] = count();
}

/*
 * Descheduling rate is the other serialization tell. macOS `sched` has no
 * `preempt` probe (qualified: the provider exposes only on-cpu/off-cpu/sleep/
 * wakeup/iwakeup), so off-cpu and sleep are counted separately -- a thread that
 * goes off-cpu WITHOUT sleeping was preempted or blocked on a spin/adaptive
 * lock, which is the shape contention would produce.
 */
sched:::off-cpu /execname == "carrick"/ { @offcpu = count(); }
sched:::sleep   /execname == "carrick"/ { @sleep = count(); }

dtrace:::END
{
	printa("NFCOST1|total|kind=kernel_samples|count=%@u\n", @kern_total);
	printa("NFCOST1|total|kind=user_samples|count=%@u\n", @user_total);
	printa("NFCOST1|total|kind=as_fault|count=%@u\n", @as_fault);
	printa("NFCOST1|total|kind=zfod|count=%@u\n", @zfod);
	printa("NFCOST1|total|kind=cow_fault|count=%@u\n", @cow_fault);
	printa("NFCOST1|total|kind=offcpu|count=%@u\n", @offcpu);
	printa("NFCOST1|total|kind=sleep|count=%@u\n", @sleep);

	trunc(@kern_by_function, 25);
	printa("NFCOST1|kernfn|function=%a|count=%@u\n", @kern_by_function);

	trunc(@fault_pc, 12);
	printa("NFCOST1|faultpc|pc=%#x|count=%@u\n", @fault_pc);

	trunc(@kern_stacks, 6);
	printa("NFCOST1|kernstack|count=%@u\n%k", @kern_stacks);

	printf("NFCOST1|complete|timed_out=%d\n", timed_out);
}
