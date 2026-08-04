#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option bufsize=16m
#pragma D option dynvarsize=64m

/*
 * Capture one authenticated CPU-sample population for a native-DSR guest
 * process tree. User samples are split by the exact half-open JIT-cache bounds;
 * JIT PCs are aggregated for an offline join against retirement snapshots.
 * Kernel samples remain in the same 997 Hz population. Samples with both or
 * neither profile PC populated are counted as invalid and reject the capture.
 *
 * Provider ABI qualified live on macOS 26A5388g (2026-08-03):
 * `proc:::create`, `proc:::exit`, and `profile-997` all list and fire on this
 * host; `proc:::create` identifies the child as `args[0]->pr_pid`,
 * `proc:::exit` arg0 is the CLD_* exit reason, profile arg0 is the sampled
 * kernel PC, profile arg1 is the sampled user PC, and carrick's
 * `dsr-cache-bounds` arguments are the exact half-open JIT-cache range
 * [arg0, arg1). Cache bounds are inherited across fork until a child publishes
 * its own range.
 *
 * The 997 Hz sampling plus aggregation is perturbing. Use only same-instrument
 * attribution ratios from this trace; never cite its duration as wall evidence.
 * Instruction bytes are read only from authenticated retirement snapshots
 * after tracing. The probe path never reads sampled process memory.
 */

dtrace:::BEGIN
{
	/* CARRICK_NSHAPE2_HEADER */
	/* CARRICK_NSHAPE2_TERMINALS */
	tracked[$target] = 1;
	jit_start[$target] = (uint64_t)0;
	jit_end[$target] = (uint64_t)0;
	admitted = 1;
	exited = 0;
	live = 1;
	bounded = 0;
	target_completed = 0;
	target_exit_reason = 0;
	probe_errors = 0;
	user_cpu = 0;
	kernel_cpu = 0;
	invalid_cpu = 0;
	jit_user = 0;
	non_jit_user = 0;
}

proc:::create
/tracked[pid] && tracked[args[0]->pr_pid] == 0/
{
	tracked[args[0]->pr_pid] = 1;
	jit_start[args[0]->pr_pid] = jit_start[pid];
	jit_end[args[0]->pr_pid] = jit_end[pid];
	admitted++;
	live++;
	printf("NSHAPE2|fork|parent=%d|child=%d\n", pid, args[0]->pr_pid);
}

proc:::exit
/tracked[pid]/
{
	exited++;
	live--;
	tracked[pid] = 0;
	jit_start[pid] = (uint64_t)0;
	jit_end[pid] = (uint64_t)0;
	if (pid == $target) {
		target_completed = 1;
		target_exit_reason = arg0;
	}
	if (target_completed && live == 0) {
		exit(0);
	}
}

carrick*:::dsr-cache-bounds
/tracked[pid]/
{
	jit_start[pid] = arg0;
	jit_end[pid] = arg1;
}

profile-997
/tracked[pid]/
{
	if (arg1 != 0 && arg0 == 0) {
		user_cpu++;
		if (jit_end[pid] != 0 && arg1 >= jit_start[pid] &&
		    arg1 < jit_end[pid]) {
			jit_user++;
			@pc[pid, arg1] = count();
		} else {
			non_jit_user++;
		}
	} else if (arg0 != 0 && arg1 == 0) {
		kernel_cpu++;
	} else if ((arg0 == 0) == (arg1 == 0)) {
		invalid_cpu++;
	}
}

dtrace:::ERROR
{
	probe_errors++;
}

tick-180s
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("NSHAPE2|section=mode\n");
	printf("NSHAPE2|mode|kind=user|count=%d\n", user_cpu);
	printf("NSHAPE2|mode|kind=kernel|count=%d\n", kernel_cpu);
	printf("NSHAPE2|mode|kind=invalid|count=%d\n", invalid_cpu);
	printf("NSHAPE2|section=region\n");
	printf("NSHAPE2|region|kind=jit|count=%d\n", jit_user);
	printf("NSHAPE2|region|kind=non-jit|count=%d\n", non_jit_user);
	printf("NSHAPE2|section=pc\n");
	printa("NSHAPE2|pc|pid=%d|pc=0x%x|count=%@d\n", @pc);
	printf("NSHAPE2|complete|bounded=%d|target_completed=%d|target_exit_reason=%d|admitted=%d|exited=%d|live_at_end=%d|probe_errors=%d\n",
	    bounded, target_completed, target_exit_reason, admitted, exited, live,
	    probe_errors);
}
