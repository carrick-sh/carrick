#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=32m
#pragma D option aggsize=32m
#pragma D option ustackframes=24
#pragma D option strsize=64k

/*
 * Whole-process-tree attribution for the Darwin/AArch64 native lane.
 *
 * This program deliberately keeps three quantities separate:
 * - one wall-state sample stream (`tick-197hz`);
 * - on-CPU thread samples (`profile-499`);
 * - off-CPU resource duration by the PC/stack that blocked.
 *
 * `$target` is the launch-owned outer carrick command. Children are admitted
 * only through proc:::create, so unrelated carrick runs never enter the set.
 * Absolute traced timing is diagnostic; proportions and exact counts select
 * the next untraced experiment.
 */

dtrace:::BEGIN
{
	started = timestamp;
	target_exit_reason = 0;
	track_pid[$target] = 1;
	thread_state[$target, 0] = 0;
	jit_seen[$target] = 0;
	catalog_seen[$target] = 0;
	live_pids = 1;
	on_cpu_threads = 0;
	runnable_threads = 0;
	sleeping_threads = 0;
	wall_samples = 0;
}

proc:::create
/track_pid[pid]/
{
	track_pid[args[0]->pr_pid] = 1;
	live_pids++;
	@process_events["create"] = count();
}

proc:::lwp-exit
/track_pid[pid] && thread_state[pid, tid] != 0/
{
	on_cpu_threads -= thread_state[pid, tid] == 1 ? 1 : 0;
	runnable_threads -= thread_state[pid, tid] == 2 ? 1 : 0;
	sleeping_threads -= thread_state[pid, tid] == 3 ? 1 : 0;
	thread_state[pid, tid] = 0;
	self->off_ts = 0;
}

proc:::exit
/track_pid[pid] && pid != $target/
{
	track_pid[pid] = 0;
	live_pids--;
	@process_events["exit"] = count();
}

proc:::exit
/pid == $target/
{
	track_pid[pid] = 0;
	live_pids--;
	target_exit_reason = arg0;
	exit(0);
}

sched:::on-cpu
/track_pid[pid]/
{
	on_cpu_threads -= thread_state[pid, tid] == 1 ? 1 : 0;
	runnable_threads -= thread_state[pid, tid] == 2 ? 1 : 0;
	sleeping_threads -= thread_state[pid, tid] == 3 ? 1 : 0;
	thread_state[pid, tid] = 1;
	on_cpu_threads++;
}

sched:::off-cpu
/track_pid[pid]/
{
	on_cpu_threads -= thread_state[pid, tid] == 1 ? 1 : 0;
	runnable_threads -= thread_state[pid, tid] == 2 ? 1 : 0;
	sleeping_threads -= thread_state[pid, tid] == 3 ? 1 : 0;
	self->off_ts = timestamp;
	self->off_pc = uregs[R_PC];
	self->off_sleeping = curlwpsinfo->pr_state == SSLEEP;
	thread_state[pid, tid] = self->off_sleeping ? 3 : 2;
	runnable_threads += self->off_sleeping ? 0 : 1;
	sleeping_threads += self->off_sleeping ? 1 : 0;
}

sched:::on-cpu
/track_pid[pid] && self->off_ts != 0/
{
	this->delta = timestamp - self->off_ts;
	@off_count[self->off_sleeping ? "voluntary" : "runnable",
	    pid, self->off_pc] = count();
	@off_ns[self->off_sleeping ? "voluntary" : "runnable",
	    pid, self->off_pc] = sum(this->delta);
	@off_total[self->off_sleeping ? "voluntary" : "runnable"] =
	    sum(this->delta);
	self->off_ts = 0;
	self->off_pc = 0;
	self->off_sleeping = 0;
}

/*
 * Stack collection is a separate clause so the expensive ustack() action is
 * paid only for voluntary blocks, not scheduler preemption.
 */
sched:::off-cpu
/track_pid[pid] && curlwpsinfo->pr_state == SSLEEP/
{
	self->stack_off_ts = timestamp;
}

sched:::on-cpu
/track_pid[pid] && self->stack_off_ts != 0/
{
	@voluntary_stack[pid, ustack(24)] =
	    sum(timestamp - self->stack_off_ts);
	self->stack_off_ts = 0;
}

tick-197hz
{
	wall_samples++;
	@wall_state[on_cpu_threads > 0 ? "on-cpu" :
	    runnable_threads > 0 ? "runnable-descheduled" :
	    sleeping_threads > 0 ? "all-sleeping" : "transition"] = count();
}

profile-499
/track_pid[pid] && arg1 != 0/
{
	@cpu_user[pid, arg1] = count();
}

profile-499
/track_pid[pid] && arg0 != 0/
{
	@cpu_kernel[arg0] = count();
}

carrick*:::host-image-base
/track_pid[pid]/
{
	@image_base["host", arg0, arg1] = count();
}

carrick*:::host-image-catalog
/track_pid[pid] && catalog_seen[pid] == 0/
{
	catalog_seen[pid] = 1;
	printf("NWIMAGES1|%s\n", copyinstr(arg0));
}

carrick*:::guest-image-base
/track_pid[pid]/
{
	@image_base["guest", arg0, arg1] = count();
}

carrick*:::host-jit-range
/track_pid[pid] && jit_seen[arg0] == 0/
{
	jit_seen[arg0] = 1;
	@image_base["jit-start", arg0, arg1] = count();
	@image_base["jit-end", arg0, arg2] = count();
}

dtrace:::END
{
	printa("DSRPROF1|count|phase=wall-state|kind=%s|value=%@d\n",
	    @wall_state);
	printf("DSRPROF1|count|phase=wall-samples|value=%d\n",
	    wall_samples);
	printa("DSRPROF1|count|phase=cpu-user-pc|pid=%d|source_pc=0x%x|value=%@d\n",
	    @cpu_user);
	printa("DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0x%x|value=%@d\n",
	    @cpu_kernel);
	printa("DSRPROF1|count|phase=offcpu-%s-pc|pid=%d|source_pc=0x%x|value=%@d\n",
	    @off_count);
	printa("DSRPROF1|total|phase=offcpu-%s-pc|pid=%d|source_pc=0x%x|value_ns=%@d\n",
	    @off_ns);
	printa("DSRPROF1|total|phase=offcpu-%s-total|value_ns=%@d\n",
	    @off_total);
	printa("DSRPROF1|count|phase=process-lifecycle|kind=%s|value=%@d\n",
	    @process_events);
	printa("DSRPROF1|count|phase=image-base|kind=%s|pid=%d|source_pc=0x%x|value=%@d\n",
	    @image_base);
	printf("DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=%d\n",
	    live_pids);
	printf("DSRPROF1|total|phase=elapsed|value_ns=%d\n",
	    timestamp - started);

	trunc(@voluntary_stack, 32);
	printa("NWSTACK1|begin|state=voluntary|pid=%d|value_ns=%@d\n%kNWSTACK1|end\n",
	    @voluntary_stack);

	printf("DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=%d\n",
	    target_exit_reason);
}
