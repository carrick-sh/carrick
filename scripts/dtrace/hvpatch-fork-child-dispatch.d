#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-child-dispatch.d — join a published fork child to its exact
 * scheduler claim, persistent-executor load, and process-exit lifecycle.
 *
 * WHAT: identifies whether an ordinary HVPatch fork child disappears before
 * executor claim, is claimed but never completes backend load, or loads but
 * never completes process retirement. The companion lifecycle identity probe
 * supplies the child's non-reused TaskSerial. The dedicated claim probe joins
 * that TaskSerial to the independently allocated ThreadSerial and execution
 * generation before backend load; the existing Load event closes that edge.
 *
 * Provider ABI qualified live on Darwin/arm64 (macOS 27.0, 2026-08-25)
 * against carrick-observability:
 *   hvpatch-guest-lifecycle-identity:
 *     arg0 Linux pid, arg1 TaskSerial, arg2 parent TaskSerial, arg3 MmId.
 *     It fires immediately before hvpatch-guest-lifecycle on the same host
 *     thread.
 *   hvpatch-guest-lifecycle:
 *     arg0 phase (1 Fork, 5 ProcessExit), arg1 Linux pid, arg2 Linux ppid,
 *     arg3 Linux tid, arg4 ASID.
 *   hvpatch-executor-lifecycle:
 *     arg0 executor, arg1 phase (1 Load, 2 Save, 3 Switch), arg2 ThreadSerial,
 *     arg3 ExecutionGeneration, arg4 ASID generation. A process leader's
 *     ThreadSerial is intentionally not assumed equal to its TaskSerial.
 *   hvpatch-executor-claim:
 *     arg0 TaskSerial, arg1 ThreadSerial, arg2 executor,
 *     arg3 ExecutionGeneration, arg4 validated ASID generation (zero marks
 *     invalid/unavailable snapshot authority). It fires after the scheduler
 *     claim and before backend audit/load even when later validation fails.
 *   hvpatch-fork-runtime-stage:
 *     arg0 phase (9 cumulative parent critical section), arg1 parent pid,
 *     arg2 child pid, arg3 forking tid, arg4 elapsed ns.
 *
 * A successful evidence capture requires at least one child Fork, exact claim,
 * completed load, and ProcessExit record. PID-1's direct children are ordinary
 * fork children and are included. The consumer exits nonzero on any missing
 * required stream, watchdog expiry, DTrace error, or drop.
 *
 * PERTURBATION: low. Only fork-child lifecycle and exact claim/load records
 * fire; no syscall, COW, copy, or inventory provider is enabled. Use this only
 * to locate the missing boundary; prove all liveness conclusions again without
 * DTrace. The 300-second watchdog exits the consumer without externally
 * detaching fasttrap from a continuing tracee.
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option dynvarsize=16m

dtrace:::BEGIN
{
	started = timestamp;
	bounded = 0;
	errors = 0;
	drops = 0;
	guest_forks = 0;
	guest_exits = 0;
	child_claims = 0;
	child_loads = 0;
	target_exited = 0;
	child_task[0] = 0;
	task_pid[0] = 0;
	claimed_task[0, 0] = 0;
	claim_ts[0] = 0;
	claim_thread[0] = 0;
	claim_executor[0] = 0;
	claim_generation[0] = 0;
	claim_asid_generation[0] = 0;
	load_ts[0] = 0;
	load_thread[0] = 0;
	load_executor[0] = 0;
	load_generation[0] = 0;
	load_asid_generation[0] = 0;
	printf("HVPATCHFORKDISPATCH1|header|version=1\n");
}

carrick*:::hvpatch-guest-lifecycle-identity
/(pid == $target || progenyof($target))/
{
	self->identity_pid = (int32_t)arg0;
	self->task_serial = (uint64_t)arg1;
	self->parent_serial = (uint64_t)arg2;
	self->mm = (uint64_t)arg3;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) &&
 self->identity_pid == (int32_t)arg1 && (int32_t)arg1 == (int32_t)arg3 &&
 (((uint32_t)arg0 == 1) ||
  ((uint32_t)arg0 == 5 && child_task[self->task_serial] != 0))/
{
	this->phase = (uint32_t)arg0;
	child_task[self->task_serial] = this->phase == 1 ? 1 : child_task[self->task_serial];
	task_pid[self->task_serial] = this->phase == 1 ? (int32_t)arg1 : task_pid[self->task_serial];
	printf("HVPATCHFORKDISPATCH1|guest|ts=%llu|host_pid=%d|host_tid=%d|phase=%u|pid=%d|ppid=%d|tid=%d|asid=%u|task_serial=%llu|parent_serial=%llu|mm=%llu\n",
	    timestamp, pid, tid, this->phase, (int32_t)arg1, (int32_t)arg2,
	    (int32_t)arg3, (uint32_t)arg4, self->task_serial,
	    self->parent_serial, self->mm);
	guest_forks += this->phase == 1;
	guest_exits += this->phase == 5;
	self->published_task = this->phase == 1 ? self->task_serial : 0;
}

/* Activation can let an executor claim/load before the Fork receipt prints. */
carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (uint32_t)arg0 == 1 &&
 self->published_task != 0 &&
 claim_ts[self->published_task] != 0/
{
	printf("HVPATCHFORKDISPATCH1|claim|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu|observed=before_fork_receipt\n",
	    (uint64_t)claim_ts[self->published_task], pid, tid,
	    task_pid[self->published_task], (uint64_t)self->published_task,
	    (uint64_t)claim_thread[self->published_task],
	    (uint32_t)claim_executor[self->published_task],
	    (uint64_t)claim_generation[self->published_task],
	    (uint64_t)claim_asid_generation[self->published_task]);
	child_claims++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (uint32_t)arg0 == 1 &&
 self->published_task != 0 &&
 load_ts[self->published_task] != 0/
{
	printf("HVPATCHFORKDISPATCH1|load|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu|observed=before_fork_receipt\n",
	    (uint64_t)load_ts[self->published_task], pid, tid,
	    task_pid[self->published_task], (uint64_t)self->published_task,
	    (uint64_t)load_thread[self->published_task],
	    (uint32_t)load_executor[self->published_task],
	    (uint64_t)load_generation[self->published_task],
	    (uint64_t)load_asid_generation[self->published_task]);
	child_loads++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) &&
 self->identity_pid == (int32_t)arg1 && (int32_t)arg1 == (int32_t)arg3 &&
 ((uint32_t)arg0 == 1 || (uint32_t)arg0 == 5)/
{
	self->identity_pid = 0;
	self->task_serial = 0;
	self->parent_serial = 0;
	self->mm = 0;
	self->published_task = 0;
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && (uint32_t)arg0 == 9/
{
	printf("HVPATCHFORKDISPATCH1|fork|ts=%llu|host_pid=%d|host_tid=%d|parent_pid=%d|child_pid=%d|forking_tid=%d|elapsed_ns=%llu\n",
	    timestamp, pid, tid, (int32_t)arg1, (int32_t)arg2, (int32_t)arg3,
	    (uint64_t)arg4);
}

carrick*:::hvpatch-executor-claim
/(pid == $target || progenyof($target))/
{
	claimed_task[(uint64_t)arg1, (uint64_t)arg3] = (uint64_t)arg0;
	claim_ts[(uint64_t)arg0] = timestamp;
	claim_thread[(uint64_t)arg0] = (uint64_t)arg1;
	claim_executor[(uint64_t)arg0] = (uint32_t)arg2;
	claim_generation[(uint64_t)arg0] = (uint64_t)arg3;
	claim_asid_generation[(uint64_t)arg0] = (uint64_t)arg4;
}

carrick*:::hvpatch-executor-claim
/(pid == $target || progenyof($target)) && child_task[(uint64_t)arg0] != 0/
{
	printf("HVPATCHFORKDISPATCH1|claim|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu\n",
	    timestamp, pid, tid, task_pid[(uint64_t)arg0], (uint64_t)arg0,
	    (uint64_t)arg1, (uint32_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
	child_claims++;
}

carrick*:::hvpatch-executor-lifecycle
/(pid == $target || progenyof($target)) && (uint32_t)arg1 == 1 &&
 claimed_task[(uint64_t)arg2, (uint64_t)arg3] != 0/
{
	this->task_serial = (uint64_t)claimed_task[(uint64_t)arg2, (uint64_t)arg3];
	load_ts[this->task_serial] = timestamp;
	load_thread[this->task_serial] = (uint64_t)arg2;
	load_executor[this->task_serial] = (uint32_t)arg0;
	load_generation[this->task_serial] = (uint64_t)arg3;
	load_asid_generation[this->task_serial] = (uint64_t)arg4;
}

carrick*:::hvpatch-executor-lifecycle
/(pid == $target || progenyof($target)) && (uint32_t)arg1 == 1 &&
 claimed_task[(uint64_t)arg2, (uint64_t)arg3] != 0 &&
 child_task[claimed_task[(uint64_t)arg2, (uint64_t)arg3]] != 0/
{
	this->task_serial = (uint64_t)claimed_task[(uint64_t)arg2, (uint64_t)arg3];
	printf("HVPATCHFORKDISPATCH1|load|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu\n",
	    timestamp, pid, tid, task_pid[this->task_serial], (uint64_t)this->task_serial,
	    (uint64_t)arg2, (uint32_t)arg0, (uint64_t)arg3, (uint64_t)arg4);
	child_loads++;
}

dtrace:::ERROR
{
	errors++;
	exit(3);
}

dtrace:::DROP
{
	drops++;
	exit(4);
}

proc:::exit
/pid == $target/
{
	target_exited = 1;
	this->valid = guest_forks > 0 && child_claims > 0 && child_loads > 0 &&
	    guest_exits > 0 && bounded == 0 && errors == 0 && drops == 0;
	exit(this->valid ? 0 : 2);
}

profile:::tick-1sec
/timestamp - started > 300 * 1000000000/
{
	bounded = 1;
	exit(5);
}

dtrace:::END
{
	this->valid = guest_forks > 0 && child_claims > 0 && child_loads > 0 &&
	    guest_exits > 0 && target_exited == 1 && bounded == 0 && errors == 0 &&
	    drops == 0;
	printf("HVPATCHFORKDISPATCH1|summary|status=%s|forks=%d|claims=%d|loads=%d|exits=%d|bounded=%d|errors=%d|drops=%d|target_exited=%d\n",
	    this->valid ? "ok" : "error", guest_forks, child_claims, child_loads,
	    guest_exits, bounded, errors, drops, target_exited);
}
