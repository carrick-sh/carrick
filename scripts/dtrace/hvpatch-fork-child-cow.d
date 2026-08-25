#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-child-cow.d — locate a fork child across scheduler claim,
 * executor load, first private-page COW, and process-lifecycle retirement.
 *
 * WHAT: marks every HVPatch process-leader fork child from the authoritative
 * guest lifecycle stream, then records its exact scheduler claim, successful
 * executor load, and frame-COW trigger. It answers whether a published child
 * was never claimed, was claimed but stuck inside backend load, or reached
 * guest execution far enough to touch its fork-shared stack.
 *
 * Provider ABI qualified from crates/carrick-observability/src/probes.rs and
 * the current Darwin/arm64 signed provider (2026-08-25):
 *   hvpatch-guest-lifecycle-identity:
 *     arg0 Linux pid, arg1 TaskSerial, arg2 parent TaskSerial, arg3 MmId.
 *   hvpatch-guest-lifecycle:
 *     arg0 phase (1 Fork, 5 ProcessExit), arg1 Linux pid, arg2 Linux ppid,
 *     arg3 Linux tid, arg4 ASID. A process leader has pid == tid.
 *   hvpatch-executor-claim:
 *     arg0 TaskSerial, arg1 ThreadSerial, arg2 executor id,
 *     arg3 execution generation, arg4 validated ASID generation (zero marks
 *     invalid/unavailable snapshot authority). It fires after the scheduler
 *     claim and before backend load even when later validation fails.
 *   hvpatch-executor-lifecycle:
 *     arg0 executor id, arg1 phase (1 Load), arg2 ThreadSerial,
 *     arg3 execution generation, arg4 ASID generation. Load fires only after
 *     backend load and hardware audit both complete.
 *   hvpatch-frame-cow-trigger-identity:
 *     arg0 Linux pid, arg1 Linux tid, arg2 MmId, arg3 ASID, arg4 class.
 *   hvpatch-frame-cow-trigger:
 *     arg0 semantic VA, arg1 syndrome, arg2 FAR, arg3 TTBR0.
 *
 * A successful evidence capture requires at least one child Fork, exact claim,
 * completed load, COW trigger, and ProcessExit record. PID-1's direct children
 * are ordinary fork children and are included. The consumer exits nonzero on
 * any missing required stream, watchdog expiry, DTrace error, or drop.
 *
 * PERTURBATION: low but nonzero. Lifecycle, one claim/load pair per scheduled
 * quantum, and frame-COW triggers only; no syscall provider, copy hashing, or
 * frame-inventory hot path is enabled. The 300-second watchdog exits the
 * consumer itself; do not externally detach fasttrap from a continuing tracee.
 */

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
	started = timestamp;
	bounded = 0;
	errors = 0;
	guest_forks = 0;
	guest_exits = 0;
	child_claims = 0;
	child_loads = 0;
	child_trigger_events = 0;
	target_exited = 0;
	drops = 0;
	fork_child[0] = 0;
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
	child_triggers[0] = 0;
	printf("HVPATCHFORKCOW1|header|version=1\n");
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
  ((uint32_t)arg0 == 5 && fork_child[(int32_t)arg1] != 0))/
{
	this->phase = (uint32_t)arg0;
	fork_child[(int32_t)arg1] = this->phase == 1 ? 1 : fork_child[(int32_t)arg1];
	child_task[self->task_serial] = this->phase == 1 ? 1 : child_task[self->task_serial];
	task_pid[self->task_serial] = this->phase == 1 ? (int32_t)arg1 : task_pid[self->task_serial];
	printf("HVPATCHFORKCOW1|guest|ts=%llu|host_pid=%d|host_tid=%d|phase=%u|pid=%d|ppid=%d|tid=%d|asid=%u|task_serial=%llu|parent_serial=%llu|mm=%llu\n",
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
 self->published_task != 0 && claim_ts[self->published_task] != 0/
{
	printf("HVPATCHFORKCOW1|claim|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu|observed=before_fork_receipt\n",
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
 self->published_task != 0 && load_ts[self->published_task] != 0/
{
	printf("HVPATCHFORKCOW1|load|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu|observed=before_fork_receipt\n",
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
	printf("HVPATCHFORKCOW1|claim|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu\n",
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
	printf("HVPATCHFORKCOW1|load|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|task_serial=%llu|thread_serial=%llu|executor=%u|generation=%llu|asid_generation=%llu\n",
	    timestamp, pid, tid, task_pid[this->task_serial], (uint64_t)this->task_serial,
	    (uint64_t)arg2, (uint32_t)arg0, (uint64_t)arg3, (uint64_t)arg4);
	child_loads++;
}

carrick*:::hvpatch-frame-cow-trigger-identity
/(pid == $target || progenyof($target))/
{
	self->trigger_pid = (int32_t)arg0;
	self->trigger_tid = (int32_t)arg1;
	self->trigger_mm = (uint64_t)arg2;
	self->trigger_asid = (uint32_t)arg3;
	self->trigger_class = (uint32_t)arg4;
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target)) && fork_child[self->trigger_pid] != 0/
{
	printf("HVPATCHFORKCOW1|trigger|ts=%llu|host_pid=%d|host_tid=%d|pid=%d|tid=%d|mm=%llu|asid=%u|class=%u|va=%llx|syndrome=%llx|far=%llx|ttbr0=%llx\n",
	    timestamp, pid, tid, self->trigger_pid, self->trigger_tid,
	    self->trigger_mm, self->trigger_asid, self->trigger_class,
	    (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3);
	child_triggers[self->trigger_pid]++;
	child_trigger_events++;
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
	    child_trigger_events > 0 && guest_exits > 0 && bounded == 0 &&
	    errors == 0 && drops == 0;
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
	    child_trigger_events > 0 && guest_exits > 0 && target_exited == 1 &&
	    bounded == 0 && errors == 0 && drops == 0;
	printf("HVPATCHFORKCOW1|summary|status=%s|forks=%d|claims=%d|loads=%d|triggers=%d|exits=%d|bounded=%d|errors=%d|drops=%d|target_exited=%d\n",
	    this->valid ? "ok" : "error", guest_forks, child_claims, child_loads,
	    child_trigger_events, guest_exits, bounded, errors, drops, target_exited);
}
