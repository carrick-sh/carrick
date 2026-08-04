#pragma D option quiet
#pragma D option dynvarsize=512m
#pragma D option bufsize=64m
#pragma D option aggsize=64m
#pragma D option ustackframes=24
#pragma D option strsize=16k
#pragma D option temporal=true
#pragma D option switchrate=10ms

/*
 * Birth-keyed whole-process-tree attribution for Darwin/AArch64 native DSR.
 *
 * The launch-owned `$target` can be either the native owner (`run-elf`) or a
 * launcher whose first child owns the native translator (`run`). The first
 * in-scope translated-range reset selects the owner only after Carrick has
 * published its checked PROC_PIDTBSDINFO birth tuple. Guest fork children are
 * admitted only after proc:::create and their own host-process-birth probe.
 *
 * Raw epoch zero is the process-image startup/inherited catalog. Carrick's
 * nonzero internal catalog epoch is checked for monotonicity but normalized to
 * a per-image raw stream so an initial reset stays at zero, a fork replay moves
 * the inherited child to one, and a successful exec starts a fresh image zero.
 * Elapsed authority starts when that first complete native-owner catalog begins
 * and stops when the owner exits. Launcher setup and post-owner teardown have no
 * eligible wall ticks and therefore are deliberately outside the denominator.
 *
 * PERTURBATION: HIGH. This profile combines profile-499 CPU sampling,
 * profile-197 wall sampling, kernel stack aggregation, syscall/mach-trap
 * bracketing, and Carrick lifecycle USDT. On the 2026-08-03 cold-Go captures
 * bound to source c7e36c87, it stretched an untraced ~9.3 s process to
 * 16.2-17.7 s and raised the sampled kernel share to 52-53%. Absolute elapsed
 * and traced-vs-untraced shares are therefore diagnostic only; cite only
 * same-instrument ratios, and retain improvements only under an untraced gate.
 *
 * KERNEL-SAMPLE TRAP (qualified on Darwin 27.0 26A5388g, T8132 KDK): the live
 * PC 0xfffffe0038dc0b00 symbolizes to the local (`nm` type `s`)
 * ml_set_interrupts_enabled_with_debug+0x4c. Its preceding instruction is
 * `msr DAIFClr, #0x7`, which re-enables interrupts. A timer deferred while
 * interrupts were masked is consequently delivered at +0x4c, so this leaf is
 * an interrupt-disabled-time bucket, not residency in that function. Nearly
 * every selected stack was one frame and cannot name the preceding critical
 * section. Re-qualify the exact address and instruction on every kernel/KDK
 * change before interpreting this family.
 */

dtrace:::BEGIN
{
	started = 0;
	stopped = 0;
	root_pid = (pid_t)0;
	target_exit_reason = 0;
	timed_out = 0;
	identity_violations = 0;
	lifecycle_violations = 0;
	range_violations = 0;
	kernel_violations = 0;
	offcpu_violations = 0;
	probe_errors = 0;
	live_pids = 0;
	on_cpu_threads = 0;
	runnable_threads = 0;
	sleeping_threads = 0;

	/* Fix every retained dynamic-array value at its full intended width. */
	tracked[(pid_t)0] = 0;
	birth_seen[(pid_t)0] = 0;
	birth_sec[(pid_t)0] = (int64_t)0;
	birth_usec[(pid_t)0] = (int32_t)0;
	image_generation[(pid_t)0] = (uint64_t)0;
	current_epoch[(pid_t)0] = (uint64_t)0;
	source_epoch[(pid_t)0] = (uint64_t)0;
	exec_observed[(pid_t)0] = 0;
	range_ready[(pid_t)0] = 0;
	range_frontier[(pid_t)0] = (uint64_t)0;
	catalog_seen[(pid_t)0, (uint64_t)0] = 0;
	host_base_seen[(pid_t)0, (uint64_t)0] = 0;
	host_catalog_seen[(pid_t)0, (uint64_t)0] = 0;
	guest_base_seen[(pid_t)0, (uint64_t)0] = 0;
	canonical_host_image_catalog_seen = 0;
	canonical_host_image_catalog_pid = (pid_t)0;
	canonical_host_image_catalog = "";

	pending_parent_pid[(pid_t)0] = (pid_t)0;
	pending_parent_sec[(pid_t)0] = (int64_t)0;
	pending_parent_usec[(pid_t)0] = (int32_t)0;
	pending_parent_image[(pid_t)0] = (uint64_t)0;
	pending_parent_epoch[(pid_t)0] = (uint64_t)0;
	pending_range_frontier[(pid_t)0] = (uint64_t)0;

	thread_state[(pid_t)0, (uint64_t)0] = 0;
	thread_lifecycle[(pid_t)0, (uint64_t)0] = 0;
	kernel_depth[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	kernel_function[(pid_t)0, (uint64_t)0, (uint64_t)0] = "";
	kernel_image[(pid_t)0, (uint64_t)0, (uint64_t)0] = (uint64_t)0;
	kernel_epoch[(pid_t)0, (uint64_t)0, (uint64_t)0] = (uint64_t)0;
	terminal_scope["", ""] = 0;

	off_open[(pid_t)0, (uint64_t)0] = 0;
	off_episode[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	off_image[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	off_epoch[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	off_kind[(pid_t)0, (uint64_t)0] = 0;
	off_pc[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	off_started[(pid_t)0, (uint64_t)0] = (uint64_t)0;

	/* These two actions are substituted from the lossless launch receipts. */
	/* CARRICK_DSRPROF2_HEADER */
	/* CARRICK_DSRPROF2_TERMINALS */
}

/* Surface D action faults explicitly; partial clauses corrupt exact state. */
dtrace:::ERROR
{
	probe_errors++;
	printf("DSRERROR2|fault|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
	    arg1, arg2, arg3, arg4, arg5);
}

/* Retain every valid in-scope Carrick-published process incarnation. */
carrick*:::host-process-birth
/(pid == $target || progenyof($target)) &&
    (uint32_t)arg0 == (uint32_t)pid && (int64_t)arg1 > 0 &&
    (int32_t)arg2 >= 0 && (int32_t)arg2 < 1000000/
{
	identity_violations += birth_seen[pid] != 0 &&
	    (birth_sec[pid] != (int64_t)arg1 ||
	    birth_usec[pid] != (int32_t)arg2) ? 1 : 0;
	birth_sec[pid] = birth_seen[pid] == 0 ? (int64_t)arg1 : birth_sec[pid];
	birth_usec[pid] = birth_seen[pid] == 0 ? (int32_t)arg2 : birth_usec[pid];
	birth_seen[pid]++;
}

carrick*:::host-process-birth
/(pid == $target || progenyof($target)) &&
    !((uint32_t)arg0 == (uint32_t)pid && (int64_t)arg1 > 0 &&
    (int32_t)arg2 >= 0 && (int32_t)arg2 < 1000000)/
{
	identity_violations++;
}

/* A proc-created native child becomes attributable only with its own birth. */
carrick*:::host-process-birth
/pending_parent_pid[pid] != (pid_t)0 && tracked[pid] == 0 &&
    (uint32_t)arg0 == (uint32_t)pid && (int64_t)arg1 > 0 &&
    (int32_t)arg2 >= 0 && (int32_t)arg2 < 1000000/
{
	this->parent = pending_parent_pid[pid];
	tracked[pid] = 1;
	image_generation[pid] = (uint64_t)1;
	current_epoch[pid] = (uint64_t)0;
	source_epoch[pid] = (uint64_t)0;
	exec_observed[pid] = 0;
	range_ready[pid] = 1;
	range_frontier[pid] = pending_range_frontier[pid];
	catalog_seen[pid, (uint64_t)1] = 1;
	live_pids++;
	printf("DSRPROF2|process-create|child_pid=%d|child_sec=%d|child_usec=%d|child_image=1|child_epoch=0|parent_pid=%d|parent_sec=%d|parent_usec=%d|parent_image=%d|parent_epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], this->parent,
	    pending_parent_sec[pid], pending_parent_usec[pid],
	    pending_parent_image[pid], pending_parent_epoch[pid]);
	printf("DSRPROF2|fork-inherit|child_pid=%d|child_sec=%d|child_usec=%d|parent_pid=%d|parent_sec=%d|parent_usec=%d|parent_image=%d|parent_epoch=%d|range_frontier=%d|mapping_frontier=0\n",
	    pid, birth_sec[pid], birth_usec[pid], this->parent,
	    pending_parent_sec[pid], pending_parent_usec[pid],
	    pending_parent_image[pid], pending_parent_epoch[pid],
	    pending_range_frontier[pid]);
	pending_parent_pid[pid] = (pid_t)0;
}

/* First valid catalog reset identifies the real native owner. */
carrick*:::host-translated-range-reset
/root_pid == (pid_t)0 && (pid == $target || progenyof($target)) &&
    birth_seen[pid] != 0 && (uint64_t)arg0 > (uint64_t)0/
{
	root_pid = (pid_t)pid;
	started = timestamp;
	tracked[pid] = 1;
	image_generation[pid] = (uint64_t)1;
	current_epoch[pid] = (uint64_t)0;
	source_epoch[pid] = (uint64_t)0;
	exec_observed[pid] = 0;
	range_ready[pid] = 0;
	range_frontier[pid] = (uint64_t)0;
	live_pids++;
	printf("DSRPROF2|target-birth|pid=%d|start_sec=%d|start_usec=%d|image=1|epoch=0\n",
	    pid, birth_sec[pid], birth_usec[pid]);
}

carrick*:::host-translated-range-reset
/root_pid == (pid_t)0 && (pid == $target || progenyof($target)) &&
    !(birth_seen[pid] != 0 && (uint64_t)arg0 > (uint64_t)0)/
{
	identity_violations++;
}

/* Latch the exact parent key and catalog frontier at host fork creation. */
proc:::create
/tracked[pid]/
{
	this->child = (pid_t)args[0]->pr_pid;
	this->valid = range_ready[pid] && range_frontier[pid] > (uint64_t)0;
	this->duplicate = tracked[this->child] != 0 ||
	    pending_parent_pid[this->child] != (pid_t)0;
	lifecycle_violations += !this->valid || this->duplicate ? 1 : 0;
	pending_parent_pid[this->child] = this->valid && !this->duplicate ?
	    (pid_t)pid : pending_parent_pid[this->child];
	pending_parent_sec[this->child] = this->valid && !this->duplicate ?
	    birth_sec[pid] : pending_parent_sec[this->child];
	pending_parent_usec[this->child] = this->valid && !this->duplicate ?
	    birth_usec[pid] : pending_parent_usec[this->child];
	pending_parent_image[this->child] = this->valid && !this->duplicate ?
	    image_generation[pid] : pending_parent_image[this->child];
	pending_parent_epoch[this->child] = this->valid && !this->duplicate ?
	    current_epoch[pid] : pending_parent_epoch[this->child];
	pending_range_frontier[this->child] = this->valid && !this->duplicate ?
	    range_frontier[pid] : pending_range_frontier[this->child];
}

/*
 * `proc:::exec` is an observation, not a balanced transition: Darwin can omit
 * exec-failure. Keep attribution live until an actual exec-success retires it.
 */
proc:::exec
/tracked[pid]/
{
	printf("DSRPROF2|exec-attempt|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid]);
	exec_observed[pid] = 1;
}

proc:::exec-failure
/tracked[pid]/
{
	lifecycle_violations += exec_observed[pid] == 1 ? 0 : 1;
	printf("DSRPROF2|exec-failure|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid]);
	exec_observed[pid] = 0;
}

proc:::exec-success
/tracked[pid]/
{
	lifecycle_violations += exec_observed[pid] == 1 ? 0 : 1;
	this->retired_image = image_generation[pid];
	this->retired_epoch = current_epoch[pid];
	this->new_image = (uint64_t)(this->retired_image + 1);
	printf("DSRPROF2|exec-success|pid=%d|start_sec=%d|start_usec=%d|retired_image=%d|retired_epoch=%d|new_image=%d|new_epoch=0\n",
	    pid, birth_sec[pid], birth_usec[pid], this->retired_image,
	    this->retired_epoch, this->new_image);
	image_generation[pid] = this->new_image;
	current_epoch[pid] = (uint64_t)0;
	source_epoch[pid] = (uint64_t)0;
	range_ready[pid] = 0;
	range_frontier[pid] = (uint64_t)0;
	exec_observed[pid] = 0;
}

/* Normalize Carrick's nonzero internal epoch into the raw per-image stream. */
carrick*:::host-translated-range-reset
/tracked[pid]/
{
	this->image = image_generation[pid];
	this->seen = catalog_seen[pid, this->image];
	range_violations += (uint64_t)arg0 == (uint64_t)0 ? 1 : 0;
	range_violations += this->seen && !range_ready[pid] ? 1 : 0;
	range_violations += source_epoch[pid] != (uint64_t)0 &&
	    (uint64_t)arg0 <= source_epoch[pid] ? 1 : 0;
	current_epoch[pid] = this->seen ?
	    (uint64_t)(current_epoch[pid] + 1) : current_epoch[pid];
	source_epoch[pid] = (uint64_t)arg0;
	catalog_seen[pid, this->image] = 1;
	range_frontier[pid] = (uint64_t)0;
	range_ready[pid] = 0;
	printf("DSRPROF2|range-reset|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid]);
}

carrick*:::host-translated-range-reset
/root_pid != (pid_t)0 && (pid == $target || progenyof($target)) &&
    tracked[pid] == 0/
{
	identity_violations++;
}

carrick*:::host-translated-private-range
/tracked[pid]/
{
	this->valid = source_epoch[pid] != (uint64_t)0 &&
	    (uint64_t)arg0 == source_epoch[pid] &&
	    (uint64_t)arg1 == (uint64_t)(range_frontier[pid] + 1) &&
	    (uint64_t)arg2 < (uint64_t)arg3 &&
	    ((uint64_t)arg2 & (uint64_t)3) == (uint64_t)0 &&
	    ((uint64_t)arg3 & (uint64_t)3) == (uint64_t)0;
	range_violations += this->valid ? 0 : 1;
	range_frontier[pid] = this->valid ? (uint64_t)arg1 : range_frontier[pid];
	printf("DSRPROF2|range-private|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|sequence=%d|start=%#x|end=%#x\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg1, arg2, arg3);
}

carrick*:::host-translated-shared-range
/tracked[pid]/
{
	this->valid = source_epoch[pid] != (uint64_t)0 &&
	    (uint64_t)arg0 == source_epoch[pid] &&
	    (uint64_t)arg1 == (uint64_t)(range_frontier[pid] + 1) &&
	    (uint64_t)arg2 > (uint64_t)0 &&
	    (uint64_t)arg3 < (uint64_t)arg4 &&
	    ((uint64_t)arg3 & (uint64_t)3) == (uint64_t)0 &&
	    ((uint64_t)arg4 & (uint64_t)3) == (uint64_t)0;
	range_violations += this->valid ? 0 : 1;
	range_frontier[pid] = this->valid ? (uint64_t)arg1 : range_frontier[pid];
	printf("DSRPROF2|range-shared|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|sequence=%d|unit_id=%u|start=%#x|end=%#x\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg1, arg2, arg3, arg4);
}

carrick*:::host-translated-range-ready
/tracked[pid]/
{
	this->valid = source_epoch[pid] != (uint64_t)0 &&
	    (uint64_t)arg0 == source_epoch[pid] &&
	    (uint64_t)arg1 == range_frontier[pid] &&
	    range_frontier[pid] > (uint64_t)0 && range_ready[pid] == 0;
	range_violations += this->valid ? 0 : 1;
	range_ready[pid] = this->valid ? 1 : range_ready[pid];
	printf("DSRPROF2|range-ready|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|final_sequence=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg1);
}

/* Image publications occur after range activation and remain image-stable. */
carrick*:::host-image-base
/tracked[pid] && range_ready[pid] &&
    (uint32_t)arg0 == (uint32_t)pid &&
    host_base_seen[pid, image_generation[pid]] == 0/
{
	host_base_seen[pid, image_generation[pid]] = 1;
	printf("DSRPROF2|host-image-base|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|base=%#x\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg1);
}

/*
 * These filtered dyld shared-cache ranges are system-wide and process-
 * invariant. Copy the multi-page user buffer once, then replay that retained
 * kernel-side string for each process image. Re-copying every short-lived Go
 * tool child produced one BADADDR for every missing catalog row; 99/99
 * successful payloads in the qualifying cold build were byte-identical after
 * normalizing only their informational pid.
 */
carrick*:::host-image-catalog
/tracked[pid] && range_ready[pid] &&
    host_catalog_seen[pid, image_generation[pid]] == 0 &&
    canonical_host_image_catalog_seen == 0/
{
	canonical_host_image_catalog = copyinstr(arg0);
	canonical_host_image_catalog_pid = (pid_t)pid;
	canonical_host_image_catalog_seen = 1;
	host_catalog_seen[pid, image_generation[pid]] = 1;
	printf("DSRPROF2|host-image-catalog|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|catalog_pid=%d|payload=%s\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], canonical_host_image_catalog_pid,
	    canonical_host_image_catalog);
}

carrick*:::host-image-catalog
/tracked[pid] && range_ready[pid] &&
    host_catalog_seen[pid, image_generation[pid]] == 0 &&
    canonical_host_image_catalog_seen != 0/
{
	host_catalog_seen[pid, image_generation[pid]] = 1;
	printf("DSRPROF2|host-image-catalog|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|catalog_pid=%d|payload=%s\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], canonical_host_image_catalog_pid,
	    canonical_host_image_catalog);
}

carrick*:::guest-image-base
/tracked[pid] && range_ready[pid] &&
    (uint32_t)arg0 == (uint32_t)pid &&
    guest_base_seen[pid, image_generation[pid]] == 0/
{
	guest_base_seen[pid, image_generation[pid]] = 1;
	printf("DSRPROF2|guest-image-base|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|base=%#x\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg1);
}

/*
 * Balanced named syscall state. Returns without a captured entry are ignored.
 * Darwin's mach_trap provider is not balanced for blocking/continuation traps
 * (`swtch_pri`, `semaphore_wait_trap`, and `mach_msg2_trap` were all disproven
 * by the maintained live balance census), so it cannot supply exact state.
 * Those kernel samples remain attributable as kernel-non-syscall by PC/stack.
 *
 * DTrace stores zero to associative arrays by deallocating their dynamic
 * chunk. Keep kernel_depth at the nonzero idle sentinel 1 so every syscall
 * does not dirty and reallocate the same per-thread entry. Values above 1
 * encode logical depth + 1.
 */
syscall:::entry
/tracked[pid] && range_ready[pid]/
{
	this->depth = kernel_depth[pid, tid] == (uint64_t)0 ?
	    (uint64_t)1 : kernel_depth[pid, tid];
	kernel_depth[pid, tid] = (uint64_t)(this->depth + 1);
	kernel_function[pid, tid, this->depth] = probefunc;
	kernel_image[pid, tid, this->depth] = image_generation[pid];
	kernel_epoch[pid, tid, this->depth] = current_epoch[pid];
}

syscall:::return
/tracked[pid] && kernel_depth[pid, tid] > (uint64_t)1/
{
	this->depth = (uint64_t)(kernel_depth[pid, tid] - 1);
	this->valid = kernel_function[pid, tid, this->depth] == probefunc;
	kernel_violations += this->valid ? 0 : 1;
	kernel_depth[pid, tid] = this->valid ? this->depth : kernel_depth[pid, tid];
}

/* A reused Darwin thread ID becomes schedulable again only at lwp-start. */
proc:::lwp-start
/tracked[pid]/
{
	thread_lifecycle[pid, tid] = 1;
	kernel_depth[pid, tid] = (uint64_t)1;
	off_open[pid, tid] = 1;
}

/* Scheduler state and exact off-CPU transition reconciliation. */
sched:::on-cpu
/tracked[pid] && thread_lifecycle[pid, tid] != 2/
{
	on_cpu_threads -= thread_state[pid, tid] == 1 ? 1 : 0;
	runnable_threads -= thread_state[pid, tid] == 2 ? 1 : 0;
	sleeping_threads -= thread_state[pid, tid] == 3 ? 1 : 0;
	thread_state[pid, tid] = 1;
	on_cpu_threads++;
}

sched:::off-cpu
/tracked[pid] && thread_lifecycle[pid, tid] != 2/
{
	on_cpu_threads -= thread_state[pid, tid] == 1 ? 1 : 0;
	runnable_threads -= thread_state[pid, tid] == 2 ? 1 : 0;
	sleeping_threads -= thread_state[pid, tid] == 3 ? 1 : 0;
	thread_state[pid, tid] = curlwpsinfo->pr_state == SSLEEP ? 3 : 2;
	runnable_threads += curlwpsinfo->pr_state == SSLEEP ? 0 : 1;
	sleeping_threads += curlwpsinfo->pr_state == SSLEEP ? 1 : 0;
}

sched:::off-cpu
/tracked[pid] && thread_lifecycle[pid, tid] != 2 &&
    range_ready[pid]/
{
	this->duplicate = off_open[pid, tid] == 2;
	offcpu_violations += this->duplicate ? 1 : 0;
	off_episode[pid, tid] += this->duplicate ? (uint64_t)0 : (uint64_t)1;
	off_open[pid, tid] = 2;
	off_image[pid, tid] = this->duplicate ?
	    off_image[pid, tid] : image_generation[pid];
	off_epoch[pid, tid] = this->duplicate ?
	    off_epoch[pid, tid] : current_epoch[pid];
	off_kind[pid, tid] = this->duplicate ? off_kind[pid, tid] :
	    curlwpsinfo->pr_state == SSLEEP ? 1 : 2;
	off_pc[pid, tid] = this->duplicate ?
	    off_pc[pid, tid] : (uint64_t)uregs[R_PC];
	off_started[pid, tid] = this->duplicate ?
	    off_started[pid, tid] : (uint64_t)timestamp;
}

sched:::on-cpu
/tracked[pid] && thread_lifecycle[pid, tid] != 2 &&
    off_open[pid, tid] == 2/
{
	this->delta = (uint64_t)(timestamp - off_started[pid, tid]);
	this->kind = off_kind[pid, tid] == 1 ? "voluntary" : "runnable";
	@off_count[pid, birth_sec[pid], birth_usec[pid],
	    off_image[pid, tid], off_epoch[pid, tid], this->kind,
	    off_pc[pid, tid]] = count();
	@off_ns[pid, birth_sec[pid], birth_usec[pid],
	    off_image[pid, tid], off_epoch[pid, tid], this->kind,
	    off_pc[pid, tid]] = sum(this->delta);
	@off_stack_count[pid, birth_sec[pid], birth_usec[pid],
	    off_image[pid, tid], off_epoch[pid, tid], this->kind,
	    ustack(24)] = count();
	@off_stack_ns[pid, birth_sec[pid], birth_usec[pid],
	    off_image[pid, tid], off_epoch[pid, tid], this->kind,
	    ustack(24)] = sum(this->delta);
	off_open[pid, tid] = 1;
}

/* Receipt-qualified non-returning calls close only at their proven scope. */
proc:::lwp-exit
/tracked[pid] && kernel_depth[pid, tid] > (uint64_t)1 &&
    terminal_scope["syscall",
	    kernel_function[pid, tid, kernel_depth[pid, tid] - 1]] == 1/
{
	this->depth = (uint64_t)(kernel_depth[pid, tid] - 1);
	kernel_depth[pid, tid] = this->depth;
}

proc:::exit
/tracked[pid] && kernel_depth[pid, tid] > (uint64_t)1 &&
    terminal_scope["syscall",
	    kernel_function[pid, tid, kernel_depth[pid, tid] - 1]] == 2/
{
	this->depth = (uint64_t)(kernel_depth[pid, tid] - 1);
	kernel_depth[pid, tid] = this->depth;
}

proc:::lwp-exit
/tracked[pid]/
{
	thread_lifecycle[pid, tid] = 2;
	on_cpu_threads -= thread_state[pid, tid] == 1 ? 1 : 0;
	runnable_threads -= thread_state[pid, tid] == 2 ? 1 : 0;
	sleeping_threads -= thread_state[pid, tid] == 3 ? 1 : 0;
	thread_state[pid, tid] = 0;
	kernel_depth[pid, tid] = (uint64_t)1;
	off_open[pid, tid] = 1;
}

/* Aggregate CPU populations only after a complete range catalog is ready. */
profile-499
/tracked[pid] && range_ready[pid] && arg1 != 0/
{
	@cpu_user[pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg1] = count();
}

profile-499
/tracked[pid] && range_ready[pid] && arg0 != 0/
{
	this->class = kernel_depth[pid, tid] <= (uint64_t)1 ?
	    "kernel-non-syscall" : "kernel-named-syscall";
	@cpu_kernel[pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], this->class, arg0] = count();
	@cpu_kernel_stack[pid, birth_sec[pid], birth_usec[pid],
	    image_generation[pid], current_epoch[pid], this->class,
	    stack(24)] = count();
}

tick-197hz
/root_pid != (pid_t)0 && live_pids > 0/
{
	@wall_state[on_cpu_threads > 0 ? "on-cpu" :
	    runnable_threads > 0 ? "runnable-descheduled" :
	    sleeping_threads > 0 ? "all-sleeping" : "transition"] = count();
}

/* Process exit retires only a birth-keyed owner; launcher exit ends capture. */
proc:::exit
/tracked[pid]/
{
	printf("DSRPROF2|process-exit|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|reason=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    current_epoch[pid], arg0);
	target_exit_reason = pid == root_pid ? arg0 : target_exit_reason;
	stopped = pid == root_pid ? timestamp : stopped;
	tracked[pid] = 0;
	range_ready[pid] = 0;
	exec_observed[pid] = 0;
	live_pids--;
}

proc:::exit
/pid == $target/
{
	exit(0);
}

tick-180s
{
	timed_out = 1;
	exit(0);
}

dtrace:::END
{
	printa("DSRPROF2|cpu-user|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|pc=%#x|count=%@d\n",
	    @cpu_user);
	printa("DSRPROF2|cpu-kernel|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|class=%s|pc=%#x|count=%@d\n",
	    @cpu_kernel);
	printa("DSRSTACK2|begin|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|kind=%s|count=%@d|total_ns=0\n%kDSRSTACK2|end\n",
	    @cpu_kernel_stack);
	printa("DSRPROF2|offcpu|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|kind=%s|pc=%#x|count=%@d|total_ns=%@d\n",
	    @off_count, @off_ns);
	printa("DSRSTACK2|begin|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|kind=offcpu-%s|count=%@d|total_ns=%@d\n%kDSRSTACK2|end\n",
	    @off_stack_count, @off_stack_ns);
	printa("DSRPROF2|wall-state|kind=%s|count=%@d\n", @wall_state);
	printf("DSRPROF2|complete|profile=native-wall|bounded=%d|timed_out=%d|identity_violations=%d|lifecycle_violations=%d|range_violations=%d|kernel_violations=%d|offcpu_violations=%d|probe_errors=%d|target_exit_reason=%d|live_at_end=%d|elapsed_ns=%d\n",
	    timed_out || identity_violations != 0 || lifecycle_violations != 0 ||
	    range_violations != 0 || kernel_violations != 0 ||
	    offcpu_violations != 0 || probe_errors != 0, timed_out, identity_violations,
	    lifecycle_violations, range_violations, kernel_violations,
	    offcpu_violations, probe_errors, target_exit_reason, live_pids,
	    (stopped != 0 ? stopped : timestamp) - started);
}
