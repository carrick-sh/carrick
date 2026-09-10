#!/usr/sbin/dtrace -s
/*
 * Birth-keyed native fault ownership for Darwin/AArch64 DSR.
 *
 * WHAT IT MEASURES
 * ----------------
 * Exact per-process as_fault, zfod, and cow_fault totals plus a deterministic
 * 1/64 sample of exact fault pages. Carrick publishes the immutable host ranges
 * owned by each active native guest image; the Rust parser joins sampled pages
 * to those catalogs and classifies guest-owned versus host-other faults.
 *
 * The profile also exports every completed guest mmap/munmap/mprotect/madvise
 * operation and every exact zfod event either inside one of those operations or
 * subsequently inside the native heap/mmap arenas. Everything else is counted
 * in an explicit unexported remainder. The Rust reader requires
 * exported+unexported == the exact provider total and zero operations in flight.
 * This is intentionally an export contract: semantic-sequence replay remains an
 * offline operation and cannot perturb the ordinary runtime when no consumer is
 * attached.
 *
 * PROVIDER ABI (LIVE-QUALIFIED ON THE CAPTURE HOST)
 * ------------------------------------------------
 * `vminfo:::as_fault` and `vminfo:::zfod` arg2 are the exact 16 KiB host-page
 * base. Darwin exposes the argument as a signed scalar, so every address use
 * casts it to uint64_t before rejecting zero, noncanonical/high-half, and
 * non-16-KiB-aligned values. `vminfo:::cow_fault` arg2 is not
 * address-qualified and is count-only.
 * Process identity comes from Carrick's checked PROC_PIDTBSDINFO birth tuple;
 * fork inheritance comes from proc:::create plus the child's own birth probe.
 * The process/thread terminal map and header below are substituted only after
 * the launch qualification receipts pass.
 *
 * PERTURBATION
 * ------------
 * VERY HIGH. Fault probes fire roughly two million times on the cold-Go
 * workload, and eligible zfod events now enter the principal buffer. Exact
 * totals are lossless, but page aggregation remains sampled because the old
 * exact page census made libdtrace spend material CPU in aggregation snapshots.
 * Traced elapsed time is diagnostic metadata, never performance authority.
 */
#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=64m
#pragma D option bufsize=64m
#pragma D option temporal=true
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
	started = 0;
	stopped = 0;
	root_pid = (pid_t)0;
	target_exit = 0;
	target_exit_reason = 0;
	timed_out = 0;
	identity_violations = 0;
	lifecycle_violations = 0;
	catalog_violations = 0;
	probe_errors = 0;
	live_pids = 0;
	next_fork_id = (uint64_t)0;
	pending_forks = 0;

	/* Fix retained dynamic-array values at their intended widths. */
	tracked[(pid_t)0] = 0;
	birth_seen[(pid_t)0] = 0;
	birth_sec[(pid_t)0] = (int64_t)0;
	birth_usec[(pid_t)0] = (int32_t)0;
	image_generation[(pid_t)0] = (uint64_t)0;
	catalog_epoch[(pid_t)0] = (uint64_t)0;
	catalog_source_epoch[(pid_t)0] = (uint64_t)0;
	catalog_frontier[(pid_t)0] = (uint64_t)0;
	catalog_last_end[(pid_t)0] = (uint64_t)0;
	catalog_ready[(pid_t)0] = 0;
	catalog_seen[(pid_t)0, (uint64_t)0] = 0;
	catalog_expected[(pid_t)0] = 0;
	exec_observed[(pid_t)0] = 0;

	pending_parent_pid[(pid_t)0] = (pid_t)0;
	pending_parent_sec[(pid_t)0] = (int64_t)0;
	pending_parent_usec[(pid_t)0] = (int32_t)0;
	pending_parent_image[(pid_t)0] = (uint64_t)0;
	pending_parent_epoch[(pid_t)0] = (uint64_t)0;
	pending_catalog_frontier[(pid_t)0] = (uint64_t)0;
	pending_fork_id[(pid_t)0] = (uint64_t)0;
	memory_sequence[(pid_t)0] = (uint64_t)0;
	memory_number[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_active_sequence[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_entry_ns[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_arg0[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_arg1[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_arg2[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_arg3[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_arg4[(pid_t)0, (uint64_t)0] = (uint64_t)0;
	memory_arg5[(pid_t)0, (uint64_t)0] = (uint64_t)0;

	terminal_scope["", ""] = 0;

	/* Substituted from the lossless native launch receipts. */
	/* CARRICK_NFAULT2_HEADER */
	/* CARRICK_NFAULT2_TERMINALS */
}

/*
 * Guest memory-intent wire capture. Canonical AArch64 Linux syscall numbers:
 * munmap=215, mmap=222, mprotect=226, madvise=233. arg2 is the address of
 * Carrick's six contiguous native-u64 SyscallArgs words, qualified by the
 * existing guest-mmap-shape profile. A completed record is emitted only from
 * the matching return, but carries both timestamps so offline replay can place
 * exact zfod events that occurred inside the operation.
 */
carrick*:::syscall-entry
/tracked[pid] && ((uint64_t)arg0 == (uint64_t)215 ||
    (uint64_t)arg0 == (uint64_t)222 ||
    (uint64_t)arg0 == (uint64_t)226 ||
    (uint64_t)arg0 == (uint64_t)233) &&
    memory_number[pid, tid] == (uint64_t)0/
{
	this->args = (uint64_t *)copyin(arg2, 48);
	memory_sequence[pid]++;
	memory_number[pid, tid] = (uint64_t)arg0;
	memory_active_sequence[pid, tid] = memory_sequence[pid];
	memory_entry_ns[pid, tid] = timestamp;
	memory_arg0[pid, tid] = this->args[0];
	memory_arg1[pid, tid] = this->args[1];
	memory_arg2[pid, tid] = this->args[2];
	memory_arg3[pid, tid] = this->args[3];
	memory_arg4[pid, tid] = this->args[4];
	memory_arg5[pid, tid] = this->args[5];
	@memory_intent_entries = count();
}

carrick*:::syscall-return
/tracked[pid] && memory_number[pid, tid] != (uint64_t)0 &&
    memory_number[pid, tid] == (uint64_t)arg0/
{
	printf("NFAULT2|memory-intent|pid=%d|start_sec=%d|start_usec=%d|image=%d|tid=%d|sequence=%d|number=%d|entry_ns=%d|return_ns=%d|arg0=%d|arg1=%d|arg2=%d|arg3=%d|arg4=%d|arg5=%d|retval=%d|errno=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid], tid,
	    memory_active_sequence[pid, tid], memory_number[pid, tid],
	    memory_entry_ns[pid, tid], timestamp, memory_arg0[pid, tid],
	    memory_arg1[pid, tid], memory_arg2[pid, tid], memory_arg3[pid, tid],
	    memory_arg4[pid, tid], memory_arg5[pid, tid], (int64_t)arg2,
	    (int32_t)arg3);
	@memory_intent_returns = count();
	memory_number[pid, tid] = (uint64_t)0;
	memory_active_sequence[pid, tid] = (uint64_t)0;
	memory_entry_ns[pid, tid] = (uint64_t)0;
}
/* A D action fault makes the exact stream non-authoritative. */
dtrace:::ERROR
{
	probe_errors++;
}

/* Record each Carrick-published process incarnation exactly once. */
carrick*:::host-process-birth
/(pid == $target || progenyof($target)) && birth_seen[pid] == 0 &&
    (uint32_t)arg0 == (uint32_t)pid && (int64_t)arg1 > 0 &&
    (int32_t)arg2 >= 0 && (int32_t)arg2 < 1000000/
{
	printf("NFAULT2|birth|pid=%d|start_sec=%d|start_usec=%d\n",
	    pid, arg1, arg2);
}

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

/* A fork child is admitted only after its checked birth tuple arrives. */
carrick*:::host-process-birth
/pending_parent_pid[pid] != (pid_t)0 && tracked[pid] == 0 &&
    pending_fork_id[pid] != (uint64_t)0 &&
    (uint32_t)arg0 == (uint32_t)pid && (int64_t)arg1 > 0 &&
    (int32_t)arg2 >= 0 && (int32_t)arg2 < 1000000/
{
	this->parent = pending_parent_pid[pid];
	this->fork_id = pending_fork_id[pid];
	tracked[pid] = 1;
	image_generation[pid] = (uint64_t)1;
	catalog_epoch[pid] = pending_parent_epoch[pid];
	catalog_source_epoch[pid] = pending_parent_epoch[pid];
	catalog_frontier[pid] = pending_catalog_frontier[pid];
	catalog_ready[pid] = 1;
	catalog_seen[pid, (uint64_t)1] = 1;
	catalog_expected[pid] = 0;
	live_pids++;
	printf("NFAULT2|process-create|child_pid=%d|child_sec=%d|child_usec=%d|child_image=1|child_epoch=%d|fork_id=%d|parent_pid=%d|parent_sec=%d|parent_usec=%d|parent_image=%d|parent_epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], catalog_epoch[pid], this->fork_id,
	    this->parent, pending_parent_sec[pid], pending_parent_usec[pid],
	    pending_parent_image[pid], pending_parent_epoch[pid]);
	printf("NFAULT2|fork-inherit|child_pid=%d|child_sec=%d|child_usec=%d|child_image=1|child_epoch=%d|fork_id=%d|parent_pid=%d|parent_sec=%d|parent_usec=%d|parent_image=%d|parent_epoch=%d|range_frontier=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], catalog_epoch[pid], this->fork_id,
	    this->parent, pending_parent_sec[pid], pending_parent_usec[pid],
	    pending_parent_image[pid], pending_parent_epoch[pid],
	    pending_catalog_frontier[pid]);
	pending_parent_pid[pid] = (pid_t)0;
	pending_fork_id[pid] = (uint64_t)0;
	pending_forks--;
}

/* The first valid owned-range reset selects the native owner, not its launcher. */
carrick*:::host-native-owned-range-reset
/root_pid == (pid_t)0 && (pid == $target || progenyof($target)) &&
    birth_seen[pid] != 0 && (uint64_t)arg0 > (uint64_t)0/
{
	root_pid = (pid_t)pid;
	started = timestamp;
	tracked[pid] = 1;
	image_generation[pid] = (uint64_t)1;
	catalog_epoch[pid] = (uint64_t)0;
	catalog_ready[pid] = 0;
	catalog_expected[pid] = 0;
	live_pids++;
	printf("NFAULT2|target-birth|pid=%d|start_sec=%d|start_usec=%d|image=1\n",
	    pid, birth_sec[pid], birth_usec[pid]);
}

carrick*:::host-native-owned-range-reset
/root_pid == (pid_t)0 && (pid == $target || progenyof($target)) &&
    !(birth_seen[pid] != 0 && (uint64_t)arg0 > (uint64_t)0)/
{
	identity_violations++;
}

/*
 * Latch the complete parent catalog identity at host fork creation. Darwin's
 * proc:::create also reports same-PID thread creation on this host; those are
 * not process-tree edges and must not consume a fork id or lifecycle slot.
 */
proc:::create
/tracked[pid] && (pid_t)args[0]->pr_pid != (pid_t)pid/
{
	this->child = (pid_t)args[0]->pr_pid;
	next_fork_id++;
	this->fork_id = next_fork_id;
	this->valid = catalog_ready[pid] && catalog_frontier[pid] > (uint64_t)0;
	this->duplicate = tracked[this->child] != 0 ||
	    pending_parent_pid[this->child] != (pid_t)0 ||
	    pending_fork_id[this->child] != (uint64_t)0;
	this->valid = this->valid && this->fork_id != (uint64_t)0;
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
	    catalog_epoch[pid] : pending_parent_epoch[this->child];
	pending_catalog_frontier[this->child] = this->valid && !this->duplicate ?
	    catalog_frontier[pid] : pending_catalog_frontier[this->child];
	pending_fork_id[this->child] = this->valid && !this->duplicate ?
	    this->fork_id : pending_fork_id[this->child];
	pending_forks += this->valid && !this->duplicate ? 1 : 0;
	/* Attribute any post-fork/pre-birth samples to the inherited image. */
	image_generation[this->child] = this->valid && !this->duplicate ?
	    (uint64_t)1 : image_generation[this->child];
}

/* Host exec is observational; only success disarms the retired catalog. */
proc:::exec
/tracked[pid]/
{
	printf("NFAULT2|exec-attempt|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    catalog_epoch[pid]);
	exec_observed[pid] = 1;
}

proc:::exec-failure
/tracked[pid]/
{
	lifecycle_violations += exec_observed[pid] == 1 ? 0 : 1;
	printf("NFAULT2|exec-failure|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    catalog_epoch[pid]);
	exec_observed[pid] = 0;
}

proc:::exec-success
/tracked[pid]/
{
	lifecycle_violations += exec_observed[pid] == 1 ? 0 : 1;
	this->retired_image = image_generation[pid];
	this->retired_epoch = catalog_epoch[pid];
	this->new_image = (uint64_t)(this->retired_image + 1);
	printf("NFAULT2|exec-success|pid=%d|start_sec=%d|start_usec=%d|retired_image=%d|retired_epoch=%d|new_image=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], this->retired_image,
	    this->retired_epoch, this->new_image);
	image_generation[pid] = this->new_image;
	catalog_epoch[pid] = (uint64_t)0;
	catalog_source_epoch[pid] = (uint64_t)0;
	catalog_frontier[pid] = (uint64_t)0;
	catalog_last_end[pid] = (uint64_t)0;
	catalog_ready[pid] = 0;
	catalog_expected[pid] = 3;
	exec_observed[pid] = 0;
}

/*
 * In-process exec crosses its fatal-only mapping boundary without a host
 * proc:::exec. Phase 7 disarms the retired catalog before the first replacement
 * mapping fault; phase 8 proves mapping reached its checked end. The later
 * owned-range reset must close exactly this pending replacement.
 */
carrick*:::dsr-cache-lifecycle
/tracked[pid] && (uint32_t)arg1 == (uint32_t)7/
{
	this->valid = catalog_ready[pid] && catalog_expected[pid] == 0;
	lifecycle_violations += this->valid ? 0 : 1;
	this->retired_image = image_generation[pid];
	this->retired_epoch = catalog_epoch[pid];
	image_generation[pid] = this->valid ?
	    (uint64_t)(image_generation[pid] + 1) : image_generation[pid];
	catalog_epoch[pid] = this->valid ? (uint64_t)0 : catalog_epoch[pid];
	catalog_source_epoch[pid] = this->valid ?
	    (uint64_t)0 : catalog_source_epoch[pid];
	catalog_frontier[pid] = this->valid ? (uint64_t)0 : catalog_frontier[pid];
	catalog_last_end[pid] = this->valid ? (uint64_t)0 : catalog_last_end[pid];
	catalog_ready[pid] = this->valid ? 0 : catalog_ready[pid];
	catalog_expected[pid] = this->valid ? 1 : catalog_expected[pid];
	printf("NFAULT2|image-map-begin|pid=%d|start_sec=%d|start_usec=%d|retired_image=%d|retired_epoch=%d|new_image=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], this->retired_image,
	    this->retired_epoch, image_generation[pid]);
}

carrick*:::dsr-cache-lifecycle
/tracked[pid] && (uint32_t)arg1 == (uint32_t)8/
{
	this->valid = catalog_expected[pid] == 1;
	lifecycle_violations += this->valid ? 0 : 1;
	catalog_expected[pid] = this->valid ? 2 : catalog_expected[pid];
	printf("NFAULT2|image-map-end|pid=%d|start_sec=%d|start_usec=%d|image=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid]);
}

/* A reset is exactly one initial or replacement native image catalog. */
carrick*:::host-native-owned-range-reset
/tracked[pid]/
{
	this->initial = image_generation[pid] == (uint64_t)1 &&
	    catalog_seen[pid, (uint64_t)1] == 0 && catalog_expected[pid] == 0;
	this->prepared = catalog_expected[pid] == 2 || catalog_expected[pid] == 3;
	this->advance = catalog_ready[pid] ? 1 : 0;
	catalog_violations += this->initial || this->prepared ? 0 : 1;
	catalog_violations += this->advance ? 1 : 0;
	this->image = this->advance ?
	    (uint64_t)(image_generation[pid] + 1) : image_generation[pid];
	this->image = this->image == (uint64_t)0 ? (uint64_t)1 : this->image;
	catalog_violations += (uint64_t)arg0 == (uint64_t)0 ? 1 : 0;
	catalog_violations += catalog_seen[pid, this->image] != 0 ? 1 : 0;
	image_generation[pid] = this->image;
	catalog_epoch[pid] = (uint64_t)arg0;
	catalog_source_epoch[pid] = (uint64_t)arg0;
	catalog_frontier[pid] = (uint64_t)0;
	catalog_last_end[pid] = (uint64_t)0;
	catalog_ready[pid] = 0;
	catalog_seen[pid, this->image] = 1;
	catalog_expected[pid] = 0;
	printf("NFAULT2|catalog-reset|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    catalog_epoch[pid]);
}

carrick*:::host-native-owned-range-reset
/root_pid != (pid_t)0 && (pid == $target || progenyof($target)) &&
    tracked[pid] == 0/
{
	identity_violations++;
}

carrick*:::host-native-owned-range-add
/tracked[pid]/
{
	this->valid = catalog_source_epoch[pid] != (uint64_t)0 &&
	    (uint64_t)arg0 == catalog_source_epoch[pid] &&
	    (uint64_t)arg1 == (uint64_t)(catalog_frontier[pid] + 1) &&
	    (uint64_t)arg2 < (uint64_t)arg3 &&
	    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
	    ((uint64_t)arg3 & (uint64_t)0x3fff) == (uint64_t)0 &&
	    (catalog_frontier[pid] == (uint64_t)0 ||
	    (uint64_t)arg2 >= catalog_last_end[pid]);
	catalog_violations += this->valid ? 0 : 1;
	catalog_frontier[pid] = this->valid ?
	    (uint64_t)arg1 : catalog_frontier[pid];
	catalog_last_end[pid] = this->valid ?
	    (uint64_t)arg3 : catalog_last_end[pid];
	printf("NFAULT2|catalog-range|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|sequence=%d|start=%#x|end=%#x\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    catalog_epoch[pid], arg1, arg2, arg3);
}

carrick*:::host-native-owned-range-ready
/tracked[pid]/
{
	this->valid = catalog_source_epoch[pid] != (uint64_t)0 &&
	    (uint64_t)arg0 == catalog_source_epoch[pid] &&
	    (uint64_t)arg1 == catalog_frontier[pid] &&
	    catalog_frontier[pid] > (uint64_t)0 && catalog_ready[pid] == 0;
	catalog_violations += this->valid ? 0 : 1;
	catalog_ready[pid] = this->valid ? 1 : catalog_ready[pid];
	printf("NFAULT2|catalog-ready|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|final_sequence=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    catalog_epoch[pid], arg1);
}

/* Exact birth-keyed totals. Unknown launcher work never enters these sets. */
vminfo:::as_fault
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0/
{
	@total_as[pid, birth_sec[pid], birth_usec[pid]] = count();
}

vminfo:::zfod
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0/
{
	@total_zfod[pid, birth_sec[pid], birth_usec[pid]] = count();
}

/*
 * Exact temporal export for the portion a guest-memory sequence can own.
 * Native Darwin maps the guest heap and private mmap arena at their guest VAs,
 * so arg2 can be compared directly. Faults elsewhere are still exact in the
 * ordinary totals and enter the explicit unexported remainder unless they
 * occurred while one of the four guest memory syscalls was active.
 */
vminfo:::zfod
/(pid == $target || progenyof($target)) &&
    (birth_seen[pid] != 0 || pending_fork_id[pid] != (uint64_t)0)/
{
	@memory_total_zfod = count();
}

vminfo:::zfod
/tracked[pid] && (uint64_t)arg2 != (uint64_t)0 &&
    (uint64_t)arg2 < (uint64_t)0x0001000000000000 &&
    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
    (memory_number[pid, tid] != (uint64_t)0 ||
    ((uint64_t)arg2 >= (uint64_t)0x0000000800000000 &&
    (uint64_t)arg2 < (uint64_t)0x0000000808000000) ||
    ((uint64_t)arg2 >= (uint64_t)0x000000a000000000 &&
    (uint64_t)arg2 < (uint64_t)0x000000a800000000))/
{
	printf("NFAULT2|fault-event|outcome=zfod|pid=%d|start_sec=%d|start_usec=%d|image=%d|tid=%d|timestamp_ns=%d|page=%#x|active_number=%d|active_sequence=%d|scope=%s\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid], tid,
	    timestamp, (uint64_t)arg2, memory_number[pid, tid],
	    memory_active_sequence[pid, tid],
	    memory_number[pid, tid] != (uint64_t)0 ?
	    "active-memory" : "guest-arena");
	@memory_exported_zfod = count();
}

vminfo:::zfod
/(pid == $target || progenyof($target)) &&
    (birth_seen[pid] != 0 || pending_fork_id[pid] != (uint64_t)0) &&
    !(tracked[pid] && (uint64_t)arg2 != (uint64_t)0 &&
    (uint64_t)arg2 < (uint64_t)0x0001000000000000 &&
    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
    (memory_number[pid, tid] != (uint64_t)0 ||
    ((uint64_t)arg2 >= (uint64_t)0x0000000800000000 &&
    (uint64_t)arg2 < (uint64_t)0x0000000808000000) ||
    ((uint64_t)arg2 >= (uint64_t)0x000000a000000000 &&
    (uint64_t)arg2 < (uint64_t)0x000000a800000000)))/
{
	@memory_unexported_zfod = count();
}

vminfo:::cow_fault
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0/
{
	@total_cow[pid, birth_sec[pid], birth_usec[pid]] = count();
}

/*
 * Preserve the narrow fork-child window before its birth publication. The
 * unique fork id is emitted again with the later checked child birth, so Rust
 * can bind these totals/pages to the exact child and inherited catalog without
 * trusting PID shape or dropping work from the target-tree census.
 */
vminfo:::as_fault
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0/
{
	@prebirth_total_as[pending_fork_id[pid]] = count();
}

vminfo:::zfod
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0/
{
	@prebirth_total_zfod[pending_fork_id[pid]] = count();
}

vminfo:::cow_fault
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0/
{
	@prebirth_total_cow[pending_fork_id[pid]] = count();
}

vminfo:::as_fault
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0 &&
    ((uint64_t)arg2 == (uint64_t)0 ||
    (uint64_t)arg2 >= (uint64_t)0x0001000000000000 ||
    ((uint64_t)arg2 & (uint64_t)0x3fff) != (uint64_t)0)/
{
	@prebirth_rejected_as[pending_fork_id[pid]] = count();
}

vminfo:::zfod
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0 &&
    ((uint64_t)arg2 == (uint64_t)0 ||
    (uint64_t)arg2 >= (uint64_t)0x0001000000000000 ||
    ((uint64_t)arg2 & (uint64_t)0x3fff) != (uint64_t)0)/
{
	@prebirth_rejected_zfod[pending_fork_id[pid]] = count();
}

vminfo:::as_fault
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0 &&
    (uint64_t)arg2 != (uint64_t)0 &&
    (uint64_t)arg2 < (uint64_t)0x0001000000000000 &&
    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
    ((((uint64_t)arg2 >> 14) ^ (pid * 0x9e3779b9)) & 0x3f) == 0/
{
	@prebirth_page_as[pending_fork_id[pid], (uint64_t)arg2] = count();
}

vminfo:::zfod
/pending_fork_id[pid] != (uint64_t)0 && birth_seen[pid] == 0 &&
    (uint64_t)arg2 != (uint64_t)0 &&
    (uint64_t)arg2 < (uint64_t)0x0001000000000000 &&
    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
    ((((uint64_t)arg2 >> 14) ^ (pid * 0x9e3779b9)) & 0x3f) == 0/
{
	@prebirth_page_zfod[pending_fork_id[pid], (uint64_t)arg2] = count();
}

/* Exact provider-shape rejection counts remain separate from page sampling. */
vminfo:::as_fault
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0 &&
    ((uint64_t)arg2 == (uint64_t)0 ||
    (uint64_t)arg2 >= (uint64_t)0x0001000000000000 ||
    ((uint64_t)arg2 & (uint64_t)0x3fff) != (uint64_t)0)/
{
	@rejected_as[pid, birth_sec[pid], birth_usec[pid]] = count();
}

vminfo:::zfod
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0 &&
    ((uint64_t)arg2 == (uint64_t)0 ||
    (uint64_t)arg2 >= (uint64_t)0x0001000000000000 ||
    ((uint64_t)arg2 & (uint64_t)0x3fff) != (uint64_t)0)/
{
	@rejected_zfod[pid, birth_sec[pid], birth_usec[pid]] = count();
}

/* Deterministic 1/64 samples of exact qualified 16 KiB host pages. */
vminfo:::as_fault
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0 &&
    (uint64_t)arg2 != (uint64_t)0 &&
    (uint64_t)arg2 < (uint64_t)0x0001000000000000 &&
    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
    ((((uint64_t)arg2 >> 14) ^ (pid * 0x9e3779b9)) & 0x3f) == 0/
{
	@page_as[pid, birth_sec[pid], birth_usec[pid],
	    image_generation[pid], (uint64_t)arg2] = count();
}

vminfo:::zfod
/(pid == $target || progenyof($target)) && birth_seen[pid] != 0 &&
    (uint64_t)arg2 != (uint64_t)0 &&
    (uint64_t)arg2 < (uint64_t)0x0001000000000000 &&
    ((uint64_t)arg2 & (uint64_t)0x3fff) == (uint64_t)0 &&
    ((((uint64_t)arg2 >> 14) ^ (pid * 0x9e3779b9)) & 0x3f) == 0/
{
	@page_zfod[pid, birth_sec[pid], birth_usec[pid],
	    image_generation[pid], (uint64_t)arg2] = count();
}

/*
 * A thread/process can terminate without returning from its current guest
 * syscall. Export that terminal edge explicitly so entry closure remains exact;
 * an aborted operation owns in-window faults but never mutates replayed VM
 * state. Whichever terminal provider fires first clears the slot, preventing a
 * duplicate record when both lwp-exit and process exit are observed.
 */
proc:::lwp-exit
/tracked[pid] && memory_number[pid, tid] != (uint64_t)0/
{
	printf("NFAULT2|memory-intent-abort|pid=%d|start_sec=%d|start_usec=%d|image=%d|tid=%d|sequence=%d|number=%d|entry_ns=%d|terminal_ns=%d|arg0=%d|arg1=%d|arg2=%d|arg3=%d|arg4=%d|arg5=%d|reason=thread-exit\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid], tid,
	    memory_active_sequence[pid, tid], memory_number[pid, tid],
	    memory_entry_ns[pid, tid], timestamp, memory_arg0[pid, tid],
	    memory_arg1[pid, tid], memory_arg2[pid, tid], memory_arg3[pid, tid],
	    memory_arg4[pid, tid], memory_arg5[pid, tid]);
	@memory_intent_aborts = count();
	memory_number[pid, tid] = (uint64_t)0;
	memory_active_sequence[pid, tid] = (uint64_t)0;
	memory_entry_ns[pid, tid] = (uint64_t)0;
}

proc:::exit
/tracked[pid] && memory_number[pid, tid] != (uint64_t)0/
{
	printf("NFAULT2|memory-intent-abort|pid=%d|start_sec=%d|start_usec=%d|image=%d|tid=%d|sequence=%d|number=%d|entry_ns=%d|terminal_ns=%d|arg0=%d|arg1=%d|arg2=%d|arg3=%d|arg4=%d|arg5=%d|reason=process-exit\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid], tid,
	    memory_active_sequence[pid, tid], memory_number[pid, tid],
	    memory_entry_ns[pid, tid], timestamp, memory_arg0[pid, tid],
	    memory_arg1[pid, tid], memory_arg2[pid, tid], memory_arg3[pid, tid],
	    memory_arg4[pid, tid], memory_arg5[pid, tid]);
	@memory_intent_aborts = count();
	memory_number[pid, tid] = (uint64_t)0;
	memory_active_sequence[pid, tid] = (uint64_t)0;
	memory_entry_ns[pid, tid] = (uint64_t)0;
}

/* Retire only the exact tracked incarnation; the launcher exit ends capture. */
proc:::exit
/tracked[pid]/
{
	printf("NFAULT2|process-exit|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|reason=%d\n",
	    pid, birth_sec[pid], birth_usec[pid], image_generation[pid],
	    catalog_epoch[pid], arg0);
	target_exit_reason = pid == root_pid ? arg0 : target_exit_reason;
	stopped = pid == root_pid ? timestamp : stopped;
	tracked[pid] = 0;
	catalog_ready[pid] = 0;
	exec_observed[pid] = 0;
	live_pids--;
}

proc:::exit
/pid == $target/
{
	target_exit = 1;
	exit(0);
}

tick-90s
{
	timed_out = 1;
	exit(0);
}

dtrace:::END
{
	printa("NFAULT2|page|outcome=as_fault|pid=%d|start_sec=%d|start_usec=%d|image=%d|page=%#x|count=%@u\n",
	    @page_as);
	printa("NFAULT2|page|outcome=zfod|pid=%d|start_sec=%d|start_usec=%d|image=%d|page=%#x|count=%@u\n",
	    @page_zfod);
	printa("NFAULT2|total|outcome=as_fault|pid=%d|start_sec=%d|start_usec=%d|count=%@u\n",
	    @total_as);
	printa("NFAULT2|total|outcome=zfod|pid=%d|start_sec=%d|start_usec=%d|count=%@u\n",
	    @total_zfod);
	printa("NFAULT2|total|outcome=cow_fault|pid=%d|start_sec=%d|start_usec=%d|count=%@u\n",
	    @total_cow);
	printa("NFAULT2|rejected|outcome=as_fault|pid=%d|start_sec=%d|start_usec=%d|count=%@u\n",
	    @rejected_as);
	printa("NFAULT2|rejected|outcome=zfod|pid=%d|start_sec=%d|start_usec=%d|count=%@u\n",
	    @rejected_zfod);
	printa("NFAULT2|prebirth-page|outcome=as_fault|fork_id=%d|page=%#x|count=%@u\n",
	    @prebirth_page_as);
	printa("NFAULT2|prebirth-page|outcome=zfod|fork_id=%d|page=%#x|count=%@u\n",
	    @prebirth_page_zfod);
	printa("NFAULT2|prebirth-total|outcome=as_fault|fork_id=%d|count=%@u\n",
	    @prebirth_total_as);
	printa("NFAULT2|prebirth-total|outcome=zfod|fork_id=%d|count=%@u\n",
	    @prebirth_total_zfod);
	printa("NFAULT2|prebirth-total|outcome=cow_fault|fork_id=%d|count=%@u\n",
	    @prebirth_total_cow);
	printa("NFAULT2|prebirth-rejected|outcome=as_fault|fork_id=%d|count=%@u\n",
	    @prebirth_rejected_as);
	printa("NFAULT2|prebirth-rejected|outcome=zfod|fork_id=%d|count=%@u\n",
	    @prebirth_rejected_zfod);
	printa("NFAULT2|memory-count|kind=total-zfod|count=%@u\n", @memory_total_zfod);
	printa("NFAULT2|memory-count|kind=exported-zfod|count=%@u\n", @memory_exported_zfod);
	printa("NFAULT2|memory-count|kind=unexported-zfod|count=%@u\n", @memory_unexported_zfod);
	printa("NFAULT2|memory-count|kind=intent-entries|count=%@u\n", @memory_intent_entries);
	printa("NFAULT2|memory-count|kind=intent-returns|count=%@u\n", @memory_intent_returns);
	printa("NFAULT2|memory-count|kind=intent-aborts|count=%@u\n", @memory_intent_aborts);
	printf("NFAULT2|complete|profile=native-fault|bounded=%d|timed_out=%d|target_exit=%d|target_exit_reason=%d|identity_violations=%d|lifecycle_violations=%d|catalog_violations=%d|probe_errors=%d|live_at_end=%d|pending_forks=%d|elapsed_ns=%d\n",
	    timed_out || target_exit == 0 || root_pid == (pid_t)0 ||
	    identity_violations != 0 || lifecycle_violations != 0 ||
	    catalog_violations != 0 || probe_errors != 0 || live_pids != 0 ||
	    pending_forks != 0,
	    timed_out, target_exit, target_exit_reason, identity_violations,
	    lifecycle_violations, catalog_violations, probe_errors, live_pids,
	    pending_forks,
	    started == 0 ? 0 : (stopped != 0 ? stopped : timestamp) - started);
}
