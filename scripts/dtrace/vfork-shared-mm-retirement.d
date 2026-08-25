#!/usr/sbin/dtrace -qs
/*
 * Fail-closed ledger for CLONE_VM/vfork exec predecessor ownership and cleanup.
 *
 * WHAT IT MEASURES. Every exec predecessor must produce one exact phase 0/1/2
 * classification triplet (authority, backend, cleanup), with shared=1 and
 * strictly increasing timestamps. Any N > 0 complete execs is accepted. Exact
 * task/thread serial, MmId, ASID, Linux PID, and Linux TID keys make the result
 * independent of per-CPU output-buffer arrival order. The companion lease
 * events measure authoritative TaskKey -> Stage1MmLease edge counts. A shared
 * authority observation followed by commit-pre-final is reported as a topology
 * change, not invalid evidence: that transition is legal generally, but is the
 * decisive signal in a single-thread parent/child reducer.
 *
 * PROVIDER ABI. Source-qualified on Darwin/arm64 at d637a487 plus this
 * diagnostic. macOS exposes only arg0..arg4 reliably for USDT; arg5 reads as
 * zero. Classification therefore uses three same-host-thread probes, each with
 * at most five scalars:
 *   hvpatch-exec-predecessor-classification
 *     (phase, task_serial, thread_serial, mm, shared)
 *   hvpatch-exec-predecessor-classification-identity
 *     (phase, task_serial, mm, linux_pid, linux_tid)
 *   hvpatch-exec-predecessor-classification-asid
 *     (phase, task_serial, mm, asid)
 * Phase ordinals are 0 authority, 1 backend, 2 cleanup. The lease probes are:
 *   hvpatch-mm-lease-lifecycle
 *     (phase, task_pid, task_serial, asid, owner_count)
 *   hvpatch-mm-lease-relation
 *     (phase, task_serial, related_pid, related_serial)
 * Lease phases are 0 shared-child-published, 1 task-edge-retired-shared,
 * 2 task-edge-retired-final, 3 exec-observed, 4 exec-commit-pre-shared, and
 * 5 exec-commit-pre-final. Phases 0 and 3 require a relation companion.
 *
 * PERTURBATION. Nine cold scalar USDT firings plus low-rate lease events per
 * exec. No syscall, scheduler, fault, VM-exit, pid, or profile stream is armed.
 * DROP/ERROR, unmatched companions, incomplete or timestamp-invalid triplets,
 * owner-count contract violations, missing target exit, and the 180-second
 * bound all produce a nonzero consumer exit. This is correctness evidence.
 */

#pragma D option quiet
#pragma D option dynvarsize=16m

dtrace:::BEGIN
{
    self->identity_pending = 0;
    self->asid_pending = 0;
    self->relation_pending = 0;
    started = timestamp;
    primary_events = 0;
    valid_primary_events = 0;
    identity_events = 0;
    asid_events = 0;
    phase0 = 0;
    phase1 = 0;
    phase2 = 0;
    completes = 0;
    open = 0;
}

dtrace:::BEGIN
{
    seen0[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    seen1[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    seen2[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    ts0[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    ts1[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    shared0[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    shared1[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    linux_pid0[0, 0, 0, 0] = 0;
    linux_tid0[0, 0, 0, 0] = 0;
}
dtrace:::BEGIN
{
    observed_seen[0, 0] = 0;
    observed_owners[0, 0] = 0;
    authority_seen[0, 0] = 0;
    authority_shared[0, 0] = 0;
}

dtrace:::BEGIN
{
    lifecycle_events = 0;
    relation_events = 0;
    observed_events = 0;
    commit_events = 0;
    topology_changes = 0;
    duplicate_errors = 0;
    order_errors = 0;
    phase_errors = 0;
    shared_errors = 0;
    pair_errors = 0;
    relation_errors = 0;
    owner_contract_errors = 0;
    topology_contract_errors = 0;
    pending_identities = 0;
    pending_asids = 0;
    pending_relations = 0;
    drops = 0;
    errors = 0;
}

dtrace:::BEGIN
{
    bounded = 0;
    target_exited = 0;
    target_exit_reason = -1;
    valid = 0;
    printf("VFSMM2|header|version=2|expected=one_or_more_clone_vm_vfork_execs|max_usdt_args=5\n");
}

carrick*:::hvpatch-exec-predecessor-classification-identity
/(pid == $target || progenyof($target))/
{
    pair_errors += self->identity_pending != 0;
    pending_identities += self->identity_pending == 0;
    identity_events++;
    self->identity_pending = 1;
    self->identity_phase = (uint32_t)arg0;
    self->identity_task = (uint64_t)arg1;
    self->identity_mm = (uint64_t)arg2;
    self->linux_pid = (int)arg3;
    self->linux_tid = (int)arg4;
}

carrick*:::hvpatch-exec-predecessor-classification-asid
/(pid == $target || progenyof($target))/
{
    pair_errors += self->asid_pending != 0;
    pending_asids += self->asid_pending == 0;
    asid_events++;
    self->asid_pending = 1;
    self->asid_phase = (uint32_t)arg0;
    self->asid_task = (uint64_t)arg1;
    self->asid_mm = (uint64_t)arg2;
    self->asid = (uint32_t)arg3;
}

carrick*:::hvpatch-exec-predecessor-classification
/(pid == $target || progenyof($target)) &&
 (self->identity_pending != 1 || self->asid_pending != 1 ||
  self->identity_phase != (uint32_t)arg0 || self->asid_phase != (uint32_t)arg0 ||
  self->identity_task != (uint64_t)arg1 || self->asid_task != (uint64_t)arg1 ||
  self->identity_mm != (uint64_t)arg3 || self->asid_mm != (uint64_t)arg3)/
{
    pair_errors++;
}

carrick*:::hvpatch-exec-predecessor-classification
/(pid == $target || progenyof($target)) && arg0 > 2/
{
    phase_errors++;
}

carrick*:::hvpatch-exec-predecessor-classification
/(pid == $target || progenyof($target)) && arg0 == 0 &&
 self->identity_pending == 1 && self->asid_pending == 1 &&
 self->identity_phase == (uint32_t)arg0 && self->asid_phase == (uint32_t)arg0 &&
 self->identity_task == (uint64_t)arg1 && self->asid_task == (uint64_t)arg1 &&
 self->identity_mm == (uint64_t)arg3 && self->asid_mm == (uint64_t)arg3/
{
    this->seen = seen0[arg1, arg2, arg3, self->asid];
    phase0++;
    valid_primary_events++;
    duplicate_errors += this->seen != 0;
    order_errors += seen1[arg1, arg2, arg3, self->asid] != 0 ||
        seen2[arg1, arg2, arg3, self->asid] != 0;
    shared_errors += (uint32_t)arg4 != 1;
    topology_contract_errors += observed_seen[arg1, self->asid] != 1;
    topology_contract_errors += observed_seen[arg1, self->asid] == 1 &&
        ((observed_owners[arg1, self->asid] > 1) != ((uint32_t)arg4 == 1));
    seen0[arg1, arg2, arg3, self->asid]++;
    ts0[arg1, arg2, arg3, self->asid] = timestamp;
    shared0[arg1, arg2, arg3, self->asid] = (uint32_t)arg4;
    linux_pid0[arg1, arg2, arg3, self->asid] = self->linux_pid;
    linux_tid0[arg1, arg2, arg3, self->asid] = self->linux_tid;
    authority_seen[arg1, self->asid]++;
    authority_shared[arg1, self->asid] = (uint32_t)arg4;
    open += this->seen == 0;
}

carrick*:::hvpatch-exec-predecessor-classification
/(pid == $target || progenyof($target)) && arg0 == 1 &&
 self->identity_pending == 1 && self->asid_pending == 1 &&
 self->identity_phase == (uint32_t)arg0 && self->asid_phase == (uint32_t)arg0 &&
 self->identity_task == (uint64_t)arg1 && self->asid_task == (uint64_t)arg1 &&
 self->identity_mm == (uint64_t)arg3 && self->asid_mm == (uint64_t)arg3/
{
    this->seen = seen1[arg1, arg2, arg3, self->asid];
    this->prior = ts0[arg1, arg2, arg3, self->asid];
    phase1++;
    valid_primary_events++;
    duplicate_errors += this->seen != 0;
    order_errors += seen0[arg1, arg2, arg3, self->asid] != 1 ||
        seen2[arg1, arg2, arg3, self->asid] != 0 ||
        this->prior == 0 || timestamp <= this->prior;
    order_errors += linux_pid0[arg1, arg2, arg3, self->asid] != self->linux_pid ||
        linux_tid0[arg1, arg2, arg3, self->asid] != self->linux_tid;
    shared_errors += (uint32_t)arg4 != 1 ||
        (seen0[arg1, arg2, arg3, self->asid] == 1 &&
        shared0[arg1, arg2, arg3, self->asid] != (uint32_t)arg4);
    seen1[arg1, arg2, arg3, self->asid]++;
    ts1[arg1, arg2, arg3, self->asid] = timestamp;
    shared1[arg1, arg2, arg3, self->asid] = (uint32_t)arg4;
}

carrick*:::hvpatch-exec-predecessor-classification
/(pid == $target || progenyof($target)) && arg0 == 2 &&
 self->identity_pending == 1 && self->asid_pending == 1 &&
 self->identity_phase == (uint32_t)arg0 && self->asid_phase == (uint32_t)arg0 &&
 self->identity_task == (uint64_t)arg1 && self->asid_task == (uint64_t)arg1 &&
 self->identity_mm == (uint64_t)arg3 && self->asid_mm == (uint64_t)arg3/
{
    this->seen = seen2[arg1, arg2, arg3, self->asid];
    this->first = ts0[arg1, arg2, arg3, self->asid];
    this->second = ts1[arg1, arg2, arg3, self->asid];
    this->ordered = seen0[arg1, arg2, arg3, self->asid] == 1 &&
        seen1[arg1, arg2, arg3, self->asid] == 1 &&
        this->seen == 0 && this->first != 0 && this->second > this->first && timestamp > this->second;
    this->ordered = this->ordered &&
        linux_pid0[arg1, arg2, arg3, self->asid] == self->linux_pid &&
        linux_tid0[arg1, arg2, arg3, self->asid] == self->linux_tid;
    this->shared = (uint32_t)arg4 == 1 &&
        shared0[arg1, arg2, arg3, self->asid] == (uint32_t)arg4 &&
        shared1[arg1, arg2, arg3, self->asid] == (uint32_t)arg4;
    phase2++;
    valid_primary_events++;
    duplicate_errors += this->seen != 0;
    order_errors += !this->ordered;
    shared_errors += !this->shared;
    seen2[arg1, arg2, arg3, self->asid]++;
    completes += this->ordered && this->shared;
    open -= this->ordered && this->shared;
}

carrick*:::hvpatch-exec-predecessor-classification
/(pid == $target || progenyof($target))/
{
    primary_events++;
    printf("VFSMM2|classification|time_ns=%llu|host_pid=%d|host_tid=%d|phase=%u|task_serial=%llu|thread_serial=%llu|linux_pid=%d|linux_tid=%d|mm=%llu|asid=%u|shared=%u|paired=%u\n",
        timestamp, pid, tid, (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        self->linux_pid, self->linux_tid, (uint64_t)arg3, self->asid,
        (uint32_t)arg4, self->identity_pending == 1 && self->asid_pending == 1);
    pending_identities -= self->identity_pending == 1;
    pending_asids -= self->asid_pending == 1;
    self->identity_pending = 0;
    self->asid_pending = 0;
}

carrick*:::hvpatch-mm-lease-relation
/(pid == $target || progenyof($target))/
{
    relation_errors += self->relation_pending != 0;
    pending_relations += self->relation_pending == 0;
    relation_events++;
    self->relation_pending = 1;
    self->relation_phase = (uint32_t)arg0;
    self->relation_task = (uint64_t)arg1;
    self->related_pid = (int)arg2;
    self->related_serial = (uint64_t)arg3;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && (arg0 == 0 || arg0 == 3) &&
 (self->relation_pending != 1 || self->relation_phase != (uint32_t)arg0 ||
  self->relation_task != (uint64_t)arg2)/
{
    relation_errors++;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    owner_contract_errors += (uint32_t)arg4 < 2;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 1/
{
    owner_contract_errors += (uint32_t)arg4 < 1;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{
    owner_contract_errors += (uint32_t)arg4 != 0;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 3/
{
    observed_events++;
    owner_contract_errors += (uint32_t)arg4 < 1;
    duplicate_errors += observed_seen[arg2, arg3] != 0;
    observed_seen[arg2, arg3]++;
    observed_owners[arg2, arg3] = (uint32_t)arg4;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 4/
{
    commit_events++;
    owner_contract_errors += (uint32_t)arg4 < 2;
    topology_contract_errors += authority_seen[arg2, arg3] != 1;
    topology_changes += authority_seen[arg2, arg3] == 1 && authority_shared[arg2, arg3] != 1;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 5/
{
    commit_events++;
    owner_contract_errors += (uint32_t)arg4 != 1;
    topology_contract_errors += authority_seen[arg2, arg3] != 1;
    topology_changes += authority_seen[arg2, arg3] == 1 && authority_shared[arg2, arg3] == 1;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target)) && arg0 > 5/
{
    phase_errors++;
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target))/
{
    lifecycle_events++;
    printf("VFSMM2|lease|time_ns=%llu|host_pid=%d|host_tid=%d|phase=%u|task_pid=%d|task_serial=%llu|asid=%u|owner_count=%u|related_pid=%d|related_serial=%llu|relation_paired=%u\n",
        timestamp, pid, tid, (uint32_t)arg0, (int)arg1, (uint64_t)arg2,
        (uint32_t)arg3, (uint32_t)arg4, self->related_pid,
        self->related_serial, self->relation_pending == 1);
    relation_errors += (arg0 != 0 && arg0 != 3) && self->relation_pending == 1;
    pending_relations -= self->relation_pending == 1;
    self->relation_pending = 0;
    self->related_pid = 0;
    self->related_serial = 0;
}

dtrace:::DROP
{
    drops++;
    exit(6);
}

dtrace:::ERROR
{
    errors++;
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    target_exit_reason = (int)arg0;
    valid = primary_events > 0 && primary_events == valid_primary_events &&
        identity_events == primary_events && asid_events == primary_events &&
        primary_events == completes * 3 && phase0 == completes &&
        phase1 == completes && phase2 == completes && open == 0 &&
        observed_events == completes && commit_events == completes &&
        lifecycle_events > 0 && relation_events > 0 &&
        pending_identities == 0 && pending_asids == 0 && pending_relations == 0 &&
        duplicate_errors == 0 && order_errors == 0 && phase_errors == 0 &&
        shared_errors == 0 && pair_errors == 0 && relation_errors == 0 &&
        owner_contract_errors == 0 && topology_contract_errors == 0 &&
        drops == 0 && errors == 0 && bounded == 0;
    exit(valid ? 0 : 5);
}

profile:::tick-1sec
/timestamp - started > 180 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("VFSMM2|summary|status=%s|primary_events=%d|valid_primary_events=%d|completes=%d|phase0=%d|phase1=%d|phase2=%d|open=%d|identity_events=%d|asid_events=%d|lifecycle_events=%d|relation_events=%d|observed_events=%d|commit_events=%d|topology_changes=%d|duplicate_errors=%d|order_errors=%d|phase_errors=%d|shared_errors=%d|pair_errors=%d|relation_errors=%d|owner_contract_errors=%d|topology_contract_errors=%d|pending_identities=%d|pending_asids=%d|pending_relations=%d|drops=%d|errors=%d|target_exited=%d|target_exit_reason=%d|bounded=%d\n",
        valid ? "ok" : "error", primary_events, valid_primary_events, completes,
        phase0, phase1, phase2, open, identity_events, asid_events,
        lifecycle_events, relation_events, observed_events, commit_events,
        topology_changes, duplicate_errors, order_errors, phase_errors,
        shared_errors, pair_errors, relation_errors, owner_contract_errors,
        topology_contract_errors, pending_identities, pending_asids,
        pending_relations, drops, errors, target_exited, target_exit_reason,
        bounded);
}
