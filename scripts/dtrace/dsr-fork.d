#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
    self->fork_repair_active = 0;
    self->fork_first_active = 0;
    self->exec_reset_active = 0;
    self->exec_first_active = 0;
    self->exec_subphase_active = 0;
    self->exec_map_active = 0;
    self->exec_map_detail_active = 0;
    self->exec_map_mmap_total = 0;
    self->exec_map_copy_total = 0;
    self->exec_map_icache_total = 0;
    self->exec_map_protect_total = 0;
    self->exec_map_vvar_total = 0;
    self->host_capsule_started = 0;
    self->host_restore_started = 0;
    self->host_dispatcher_started = 0;
    self->host_image_load_started = 0;
    self->host_reset_started = 0;
    self->host_preflight_active = 0;
    self->host_capsule_prepare_active = 0;
}

/* Phases 37/38/25: old-process preflight and capsule preparation. */
carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 37/
{
    self->host_preflight_active = 1;
    self->host_preflight_started = timestamp;
    @host_preflight_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 38 && self->host_preflight_active/
{
    this->ns = timestamp - self->host_preflight_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-preflight|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_preflight_open[pid, arg0] = sum(-1);
    self->host_preflight_active = 0;
    self->host_capsule_prepare_active = 1;
    self->host_capsule_prepare_started = timestamp;
    @host_capsule_prepare_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 25 && self->host_capsule_prepare_active/
{
    this->ns = timestamp - self->host_capsule_prepare_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-capsule-prepare|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_capsule_prepare_open[pid, arg0] = sum(-1);
    self->host_capsule_prepare_active = 0;
}

/* Phase 25/26: PID-preserving host self-exec startup.  Use a process-keyed
 * associative array because thread-local D state does not survive exec(2). */
carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 25/
{
    @host_reexec_open[pid, arg0] = sum(1);
    host_reexec_started[pid] = timestamp;
    host_reexec_tid[pid] = arg0;
}

proc:::exec-success
/pid == $target || progenyof($target)/
{
    host_reexec_exec_success[pid] = timestamp;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 27/
{
    host_reexec_probes_ready[pid] = timestamp;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 26/
{
    this->ns = timestamp - host_reexec_started[pid];
    printf("DSRPROF1|sample|phase=host-self-reexec|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    this->kernel_ns = host_reexec_exec_success[pid] - host_reexec_started[pid];
    printf("DSRPROF1|sample|phase=host-self-reexec-kernel|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->kernel_ns);
    this->resume_ns = timestamp - host_reexec_exec_success[pid];
    printf("DSRPROF1|sample|phase=host-self-reexec-resume|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->resume_ns);
    this->register_ns = host_reexec_probes_ready[pid] - host_reexec_exec_success[pid];
    printf("DSRPROF1|sample|phase=host-self-reexec-startup|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->register_ns);
    this->dispatch_ns = timestamp - host_reexec_probes_ready[pid];
    printf("DSRPROF1|sample|phase=host-self-reexec-cli-dispatch|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->dispatch_ns);
    @host_reexec_open[pid, host_reexec_tid[pid]] = sum(-1);
    host_reexec_started[pid] = 0;
    host_reexec_tid[pid] = 0;
    host_reexec_exec_success[pid] = 0;
    host_reexec_probes_ready[pid] = 0;
}

/* Phases 28-36: post-dispatch capsule and guest-image reconstruction. */
carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 28/
{
    self->host_capsule_started = timestamp;
    @host_capsule_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 29/
{
    this->ns = timestamp - self->host_capsule_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-capsule|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_capsule_open[pid, arg0] = sum(-1);
    self->host_capsule_started = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 30/
{
    self->host_restore_started = timestamp;
    self->host_dispatcher_started = timestamp;
    @host_restore_open[pid, arg0] = sum(1);
    @host_dispatcher_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 31/
{
    this->ns = timestamp - self->host_dispatcher_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-dispatcher|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_dispatcher_open[pid, arg0] = sum(-1);
    self->host_dispatcher_started = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 32/
{
    self->host_image_load_started = timestamp;
    @host_image_load_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 33/
{
    this->ns = timestamp - self->host_image_load_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-image-load|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_image_load_open[pid, arg0] = sum(-1);
    self->host_image_load_started = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 34/
{
    self->host_reset_started = timestamp;
    @host_reset_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 35/
{
    this->ns = timestamp - self->host_reset_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-reset|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_reset_open[pid, arg0] = sum(-1);
    self->host_reset_started = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 36/
{
    this->ns = timestamp - self->host_restore_started;
    printf("DSRPROF1|sample|phase=host-self-reexec-restore|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @host_restore_open[pid, arg0] = sum(-1);
    self->host_restore_started = 0;
}

proc:::exit
/pid == $target/
{
    target_exit_reason = arg0;
}

proc:::create
/(pid == $target || progenyof($target))/
{
    tracked[args[0]->pr_pid] = 1;
    active++;
}

proc:::exit
/(pid == $target || progenyof($target)) && tracked[pid] && active == 1/
{
    tracked[pid] = 0;
    active = 0;
    exit(0);
}

proc:::exit
/(pid == $target || progenyof($target)) && tracked[pid] && active > 1/
{
    tracked[pid] = 0;
    active--;
}

/* Existing fork surfaces provide an independent boundary count. */
syscall::fork:entry
/pid == $target || progenyof($target)/
{
    @host_fork_entry[pid] = count();
}

syscall::fork:return
/pid == $target || progenyof($target)/
{
    @host_fork_return[pid] = count();
}

carrick*:::fork-pre
/pid == $target || progenyof($target)/
{
    @fork_boundary[pid, 1] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && arg0 != 0/
{
    @fork_boundary[pid, 2] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    @fork_boundary[pid, 3] = count();
}

/* Phase 1/2: fork-child cache repair. */
carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 1 && self->fork_repair_active/
{
    @fork_repair_overwrite[pid, arg0] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 1 && !self->fork_repair_active/
{
    @fork_repair_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    self->fork_repair_active = 1;
    self->fork_repair_started = timestamp;
    self->fork_repair_tid = arg0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 2 && !self->fork_repair_active/
{
    @fork_repair_missing_begin[pid, arg0] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 2 && self->fork_repair_active/
{
    this->ns = timestamp - self->fork_repair_started;
    printf("DSRPROF1|sample|phase=fork-child-repair|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 2 && self->fork_repair_active && self->fork_first_active/
{
    @fork_first_overwrite[pid, arg0] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 2 && self->fork_repair_active && !self->fork_first_active/
{
    @fork_first_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 2 && self->fork_repair_active/
{
    @fork_repair_open[pid, self->fork_repair_tid] = sum(-1);
    self->fork_repair_active = 0;
    self->fork_first_active = 1;
    self->fork_first_started = timestamp;
    self->fork_first_tid = arg0;
}

carrick*:::dsr-prepare-begin
/(pid == $target || progenyof($target)) && self->fork_first_active/
{
    this->ns = timestamp - self->fork_first_started;
    printf("DSRPROF1|sample|phase=first-prepare-after-fork|pid=%d|tid=%d|duration_ns=%d\n",
        pid, self->fork_first_tid, this->ns);
    @fork_first_open[pid, self->fork_first_tid] = sum(-1);
    self->fork_first_active = 0;
}

/* Phase 3/4: exec cache reset and first translated use. */
carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 3 && self->exec_reset_active/
{
    @exec_reset_overwrite[pid, arg0] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 3 && !self->exec_reset_active/
{
    @exec_reset_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 3/
{
    self->exec_reset_active = 1;
    self->exec_reset_started = timestamp;
    self->exec_reset_tid = arg0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 4 && !self->exec_reset_active/
{
    @exec_reset_missing_begin[pid, arg0] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 4 && self->exec_reset_active/
{
    this->ns = timestamp - self->exec_reset_started;
    printf("DSRPROF1|sample|phase=exec-reset|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 4 && self->exec_reset_active && self->exec_first_active/
{
    @exec_first_overwrite[pid, arg0] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 4 && self->exec_reset_active && !self->exec_first_active/
{
    @exec_first_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 4 && self->exec_reset_active/
{
    @exec_reset_open[pid, self->exec_reset_tid] = sum(-1);
    self->exec_reset_active = 0;
    self->exec_first_active = 1;
    self->exec_first_started = timestamp;
    self->exec_first_tid = arg0;
}

carrick*:::dsr-prepare-begin
/(pid == $target || progenyof($target)) && self->exec_first_active/
{
    this->ns = timestamp - self->exec_first_started;
    printf("DSRPROF1|sample|phase=first-prepare-after-exec|pid=%d|tid=%d|duration_ns=%d\n",
        pid, self->exec_first_tid, this->ns);
    @exec_first_open[pid, self->exec_first_tid] = sum(-1);
    self->exec_first_active = 0;
}

/* Low-perturbation exec-map totals: one probe per component and exec. */
carrick*:::dsr-exec-map-detail
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    printf("DSRPROF1|sample|phase=exec-map-mmap|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, arg2);
    printf("DSRPROF1|count|phase=exec-map-mmap-bytes|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg3);
    printf("DSRPROF1|count|phase=exec-map-mmap-operations|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg4);
}

carrick*:::dsr-exec-map-detail
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    printf("DSRPROF1|sample|phase=exec-map-copy|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, arg2);
    printf("DSRPROF1|count|phase=exec-map-copy-bytes|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg3);
    printf("DSRPROF1|count|phase=exec-map-copy-operations|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg4);
}

carrick*:::dsr-exec-map-detail
/(pid == $target || progenyof($target)) && arg1 == 3/
{
    printf("DSRPROF1|sample|phase=exec-map-icache|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, arg2);
    printf("DSRPROF1|count|phase=exec-map-icache-bytes|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg3);
    printf("DSRPROF1|count|phase=exec-map-icache-operations|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg4);
}

carrick*:::dsr-exec-map-detail
/(pid == $target || progenyof($target)) && arg1 == 4/
{
    printf("DSRPROF1|sample|phase=exec-map-protect|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, arg2);
    printf("DSRPROF1|count|phase=exec-map-protect-bytes|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg3);
    printf("DSRPROF1|count|phase=exec-map-protect-operations|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg4);
}

carrick*:::dsr-exec-map-detail
/(pid == $target || progenyof($target)) && arg1 == 5/
{
    printf("DSRPROF1|sample|phase=exec-map-vvar|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, arg2);
    printf("DSRPROF1|count|phase=exec-map-vvar-bytes|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg3);
    printf("DSRPROF1|count|phase=exec-map-vvar-operations|pid=%d|tid=%d|value=%d\n",
        pid, arg0, arg4);
}

/* Reserved phases 15..24 are no longer fired; aggregate detail probes above
 * replace their high-frequency begin/end pairs. */

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg1 == 15 || arg1 == 17 || arg1 == 19 || arg1 == 21 || arg1 == 23) &&
 self->exec_map_detail_active/
{
    @exec_map_detail_overwrite[pid, arg0, arg1] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 15 && !self->exec_map_detail_active/
{
    @exec_map_mmap_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 17 && !self->exec_map_detail_active/
{
    @exec_map_copy_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 19 && !self->exec_map_detail_active/
{
    @exec_map_icache_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 21 && !self->exec_map_detail_active/
{
    @exec_map_protect_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 23 && !self->exec_map_detail_active/
{
    @exec_map_vvar_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg1 == 15 || arg1 == 17 || arg1 == 19 || arg1 == 21 || arg1 == 23)/
{
    self->exec_map_detail_active = 1;
    self->exec_map_detail_started = timestamp;
    self->exec_map_detail_phase = arg1;
    self->exec_map_detail_tid = arg0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg1 == 16 || arg1 == 18 || arg1 == 20 || arg1 == 22 || arg1 == 24) &&
 (!self->exec_map_detail_active || self->exec_map_detail_phase + 1 != arg1)/
{
    @exec_map_detail_missing_begin[pid, arg0, arg1] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 16 &&
 self->exec_map_detail_active && self->exec_map_detail_phase == 15/
{
    self->exec_map_mmap_total += timestamp - self->exec_map_detail_started;
    @exec_map_mmap_open[pid, self->exec_map_detail_tid] = sum(-1);
    self->exec_map_detail_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 18 &&
 self->exec_map_detail_active && self->exec_map_detail_phase == 17/
{
    self->exec_map_copy_total += timestamp - self->exec_map_detail_started;
    @exec_map_copy_open[pid, self->exec_map_detail_tid] = sum(-1);
    self->exec_map_detail_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 20 &&
 self->exec_map_detail_active && self->exec_map_detail_phase == 19/
{
    self->exec_map_icache_total += timestamp - self->exec_map_detail_started;
    @exec_map_icache_open[pid, self->exec_map_detail_tid] = sum(-1);
    self->exec_map_detail_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 22 &&
 self->exec_map_detail_active && self->exec_map_detail_phase == 21/
{
    self->exec_map_protect_total += timestamp - self->exec_map_detail_started;
    @exec_map_protect_open[pid, self->exec_map_detail_tid] = sum(-1);
    self->exec_map_detail_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 24 &&
 self->exec_map_detail_active && self->exec_map_detail_phase == 23/
{
    self->exec_map_vvar_total += timestamp - self->exec_map_detail_started;
    @exec_map_vvar_open[pid, self->exec_map_detail_tid] = sum(-1);
    self->exec_map_detail_active = 0;
}

/* Phases 5..14: non-overlapping exec replacement subphases. */
carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg1 == 5 || arg1 == 7 || arg1 == 9 || arg1 == 11 || arg1 == 13) &&
 self->exec_subphase_active/
{
    @exec_subphase_overwrite[pid, arg0, arg1] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 5 && !self->exec_subphase_active/
{
    @exec_image_unmap_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 7 && !self->exec_subphase_active/
{
    @exec_image_map_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 9 && !self->exec_subphase_active/
{
    @exec_cache_reset_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 11 && !self->exec_subphase_active/
{
    @exec_relocation_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 13 && !self->exec_subphase_active/
{
    @exec_translator_handoff_open[pid, arg0] = sum(1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg1 == 5 || arg1 == 7 || arg1 == 9 || arg1 == 11 || arg1 == 13)/
{
    self->exec_subphase_active = 1;
    self->exec_subphase_started = timestamp;
    self->exec_subphase_phase = arg1;
    self->exec_subphase_tid = arg0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg1 == 6 || arg1 == 8 || arg1 == 10 || arg1 == 12 || arg1 == 14) &&
 (!self->exec_subphase_active || self->exec_subphase_phase + 1 != arg1)/
{
    @exec_subphase_missing_begin[pid, arg0, arg1] = count();
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 6 &&
 self->exec_subphase_active && self->exec_subphase_phase == 5/
{
    this->ns = timestamp - self->exec_subphase_started;
    printf("DSRPROF1|sample|phase=exec-image-unmap|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @exec_image_unmap_open[pid, self->exec_subphase_tid] = sum(-1);
    self->exec_subphase_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 8 &&
 self->exec_subphase_active && self->exec_subphase_phase == 7/
{
    this->ns = timestamp - self->exec_subphase_started;
    printf("DSRPROF1|sample|phase=exec-image-map|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @exec_image_map_open[pid, self->exec_subphase_tid] = sum(-1);
    self->exec_subphase_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 10 &&
 self->exec_subphase_active && self->exec_subphase_phase == 9/
{
    this->ns = timestamp - self->exec_subphase_started;
    printf("DSRPROF1|sample|phase=exec-cache-reset|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @exec_cache_reset_open[pid, self->exec_subphase_tid] = sum(-1);
    self->exec_subphase_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 12 &&
 self->exec_subphase_active && self->exec_subphase_phase == 11/
{
    this->ns = timestamp - self->exec_subphase_started;
    printf("DSRPROF1|sample|phase=exec-relocation|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @exec_relocation_open[pid, self->exec_subphase_tid] = sum(-1);
    self->exec_subphase_active = 0;
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 14 &&
 self->exec_subphase_active && self->exec_subphase_phase == 13/
{
    this->ns = timestamp - self->exec_subphase_started;
    printf("DSRPROF1|sample|phase=exec-translator-handoff|pid=%d|tid=%d|duration_ns=%d\n",
        pid, arg0, this->ns);
    @exec_translator_handoff_open[pid, self->exec_subphase_tid] = sum(-1);
    self->exec_subphase_active = 0;
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 30/
{
    bounded = 1;
    exit(0);
}

END
{
    printa("DSRPROF1|count|phase=host-fork-entry|pid=%d|kind=1|value=%@d\n", @host_fork_entry);
    printa("DSRPROF1|count|phase=host-fork-return|pid=%d|kind=1|value=%@d\n", @host_fork_return);
    printa("DSRPROF1|count|phase=fork-boundary|pid=%d|kind=%d|value=%@d\n", @fork_boundary);

    printa("DSRPROF1|incomplete|phase=fork-child-repair|pid=%d|tid=%d|kind=open|value=%@d\n", @fork_repair_open);
    printa("DSRPROF1|incomplete|phase=fork-child-repair|pid=%d|tid=%d|kind=overwrite|value=%@d\n", @fork_repair_overwrite);
    printa("DSRPROF1|incomplete|phase=fork-child-repair|pid=%d|tid=%d|kind=missing-begin|value=%@d\n", @fork_repair_missing_begin);
    printa("DSRPROF1|incomplete|phase=first-prepare-after-fork|pid=%d|tid=%d|kind=open|value=%@d\n", @fork_first_open);
    printa("DSRPROF1|incomplete|phase=first-prepare-after-fork|pid=%d|tid=%d|kind=overwrite|value=%@d\n", @fork_first_overwrite);
    printa("DSRPROF1|incomplete|phase=host-self-reexec|pid=%d|tid=%d|kind=open|value=%@d\n", @host_reexec_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-preflight|pid=%d|tid=%d|kind=open|value=%@d\n", @host_preflight_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-capsule-prepare|pid=%d|tid=%d|kind=open|value=%@d\n", @host_capsule_prepare_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-capsule|pid=%d|tid=%d|kind=open|value=%@d\n", @host_capsule_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-dispatcher|pid=%d|tid=%d|kind=open|value=%@d\n", @host_dispatcher_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-image-load|pid=%d|tid=%d|kind=open|value=%@d\n", @host_image_load_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-reset|pid=%d|tid=%d|kind=open|value=%@d\n", @host_reset_open);
    printa("DSRPROF1|incomplete|phase=host-self-reexec-restore|pid=%d|tid=%d|kind=open|value=%@d\n", @host_restore_open);

    printa("DSRPROF1|incomplete|phase=exec-reset|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_reset_open);
    printa("DSRPROF1|incomplete|phase=exec-reset|pid=%d|tid=%d|kind=overwrite|value=%@d\n", @exec_reset_overwrite);
    printa("DSRPROF1|incomplete|phase=exec-reset|pid=%d|tid=%d|kind=missing-begin|value=%@d\n", @exec_reset_missing_begin);
    printa("DSRPROF1|incomplete|phase=first-prepare-after-exec|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_first_open);
    printa("DSRPROF1|incomplete|phase=first-prepare-after-exec|pid=%d|tid=%d|kind=overwrite|value=%@d\n", @exec_first_overwrite);
    printa("DSRPROF1|incomplete|phase=exec-image-unmap|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_image_unmap_open);
    printa("DSRPROF1|incomplete|phase=exec-image-map|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_image_map_open);
    printa("DSRPROF1|incomplete|phase=exec-cache-reset|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_cache_reset_open);
    printa("DSRPROF1|incomplete|phase=exec-relocation|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_relocation_open);
    printa("DSRPROF1|incomplete|phase=exec-translator-handoff|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_translator_handoff_open);
    printa("DSRPROF1|incomplete|phase=exec-map-mmap|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_map_mmap_open);
    printa("DSRPROF1|incomplete|phase=exec-map-copy|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_map_copy_open);
    printa("DSRPROF1|incomplete|phase=exec-map-icache|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_map_icache_open);
    printa("DSRPROF1|incomplete|phase=exec-map-protect|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_map_protect_open);
    printa("DSRPROF1|incomplete|phase=exec-map-vvar|pid=%d|tid=%d|kind=open|value=%@d\n", @exec_map_vvar_open);
    printa("DSRPROF1|incomplete|phase=exec-map-detail|pid=%d|tid=%d|kind=overwrite-%d|value=%@d\n", @exec_map_detail_overwrite);
    printa("DSRPROF1|incomplete|phase=exec-map-detail|pid=%d|tid=%d|kind=missing-begin-%d|value=%@d\n", @exec_map_detail_missing_begin);
    printa("DSRPROF1|incomplete|phase=exec-subphase|pid=%d|tid=%d|kind=overwrite-%d|value=%@d\n", @exec_subphase_overwrite);
    printa("DSRPROF1|incomplete|phase=exec-subphase|pid=%d|tid=%d|kind=missing-begin-%d|value=%@d\n", @exec_subphase_missing_begin);
    printf("DSRPROF1|complete|profile=dsr-fork|bounded=%d|target_exit_reason=%d\n",
        bounded, target_exit_reason);
}
