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
    printa("DSRPROF1|incomplete|phase=exec-subphase|pid=%d|tid=%d|kind=overwrite-%d|value=%@d\n", @exec_subphase_overwrite);
    printa("DSRPROF1|incomplete|phase=exec-subphase|pid=%d|tid=%d|kind=missing-begin-%d|value=%@d\n", @exec_subphase_missing_begin);
    printf("DSRPROF1|complete|profile=dsr-fork|bounded=%d|target_exit_reason=%d\n",
        bounded, target_exit_reason);
}
