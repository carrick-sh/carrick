#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
    self->fork_repair_active = 0;
    self->fork_first_active = 0;
    self->exec_reset_active = 0;
    self->exec_first_active = 0;
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
    printf("DSRPROF1|complete|profile=dsr-fork|bounded=%d|target_exit_reason=%d\n",
        bounded, target_exit_reason);
}
