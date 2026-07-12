#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
    self->prepare_active = 0;
    self->run_active = 0;
    self->translate_active = 0;
    self->resolve_active = 0;
    self->dispatch_active = 0;
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

/* prepare_entry */
carrick*:::dsr-prepare-begin
/(pid == $target || progenyof($target)) && self->prepare_active/
{
    @prepare_overwrite[pid] = count();
}

carrick*:::dsr-prepare-begin
/(pid == $target || progenyof($target)) && !self->prepare_active/
{
    @prepare_open[pid, arg0] = sum(1);
}

carrick*:::dsr-prepare-begin
/(pid == $target || progenyof($target))/
{
    self->prepare_active = 1;
    self->prepare_started = timestamp;
    self->prepare_seq++;
}

carrick*:::dsr-prepare-end
/(pid == $target || progenyof($target)) && !self->prepare_active/
{
    @prepare_missing_begin[pid] = count();
}

carrick*:::dsr-prepare-end
/(pid == $target || progenyof($target)) && self->prepare_active && ((self->prepare_seq & 1023) == 1)/
{
    this->ns = timestamp - self->prepare_started;
    printf("DSRPROF1|sample|phase=prepare|pid=%d|tid=%d|kind=%d|duration_ns=%d|interval=1024\n",
        pid, arg0, arg4, this->ns);
}

carrick*:::dsr-prepare-end
/(pid == $target || progenyof($target)) && self->prepare_active/
{
    this->ns = timestamp - self->prepare_started;
    @prepare_count[pid, arg4] = count();
    @prepare_total[pid, arg4] = sum(this->ns);
    @prepare_min[pid, arg4] = min(this->ns);
    @prepare_max[pid, arg4] = max(this->ns);
    @prepare_open[pid, arg0] = sum(-1);
    self->prepare_active = 0;
}

/* enter_prepared gateway slice */
carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) && self->run_active/
{
    @run_overwrite[pid] = count();
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) && !self->run_active/
{
    @run_open[pid, arg0] = sum(1);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target))/
{
    self->run_active = 1;
    self->run_started = timestamp;
    self->run_seq++;
}

carrick*:::dsr-run-end
/(pid == $target || progenyof($target)) && !self->run_active/
{
    @run_missing_begin[pid] = count();
}

carrick*:::dsr-run-end
/(pid == $target || progenyof($target)) && self->run_active && ((self->run_seq & 1023) == 1)/
{
    this->ns = timestamp - self->run_started;
    printf("DSRPROF1|sample|phase=run|pid=%d|tid=%d|kind=%d|duration_ns=%d|interval=1024\n",
        pid, arg0, arg1, this->ns);
}

carrick*:::dsr-run-end
/(pid == $target || progenyof($target)) && self->run_active/
{
    this->ns = timestamp - self->run_started;
    @run_count[pid, arg1] = count();
    @run_total[pid, arg1] = sum(this->ns);
    @run_min[pid, arg1] = min(this->ns);
    @run_max[pid, arg1] = max(this->ns);
    @run_open[pid, arg0] = sum(-1);
    self->run_active = 0;
}

/* cache translation */
carrick*:::dsr-translate-begin
/(pid == $target || progenyof($target)) && self->translate_active/
{
    @translate_overwrite[pid] = count();
}

carrick*:::dsr-translate-begin
/(pid == $target || progenyof($target)) && !self->translate_active/
{
    @translate_open[pid, arg0] = sum(1);
}

carrick*:::dsr-translate-begin
/(pid == $target || progenyof($target))/
{
    self->translate_active = 1;
    self->translate_started = timestamp;
    self->translate_seq++;
}

carrick*:::dsr-translate-end
/(pid == $target || progenyof($target)) && !self->translate_active/
{
    @translate_missing_begin[pid] = count();
}

carrick*:::dsr-translate-end
/(pid == $target || progenyof($target)) && self->translate_active && ((self->translate_seq & 1023) == 1)/
{
    this->ns = timestamp - self->translate_started;
    printf("DSRPROF1|sample|phase=translate|pid=%d|tid=%d|kind=%d|duration_ns=%d|interval=1024\n",
        pid, arg0, arg4, this->ns);
}

carrick*:::dsr-translate-end
/(pid == $target || progenyof($target)) && self->translate_active/
{
    this->ns = timestamp - self->translate_started;
    @translate_count[pid, arg4] = count();
    @translate_total[pid, arg4] = sum(this->ns);
    @translate_min[pid, arg4] = min(this->ns);
    @translate_max[pid, arg4] = max(this->ns);
    @translate_open[pid, arg0] = sum(-1);
    self->translate_active = 0;
}

/* direct and indirect resolver work */
carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && self->resolve_active/
{
    @resolve_overwrite[pid] = count();
}

carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && !self->resolve_active/
{
    @resolve_open[pid, arg0] = sum(1);
}

carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target))/
{
    self->resolve_active = 1;
    self->resolve_started = timestamp;
    self->resolve_seq++;
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && !self->resolve_active/
{
    @resolve_missing_begin[pid] = count();
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && self->resolve_active && ((self->resolve_seq & 1023) == 1)/
{
    this->ns = timestamp - self->resolve_started;
    printf("DSRPROF1|sample|phase=resolve|pid=%d|tid=%d|kind=%d|duration_ns=%d|interval=1024\n",
        pid, arg0, arg1, this->ns);
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && self->resolve_active/
{
    this->ns = timestamp - self->resolve_started;
    @resolve_count[pid, arg1] = count();
    @resolve_total[pid, arg1] = sum(this->ns);
    @resolve_min[pid, arg1] = min(this->ns);
    @resolve_max[pid, arg1] = max(this->ns);
    @resolve_outcome[pid, arg4] = count();
    @resolve_open[pid, arg0] = sum(-1);
    self->resolve_active = 0;
}

/* Existing dispatcher probes cross-check the DSR syscall exit stream. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && self->dispatch_active/
{
    @dispatch_overwrite[pid] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && !self->dispatch_active/
{
    @dispatch_open[pid] = sum(1);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target))/
{
    self->dispatch_active = 1;
    self->dispatch_started = timestamp;
    self->dispatch_seq++;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && !self->dispatch_active/
{
    @dispatch_missing_begin[pid] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->dispatch_active && ((self->dispatch_seq & 1023) == 1)/
{
    this->ns = timestamp - self->dispatch_started;
    printf("DSRPROF1|sample|phase=dispatcher|pid=%d|kind=%d|duration_ns=%d|interval=1024\n",
        pid, arg0, this->ns);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->dispatch_active/
{
    this->ns = timestamp - self->dispatch_started;
    @dispatch_count[pid, arg0] = count();
    @dispatch_total[pid, arg0] = sum(this->ns);
    @dispatch_min[pid, arg0] = min(this->ns);
    @dispatch_max[pid, arg0] = max(this->ns);
    @dispatch_open[pid] = sum(-1);
    self->dispatch_active = 0;
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target))/
{
    @cache_event_count[pid, arg1] = count();
    @cache_used[pid] = max(arg4);
}

carrick*:::dsr-cache-capacity
/(pid == $target || progenyof($target))/
{
    @cache_capacity[pid] = max(arg1);
}

carrick*:::dsr-cache-lifecycle
/(pid == $target || progenyof($target))/
{
    @cache_lifecycle_count[pid, arg0, arg1] = count();
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 15/
{
    bounded = 1;
    exit(0);
}

END
{
    printa("DSRPROF1|count|phase=prepare|pid=%d|kind=%d|value=%@d\n", @prepare_count);
    printa("DSRPROF1|total|phase=prepare|pid=%d|kind=%d|value_ns=%@d\n", @prepare_total);
    printa("DSRPROF1|minimum|phase=prepare|pid=%d|kind=%d|value_ns=%@d\n", @prepare_min);
    printa("DSRPROF1|maximum|phase=prepare|pid=%d|kind=%d|value_ns=%@d\n", @prepare_max);
    printa("DSRPROF1|incomplete|phase=prepare|pid=%d|tid=%d|kind=open|value=%@d\n", @prepare_open);
    printa("DSRPROF1|incomplete|phase=prepare|pid=%d|kind=overwrite|value=%@d\n", @prepare_overwrite);
    printa("DSRPROF1|incomplete|phase=prepare|pid=%d|kind=missing-begin|value=%@d\n", @prepare_missing_begin);

    printa("DSRPROF1|count|phase=run|pid=%d|kind=%d|value=%@d\n", @run_count);
    printa("DSRPROF1|total|phase=run|pid=%d|kind=%d|value_ns=%@d\n", @run_total);
    printa("DSRPROF1|minimum|phase=run|pid=%d|kind=%d|value_ns=%@d\n", @run_min);
    printa("DSRPROF1|maximum|phase=run|pid=%d|kind=%d|value_ns=%@d\n", @run_max);
    printa("DSRPROF1|incomplete|phase=run|pid=%d|tid=%d|kind=open|value=%@d\n", @run_open);
    printa("DSRPROF1|incomplete|phase=run|pid=%d|kind=overwrite|value=%@d\n", @run_overwrite);
    printa("DSRPROF1|incomplete|phase=run|pid=%d|kind=missing-begin|value=%@d\n", @run_missing_begin);

    printa("DSRPROF1|count|phase=translate|pid=%d|kind=%d|value=%@d\n", @translate_count);
    printa("DSRPROF1|total|phase=translate|pid=%d|kind=%d|value_ns=%@d\n", @translate_total);
    printa("DSRPROF1|minimum|phase=translate|pid=%d|kind=%d|value_ns=%@d\n", @translate_min);
    printa("DSRPROF1|maximum|phase=translate|pid=%d|kind=%d|value_ns=%@d\n", @translate_max);
    printa("DSRPROF1|incomplete|phase=translate|pid=%d|tid=%d|kind=open|value=%@d\n", @translate_open);
    printa("DSRPROF1|incomplete|phase=translate|pid=%d|kind=overwrite|value=%@d\n", @translate_overwrite);
    printa("DSRPROF1|incomplete|phase=translate|pid=%d|kind=missing-begin|value=%@d\n", @translate_missing_begin);

    printa("DSRPROF1|count|phase=resolve|pid=%d|kind=%d|value=%@d\n", @resolve_count);
    printa("DSRPROF1|total|phase=resolve|pid=%d|kind=%d|value_ns=%@d\n", @resolve_total);
    printa("DSRPROF1|minimum|phase=resolve|pid=%d|kind=%d|value_ns=%@d\n", @resolve_min);
    printa("DSRPROF1|maximum|phase=resolve|pid=%d|kind=%d|value_ns=%@d\n", @resolve_max);
    printa("DSRPROF1|count|phase=resolve-outcome|pid=%d|kind=%d|value=%@d\n", @resolve_outcome);
    printa("DSRPROF1|incomplete|phase=resolve|pid=%d|tid=%d|kind=open|value=%@d\n", @resolve_open);
    printa("DSRPROF1|incomplete|phase=resolve|pid=%d|kind=overwrite|value=%@d\n", @resolve_overwrite);
    printa("DSRPROF1|incomplete|phase=resolve|pid=%d|kind=missing-begin|value=%@d\n", @resolve_missing_begin);

    printa("DSRPROF1|count|phase=dispatcher|pid=%d|kind=%d|value=%@d\n", @dispatch_count);
    printa("DSRPROF1|total|phase=dispatcher|pid=%d|kind=%d|value_ns=%@d\n", @dispatch_total);
    printa("DSRPROF1|minimum|phase=dispatcher|pid=%d|kind=%d|value_ns=%@d\n", @dispatch_min);
    printa("DSRPROF1|maximum|phase=dispatcher|pid=%d|kind=%d|value_ns=%@d\n", @dispatch_max);
    printa("DSRPROF1|incomplete|phase=dispatcher|pid=%d|kind=open|value=%@d\n", @dispatch_open);
    printa("DSRPROF1|incomplete|phase=dispatcher|pid=%d|kind=overwrite|value=%@d\n", @dispatch_overwrite);
    printa("DSRPROF1|incomplete|phase=dispatcher|pid=%d|kind=missing-begin|value=%@d\n", @dispatch_missing_begin);

    printa("DSRPROF1|count|phase=cache-event|pid=%d|kind=%d|value=%@d\n", @cache_event_count);
    printa("DSRPROF1|count|phase=cache-lifecycle|pid=%d|tid=%d|kind=%d|value=%@d\n", @cache_lifecycle_count);
    printa("DSRPROF1|high-water|metric=cache-bytes|pid=%d|used=%@d|capacity=%@d\n", @cache_used, @cache_capacity);
    printf("DSRPROF1|complete|profile=dsr|bounded=%d|target_exit_reason=%d\n",
        bounded, target_exit_reason);
}
