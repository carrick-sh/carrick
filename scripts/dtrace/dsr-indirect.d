#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
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

carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    this->word = *(uint32_t *)copyin(arg2, 4);
    this->kind = (this->word & 0xfffffc1f) == 0xd65f0000 ? 3 :
        (this->word & 0xfffffc1f) == 0xd63f0000 ? 2 :
        (this->word & 0xfffffc1f) == 0xd61f0000 ? 1 : 0;
    @source[pid, arg2] = count();
    @pair[pid, arg2, arg3] = count();
    @indirect_kind[pid, this->kind] = count();
    @indirect_total[pid] = count();
}

carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    @direct_source[pid, arg2] = count();
    @direct_pair[pid, arg2, arg3] = count();
    @direct_total[pid] = count();
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    @direct_outcome[pid, arg4] = count();
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    @outcome[pid, arg4] = count();
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 45/
{
    bounded = 1;
    exit(0);
}

END
{
    printa("DSRPROF1|count|phase=direct-source|pid=%d|source_pc=%#x|value=%@d\n", @direct_source);
    printa("DSRPROF1|count|phase=direct-pair|pid=%d|source_pc=%#x|target_pc=%#x|value=%@d\n", @direct_pair);
    printa("DSRPROF1|count|phase=direct-total|pid=%d|kind=1|value=%@d\n", @direct_total);
    printa("DSRPROF1|count|phase=direct-outcome|pid=%d|kind=%d|value=%@d\n", @direct_outcome);
    printa("DSRPROF1|count|phase=indirect-source|pid=%d|source_pc=%#x|value=%@d\n", @source);
    printa("DSRPROF1|count|phase=indirect-pair|pid=%d|source_pc=%#x|target_pc=%#x|value=%@d\n", @pair);
    printa("DSRPROF1|count|phase=indirect-kind|pid=%d|kind=%d|value=%@d\n", @indirect_kind);
    printa("DSRPROF1|count|phase=indirect-total|pid=%d|kind=2|value=%@d\n", @indirect_total);
    printa("DSRPROF1|count|phase=indirect-outcome|pid=%d|kind=%d|value=%@d\n", @outcome);
    printf("DSRPROF1|complete|profile=dsr-indirect|bounded=%d|target_exit_reason=%d\n",
        bounded, target_exit_reason);
}
