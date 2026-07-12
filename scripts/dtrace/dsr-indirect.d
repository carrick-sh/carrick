#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
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
    @source[pid, arg2] = count();
    @pair[pid, arg2, arg3] = count();
    @indirect_total[pid] = count();
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
/secs >= 15/
{
    bounded = 1;
    exit(0);
}

END
{
    printa("DSRPROF1|count|phase=indirect-source|pid=%d|source_pc=%#x|value=%@d\n", @source);
    printa("DSRPROF1|count|phase=indirect-pair|pid=%d|source_pc=%#x|target_pc=%#x|value=%@d\n", @pair);
    printa("DSRPROF1|count|phase=indirect-total|pid=%d|kind=2|value=%@d\n", @indirect_total);
    printa("DSRPROF1|count|phase=indirect-outcome|pid=%d|kind=%d|value=%@d\n", @outcome);
    printf("DSRPROF1|complete|profile=dsr-indirect|bounded=%d\n", bounded);
}
