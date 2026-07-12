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

tick-1s
{
    secs++;
}

tick-1s
/secs >= 1/
{
    bounded = 1;
    exit(0);
}

END
{
    printf("DSRPROF1|complete|profile=dsr|bounded=%d\n", bounded);
}
