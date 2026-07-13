#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
    printf("transport phase boundaries reg_reads sysreg_reads reg_writes\n");
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

dtrace:::ERROR
{
    @dtrace_errors = count();
}

carrick*:::hvf-syscall-transport
/pid == $target || progenyof($target)/
{
    @boundaries[arg0, arg1] = count();
    @reg_reads[arg0, arg1] = sum(arg2);
    @sysreg_reads[arg0, arg1] = sum(arg3);
    @reg_writes[arg0, arg1] = sum(arg4);
}

END
{
    printa("boundaries transport=%d phase=%d %@d\n", @boundaries);
    printa("reg_reads transport=%d phase=%d %@d\n", @reg_reads);
    printa("sysreg_reads transport=%d phase=%d %@d\n", @sysreg_reads);
    printa("reg_writes transport=%d phase=%d %@d\n", @reg_writes);
    printa("dtrace_errors %@d\n", @dtrace_errors);
}
