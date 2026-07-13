#pragma D option quiet

BEGIN
{
    printf("transport phase boundaries reg_reads sysreg_reads reg_writes\n");
}

carrick*:::hvf-syscall-transport
/pid == $target || progenyof($target)/
{
    @boundaries[arg0, arg1] = count();
    @reg_reads[arg0, arg1] = sum(arg3);
    @sysreg_reads[arg0, arg1] = sum(arg4);
    @reg_writes[arg0, arg1] = sum(arg5);
}

END
{
    printa("boundaries transport=%d phase=%d %@d\n", @boundaries);
    printa("reg_reads transport=%d phase=%d %@d\n", @reg_reads);
    printa("sysreg_reads transport=%d phase=%d %@d\n", @sysreg_reads);
    printa("reg_writes transport=%d phase=%d %@d\n", @reg_writes);
}
