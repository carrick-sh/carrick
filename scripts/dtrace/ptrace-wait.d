#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=8m

dtrace:::BEGIN
{
    printf("ptrace/wait trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 117 || arg0 == 129 || arg0 == 260)/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    printf("%Y [%d guest entry] %-12s nr=%d args=[%#x,%#x,%#x,%#x]\n",
        walltimestamp, pid, copyinstr(arg1), arg0,
        this->a[0], this->a[1], this->a[2], this->a[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 117 || arg0 == 129 || arg0 == 260)/
{
    printf("%Y [%d guest ret  ] %-12s nr=%d ret=%d errno=%d\n",
        walltimestamp, pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && (int)arg0 != 0/
{
    printf("%Y [%d fork parent] child=%d\n", walltimestamp, pid, (int)arg0);
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && (int)arg0 == 0/
{
    printf("%Y [%d fork child]\n", walltimestamp, pid);
}

syscall::wait4:entry
/pid == $target || progenyof($target)/
{
    printf("%Y [%d host entry ] wait4 pid=%d options=%#x\n",
        walltimestamp, pid, (int)arg0, arg2);
}

syscall::wait4:return
/pid == $target || progenyof($target)/
{
    printf("%Y [%d host ret   ] wait4 ret=%d errno=%d\n",
        walltimestamp, pid, (int)arg0, errno);
}

syscall::waitid:entry
/pid == $target || progenyof($target)/
{
    printf("%Y [%d host entry ] waitid idtype=%d id=%d options=%#x\n",
        walltimestamp, pid, (int)arg0, (int)arg1, arg3);
}

syscall::waitid:return
/pid == $target || progenyof($target)/
{
    printf("%Y [%d host ret   ] waitid ret=%d errno=%d\n",
        walltimestamp, pid, (int)arg0, errno);
}

tick-1s
{
    secs++;
    printf("%Y [tick] %d\n", walltimestamp, secs);
}

tick-1s
/secs >= 12/
{
    exit(0);
}

dtrace:::END
{
    printf("ptrace/wait trace ended at %Y\n", walltimestamp);
}
