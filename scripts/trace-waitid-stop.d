#pragma D option quiet
#pragma D option strsize=256

/*
 * Focused trace for Go os/exec TestWaitid.
 *
 * The test sends SIGSTOP to a child, starts cmd.Wait(), then sends SIGCONT.
 * Carrick must not report the stopped child as wait-complete for a WEXITED-only
 * waitid/pidfd path.
 */

dtrace:::BEGIN
{
    printf("waitid-stop trace started at %Y\n", walltimestamp);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d fork-post] child=%d pc=%#x elr=%#x\n",
        pid, (int)arg0, arg1, arg2);
}

carrick*:::execve-loaded
/pid == $target || progenyof($target)/
{
    printf("[%d execve] path=%s entry=%#x sp=%#x\n",
        pid, copyinstr(arg0), arg1, arg2);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d guest-exit] code=%d\n", pid, (int)arg1);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 57 || arg0 == 63 || arg0 == 64 || arg0 == 95 ||
     arg0 == 129 || arg0 == 220 || arg0 == 221 || arg0 == 260 ||
     arg0 == 424 || arg0 == 434)/
{
    self->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d entry] %-18s nr=%d args=[%#x,%#x,%#x,%#x,%#x,%#x]\n",
        pid, copyinstr(arg1), arg0,
        self->sa[0], self->sa[1], self->sa[2],
        self->sa[3], self->sa[4], self->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 57 || arg0 == 63 || arg0 == 64 || arg0 == 95 ||
     arg0 == 129 || arg0 == 220 || arg0 == 221 || arg0 == 260 ||
     arg0 == 424 || arg0 == 434)/
{
    printf("[%d ret  ] %-18s nr=%d ret=%d errno=%d\n",
        pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
}

syscall::kill:entry
/pid == $target || progenyof($target)/
{
    self->kill_pid = (int)arg0;
    self->kill_sig = (int)arg1;
}

syscall::kill:return
/pid == $target || progenyof($target)/
{
    printf("[%d HOST] kill(pid=%d,sig=%d) -> ret=%d errno=%d\n",
        pid, self->kill_pid, self->kill_sig, (int)arg1, errno);
}

syscall::waitid:entry
/pid == $target || progenyof($target)/
{
    self->waitid_idtype = (int)arg0;
    self->waitid_id = (int)arg1;
    self->waitid_options = (int)arg3;
}

syscall::waitid:return
/pid == $target || progenyof($target)/
{
    printf("[%d HOST] waitid(idtype=%d,id=%d,options=%#x) -> ret=%d errno=%d\n",
        pid, self->waitid_idtype, self->waitid_id, self->waitid_options,
        (int)arg1, errno);
}

syscall::wait4:entry
/pid == $target || progenyof($target)/
{
    self->wait4_pid = (int)arg0;
    self->wait4_options = (int)arg2;
}

syscall::wait4:return
/pid == $target || progenyof($target)/
{
    printf("[%d HOST] wait4(pid=%d,options=%#x) -> ret=%d errno=%d\n",
        pid, self->wait4_pid, self->wait4_options, (int)arg1, errno);
}

syscall::kevent:entry
/pid == $target || progenyof($target)/
{
    self->kevent_changelist = arg1;
    self->kevent_nchanges = (int)arg2;
    self->kevent_eventlist = arg3;
    self->kevent_nevents = (int)arg4;
}

syscall::kevent:return
/(pid == $target || progenyof($target)) && ((int)arg1 != 0 || errno != 0)/
{
    printf("[%d HOST] kevent(nchanges=%d,nevents=%d) -> ret=%d errno=%d\n",
        pid, self->kevent_nchanges, self->kevent_nevents, (int)arg1, errno);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 20/
{
    exit(0);
}
