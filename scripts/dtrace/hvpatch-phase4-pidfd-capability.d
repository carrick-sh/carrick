#!/usr/sbin/dtrace -qs
/*
 * Attribute Go's Linux pidfd capability probe under hvpatch. Go proceeds to
 * clone(CLONE_PIDFD|CLONE_VFORK|CLONE_VM) only after pidfd_open(self),
 * waitid(P_PIDFD,self,WEXITED), and pidfd_send_signal(fd,0) match Linux.
 *
 * Provider ABI qualified on Darwin/arm64 2026-08-09: syscall-entry arg0 is the
 * aarch64 Linux syscall number and arg2 points to a host six-u64 argument
 * array; syscall-return args 0..3 are nr/name/retval/errno. Selected numbers:
 * waitid=95, clone=220, pidfd_send_signal=424, pidfd_open=434.
 *
 * Perturbation: four low-frequency syscall families only. Zero selected events
 * is an invalid capture, not evidence that Go skipped pidfds by design.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    entries = 0;
    returns = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 95 || arg0 == 220 || arg0 == 424 || arg0 == 434)/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    self->nr = (int)arg0;
    self->a0 = this->a[0];
    self->a1 = this->a[1];
    self->a2 = this->a[2];
    self->a3 = this->a[3];
    entries++;
    printf("HVPATCH4PIDFD|entry|host_pid=%d|host_tid=%d|nr=%d|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        pid, tid, self->nr, self->a0, self->a1, self->a2, self->a3);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr == (int)arg0/
{
    returns++;
    printf("HVPATCH4PIDFD|return|host_pid=%d|host_tid=%d|nr=%d|a0=0x%llx|a1=0x%llx|retval=%lld|errno=%d\n",
        pid, tid, self->nr, self->a0, self->a1, (int64_t)arg2, (int)arg3);
    self->nr = 0;
    self->a0 = 0;
    self->a1 = 0;
    self->a2 = 0;
    self->a3 = 0;
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCH4PIDFD|summary|entries=%d|returns=%d|bounded=%d|errors=%d\n",
        entries, returns, bounded, errors);
}
