#!/usr/sbin/dtrace -qs
/*
 * Compare Linux clone(2) attempts and results with the Phase 4 guest-process
 * lifecycle census. This distinguishes a rejected CLONE_PIDFD probe from a
 * process that Carrick created but failed to publish.
 *
 * Provider ABI qualified on Darwin/arm64 2026-08-09: syscall-entry arg0 is the
 * Linux syscall number and arg2 points to a host-resident six-u64 SyscallArgs;
 * syscall-return carries nr/name/retval/errno in args 0..3. aarch64 clone is
 * syscall 220. PID/TID printed here are Darwin tracer identities; the clone
 * arguments and return are Linux guest values.
 *
 * Perturbation: every guest clone entry/return is printed (~hundreds including
 * Go runtime thread clones). Counts and exact 0x5100 PIDFD/VFORK shape are
 * diagnostic authority; timing from this capture is not citable.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    entries = 0;
    returns = 0;
    pidfd_entries = 0;
    pidfd_success = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 220/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    self->clone_flags = this->a[0];
    self->clone_stack = this->a[1];
    self->clone_parent_tid = this->a[2];
    self->clone_tls = this->a[3];
    self->clone_child_tid = this->a[4];
    entries++;
    pidfd_entries += (self->clone_flags & 0x1000) != 0;
    printf("HVPATCH4CLONE|entry|host_pid=%d|host_tid=%d|flags=0x%llx|stack=0x%llx|parent_tid=0x%llx|tls=0x%llx|child_tid=0x%llx\n",
        pid, tid, self->clone_flags, self->clone_stack,
        self->clone_parent_tid, self->clone_tls, self->clone_child_tid);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 220 && self->clone_flags != 0/
{
    returns++;
    pidfd_success += (self->clone_flags & 0x1000) != 0 && (int64_t)arg2 >= 0;
    printf("HVPATCH4CLONE|return|host_pid=%d|host_tid=%d|flags=0x%llx|retval=%lld|errno=%d\n",
        pid, tid, self->clone_flags, (int64_t)arg2, (int)arg3);
    self->clone_flags = 0;
    self->clone_stack = 0;
    self->clone_parent_tid = 0;
    self->clone_tls = 0;
    self->clone_child_tid = 0;
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
    printf("HVPATCH4CLONE|summary|entries=%d|returns=%d|pidfd_entries=%d|pidfd_success=%d|bounded=%d|errors=%d\n",
        entries, returns, pidfd_entries, pidfd_success, bounded, errors);
}
