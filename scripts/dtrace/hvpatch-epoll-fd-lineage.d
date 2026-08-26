/*
 * HVPatch guest epoll-fd lineage around an exec/fork-heavy failure.
 *
 * Question: when a guest epoll_pwait reports EBADF for fd 11 after hundreds
 * of successful waits, which guest-thread operation created, duplicated,
 * closed, or reused that descriptor immediately beforehand?
 *
 * Provider ABI qualified on this host against the exact signed Carrick DOF
 * and crates/carrick-observability/src/probes.rs on 2026-08-25:
 *   syscall-entry: arg0=Linux nr, arg1=name, arg2=host pointer to six u64 args
 *   syscall-return: arg0=Linux nr, arg1=name, arg2=retval, arg3=Linux errno
 *   hvpatch-guest-lifecycle: phase, Linux pid, ppid, tid, ASID
 *   epoll-result: epfd, ready-count, wait-count, timeout-ms, result-kind
 * The parent trace must use pid == $target || progenyof($target).
 *
 * Perturbation: line-oriented, but restricted to epoll/dup/fcntl/exec plus
 * close(fd=11). Use only for correctness lineage, never for performance.
 * Live qualification on the exact 2026-08-25 HVPatch artifact found that the
 * lifecycle and epoll probes fire, but the listed generic syscall probes do
 * not.  A listed probe is not a firing probe: until HVPatch publishes those
 * boundaries, this script deliberately fails closed instead of presenting the
 * lifecycle/epoll traffic as fd-lineage evidence.
 *
 * The script self-exits after 12 seconds and fails closed unless at least one
 * selected syscall-return fires.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option destructive
#pragma D option bufsize=64m

dtrace:::BEGIN
{
    printf("EFD1|begin|wall=%Y\n", walltimestamp);
}

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{
    events++;
    printf("EFD1|life|hostpid=%d|hosttid=%d|phase=%d|pid=%d|ppid=%d|tid=%d|asid=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 20 || arg0 == 21 || arg0 == 22 || arg0 == 23 ||
  arg0 == 24 || arg0 == 25 || arg0 == 57 || arg0 == 221 ||
  arg0 == 441)/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    self->nr = arg0;
    self->a0 = this->args[0];
    self->a1 = this->args[1];
    self->a2 = this->args[2];
    self->a3 = this->args[3];
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr == arg0 &&
 (self->nr != 57 || self->a0 == 11)/
{
    events++;
    syscall_events++;
    printf("EFD1|ret|hostpid=%d|hosttid=%d|nr=%d|name=%s|a0=%d|a1=%d|a2=%d|a3=%d|ret=%d|errno=%d\n",
        pid, tid, (int)arg0, stringof(arg1), (int)self->a0,
        (int)self->a1, (int)self->a2, (int)self->a3,
        (int)arg2, (int)arg3);
    self->nr = 0;
    self->a0 = 0;
    self->a1 = 0;
    self->a2 = 0;
    self->a3 = 0;
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
    events++;
    printf("EFD1|epoll-result|hostpid=%d|hosttid=%d|epfd=%d|ready=%d|wait=%d|timeout=%d|kind=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

tick-12s
/syscall_events == 0/
{
    printf("EFD1|error=no-selected-syscall-return|events=%d\n", events);
    exit(1);
}

tick-12s
/syscall_events > 0/
{
    printf("EFD1|end|events=%d|syscall_events=%d\n", events, syscall_events);
    exit(0);
}
