/*
 * Trace the guest-visible lseek11 sparse-file position transitions.
 *
 * This records lseek(2), read(2), write(2), pwrite64(2), ftruncate(2), and
 * fsync(2) entries/returns so a SEEK_HOLE answer can be paired with the read
 * that immediately follows it. It distinguishes an incorrect hole position
 * from a read-path failure without inspecting guest buffers.
 *
 * Provider ABI qualified against crates/carrick-observability/src/probes.rs:
 * syscall-entry arg0 is the canonical Linux number and arg2 points to the six
 * host-resident u64 arguments; syscall-return arg2 is the signed result and
 * arg3 is Linux errno. The carrier is $target and progeny are included.
 *
 * Perturbation: light. It copies 48 bytes only for selected syscall entries and
 * prints one line per selected entry/return. Suitable for correctness tracing,
 * not performance measurement. The 45-second tick bound reports an error when
 * no selected return fired, so an empty trace cannot look successful.
 */

#pragma D option quiet
#pragma D option strsize=128

dtrace:::BEGIN
{
    secs = 0;
    selected_returns = 0;
    printf("LSK11|begin|wall=%Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 46 || arg0 == 62 || arg0 == 63 || arg0 == 64 || arg0 == 68 || arg0 == 82)/
{
    this->a0 = *(uint64_t *)copyin(arg2, 8);
    this->a1 = *(uint64_t *)copyin(arg2 + 8, 8);
    this->a2 = *(uint64_t *)copyin(arg2 + 16, 8);
    self->nr = (int)arg0;
    self->a0 = this->a0;
    self->a1 = this->a1;
    self->a2 = this->a2;
    printf("LSK11|entry|pid=%d|nr=%d|name=%s|a0=%lld|a1=%lld|a2=%lld\n",
        pid, (int)arg0, copyinstr(arg1), (long long)this->a0,
        (long long)this->a1, (long long)this->a2);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 46 || arg0 == 62 || arg0 == 63 || arg0 == 64 || arg0 == 68 || arg0 == 82)/
{
    selected_returns++;
    printf("LSK11|return|pid=%d|nr=%d|name=%s|a0=%lld|a1=%lld|a2=%lld|ret=%lld|errno=%d\n",
        pid, (int)arg0, copyinstr(arg1), (long long)self->a0,
        (long long)self->a1, (long long)self->a2,
        (long long)arg2, (int)arg3);
    self->nr = 0;
    self->a0 = 0;
    self->a1 = 0;
    self->a2 = 0;
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 45 && selected_returns == 0/
{
    printf("LSK11|error=no-selected-syscall-return\n");
    exit(1);
}

tick-1s
/secs >= 45 && selected_returns > 0/
{
    printf("LSK11|bound|selected_returns=%d\n", selected_returns);
    exit(0);
}
