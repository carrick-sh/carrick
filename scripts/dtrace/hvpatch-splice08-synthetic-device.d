/*
 * Trace HVPatch splice-source authority and synthetic character device routing.
 *
 * Distinguishes LTP splice08's /dev/zero and /dev/full to pipe splice data flow
 * from launch failure, route failure (EINVAL), or non-firing probes.
 *
 * Provider ABI qualified against crates/carrick-observability/src/probes.rs:
 *   carrick*:::syscall-entry(arg0=Linux nr, arg1=name, arg2=host SyscallArgs pointer)
 *   carrick*:::syscall-return(arg0=Linux nr, arg1=name, arg2=signed retval, arg3=errno)
 *   carrick*:::host-pipe-io(arg0=hostpid, arg1=host_fd, arg2=dir, arg3=n)
 *   proc:::exit
 *   tick-1s
 *
 * Scope:
 *   `$target` is the Carrick carrier process spawned by libdtrace;
 *   `progenyof($target)` is included so child tasks and forks remain tracked.
 *
 * Perturbation:
 *   Light copyin (48-byte SyscallArgs) on selected I/O entries and return
 *   accounting. Suitable for correctness verification and fault localization;
 *   not for micro-benchmark timing.
 *
 * Fail-closed criteria:
 *   Requires exact execution shape before target exit and the 20-second timeout:
 *   target-exited=1, timeout-bound=0, exactly 18 splice entries, 18 splice returns,
 *   18 non-error returns (splice_ok=18), 2 zero-length entries, 0 EINVAL, and no
 *   unreturned calls. Exit status 0 is emitted strictly on exact PASS; any missing
 *   entry, count mismatch, timeout, or EINVAL emits a FAIL/error receipt and exits 1.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=4m

dtrace:::BEGIN
{
    secs = 0;
    target_exited = 0;
    entries = 0;
    returns = 0;
    splice_entries = 0;
    splice_returns = 0;
    splice_ok = 0;
    splice_einval = 0;
    splice_zero_len = 0;
    host_pipe_ios = 0;
    printf("SPL8|begin|wall=%Y\n", walltimestamp);
}

/* Pipe creation: pipe2(59) */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 59/
{
    entries++;
    this->p0 = *(uint64_t *)copyin(arg2, 8);
    this->p1 = *(uint64_t *)copyin(arg2 + 8, 8);
    printf("SPL8|entry|pid=%d|nr=%d|name=%s|pipefd_ptr=0x%llx|flags=0x%llx\n",
        pid, (int)arg0, copyinstr(arg1),
        (unsigned long long)this->p0,
        (unsigned long long)this->p1);
}

/* Open: openat(56) */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 56/
{
    entries++;
    this->o0 = *(uint64_t *)copyin(arg2, 8);
    this->o1 = *(uint64_t *)copyin(arg2 + 8, 8);
    this->o2 = *(uint64_t *)copyin(arg2 + 16, 8);
    printf("SPL8|entry|pid=%d|nr=%d|name=%s|dfd=%d|path=0x%llx|flags=0x%llx\n",
        pid, (int)arg0, copyinstr(arg1),
        (int)this->o0,
        (unsigned long long)this->o1,
        (unsigned long long)this->o2);
}

/* Splice: splice(76)
 * args: [fd_in, off_in, fd_out, off_out, len, flags]
 */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 76/
{
    entries++;
    splice_entries++;
    this->s0 = *(uint64_t *)copyin(arg2, 8);
    this->s1 = *(uint64_t *)copyin(arg2 + 8, 8);
    this->s2 = *(uint64_t *)copyin(arg2 + 16, 8);
    this->s3 = *(uint64_t *)copyin(arg2 + 24, 8);
    this->s4 = *(uint64_t *)copyin(arg2 + 32, 8);
    this->s5 = *(uint64_t *)copyin(arg2 + 40, 8);
    self->cur_fd_in = (int)this->s0;
    self->cur_off_in = this->s1;
    self->cur_fd_out = (int)this->s2;
    self->cur_off_out = this->s3;
    self->cur_len = this->s4;
    self->cur_flags = this->s5;
    if (this->s4 == 0) {
        splice_zero_len++;
    }
    printf("SPL8|splice-entry|pid=%d|fd_in=%d|off_in=0x%llx|fd_out=%d|off_out=0x%llx|len=%llu|flags=0x%llx\n",
        pid, (int)this->s0,
        (unsigned long long)this->s1,
        (int)this->s2,
        (unsigned long long)this->s3,
        (unsigned long long)this->s4,
        (unsigned long long)this->s5);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 56 || arg0 == 59)/
{
    returns++;
    printf("SPL8|return|pid=%d|nr=%d|name=%s|ret=%lld|errno=%d\n",
        pid, (int)arg0, copyinstr(arg1), (long long)arg2, (int)arg3);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 76/
{
    returns++;
    splice_returns++;
    if (arg3 == 22) {
        splice_einval++;
    } else if ((long long)arg2 >= 0) {
        splice_ok++;
    }
    printf("SPL8|splice-return|pid=%d|fd_in=%d|fd_out=%d|len=%llu|ret=%lld|errno=%d\n",
        pid, self->cur_fd_in, self->cur_fd_out,
        (unsigned long long)self->cur_len,
        (long long)arg2, (int)arg3);
    self->cur_fd_in = -1;
    self->cur_fd_out = -1;
    self->cur_len = 0;
}

carrick*:::host-pipe-io
/(pid == $target || progenyof($target))/
{
    host_pipe_ios++;
    printf("SPL8|host-pipe-io|pid=%d|host_fd=%d|dir=%d|n=%lld\n",
        pid, (int)arg1, (int)arg2, (long long)arg3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
}

tick-1s
{
    secs++;
}

tick-1s
/(target_exited || secs >= 20)/
{
    this->is_exact_pass = (
        target_exited == 1 &&
        secs < 20 &&
        splice_entries == 18 &&
        splice_returns == 18 &&
        splice_ok == 18 &&
        splice_zero_len == 2 &&
        splice_einval == 0
    );

    if (this->is_exact_pass) {
        printf("SPL8|receipt|target-exited=%d|timeout-bound=%d|entries=%d|returns=%d|splice_entries=%d|splice_returns=%d|splice_ok=%d|splice_einval=%d|splice_zero_len=%d|host_pipe_ios=%d|verdict=PASS\n",
            target_exited, secs >= 20, entries, returns, splice_entries, splice_returns,
            splice_ok, splice_einval, splice_zero_len, host_pipe_ios);
        exit(0);
    } else if (splice_entries == 0) {
        printf("SPL8|error=missing-splice-entries|target-exited=%d|timeout-bound=%d|entries=%d|returns=%d\n",
            target_exited, secs >= 20, entries, returns);
        exit(1);
    } else {
        printf("SPL8|receipt|target-exited=%d|timeout-bound=%d|entries=%d|returns=%d|splice_entries=%d|splice_returns=%d|splice_ok=%d|splice_einval=%d|splice_zero_len=%d|host_pipe_ios=%d|verdict=FAIL\n",
            target_exited, secs >= 20, entries, returns, splice_entries, splice_returns,
            splice_ok, splice_einval, splice_zero_len, host_pipe_ios);
        exit(1);
    }
}
