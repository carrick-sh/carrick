/*
 * Trace HVPatch pipe-end authority and access-mode direction enforcement.
 *
 * Captures guest pipe creation and read/write-family operations, correlating
 * entry arguments, return values, errno codes, and host-pipe-io events under
 * HVPatch unified-kernel execution.
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
 *   Requires at least one write(2) returning EBADF (errno 9) and at least one
 *   read(2) returning EBADF (errno 9) on the wrong pipe ends before target exit
 *   or the 20-second timeout bound. Missing either counter exits with status 1
 *   and named error receipts.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=4m

dtrace:::BEGIN
{
    secs = 0;
    entries = 0;
    returns = 0;
    write_ebadf = 0;
    read_ebadf = 0;
    host_pipe_ios = 0;
    printf("PEA1|begin|wall=%Y\n", walltimestamp);
}

/* Pipe creation: pipe2(59) */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 59/
{
    entries++;
    this->args = (uint64_t *)copyin(arg2, 48);
    printf("PEA1|entry|pid=%d|nr=%d|name=%s|pipefd_ptr=0x%llx|flags=0x%llx\n",
        pid, (int)arg0, copyinstr(arg1),
        (unsigned long long)this->args[0],
        (unsigned long long)this->args[1]);
}

/* Read and write family scalar and vectored syscalls on AArch64:
 *   63=read, 64=write, 65=readv, 66=writev, 67=pread64, 68=pwrite64,
 *   69=preadv, 70=pwritev, 75=vmsplice, 76=splice, 77=tee
 */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 63 || arg0 == 64 || arg0 == 65 || arg0 == 66 ||
     arg0 == 67 || arg0 == 68 || arg0 == 69 || arg0 == 70 ||
     arg0 == 75 || arg0 == 76 || arg0 == 77)/
{
    entries++;
    this->args = (uint64_t *)copyin(arg2, 48);
    self->cur_fd = (int)this->args[0];
    self->cur_nr = (int)arg0;
    printf("PEA1|entry|pid=%d|nr=%d|name=%s|fd=%d|arg1=0x%llx|arg2=%llu\n",
        pid, (int)arg0, copyinstr(arg1), (int)this->args[0],
        (unsigned long long)this->args[1],
        (unsigned long long)this->args[2]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 59 || arg0 == 63 || arg0 == 64 || arg0 == 65 || arg0 == 66 ||
     arg0 == 67 || arg0 == 68 || arg0 == 69 || arg0 == 70 ||
     arg0 == 75 || arg0 == 76 || arg0 == 77)/
{
    returns++;
    if (arg0 == 64 && arg3 == 9) {
        write_ebadf++;
    }
    if (arg0 == 63 && arg3 == 9) {
        read_ebadf++;
    }
    printf("PEA1|return|pid=%d|nr=%d|name=%s|fd=%d|ret=%lld|errno=%d\n",
        pid, (int)arg0, copyinstr(arg1), self->cur_fd,
        (long long)arg2, (int)arg3);
    self->cur_fd = -1;
    self->cur_nr = 0;
}

carrick*:::host-pipe-io
/(pid == $target || progenyof($target))/
{
    host_pipe_ios++;
    printf("PEA1|host-pipe-io|pid=%d|host_fd=%d|dir=%d|n=%lld\n",
        pid, (int)arg1, (int)arg2, (long long)arg3);
}

proc:::exit
/pid == $target && write_ebadf > 0 && read_ebadf > 0/
{
    printf("PEA1|pass|entries=%d|returns=%d|write_ebadf=%d|read_ebadf=%d|host-pipe-ios=%d\n",
        entries, returns, write_ebadf, read_ebadf, host_pipe_ios);
    exit(0);
}

proc:::exit
/pid == $target && write_ebadf == 0/
{
    printf("PEA1|error=missing-write-EBADF|entries=%d|returns=%d|write_ebadf=%d|read_ebadf=%d\n",
        entries, returns, write_ebadf, read_ebadf);
    exit(1);
}

proc:::exit
/pid == $target && write_ebadf > 0 && read_ebadf == 0/
{
    printf("PEA1|error=missing-read-EBADF|entries=%d|returns=%d|write_ebadf=%d|read_ebadf=%d\n",
        entries, returns, write_ebadf, read_ebadf);
    exit(1);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 20 && write_ebadf > 0 && read_ebadf > 0/
{
    printf("PEA1|pass|timeout-bound=1|entries=%d|returns=%d|write_ebadf=%d|read_ebadf=%d|host-pipe-ios=%d\n",
        entries, returns, write_ebadf, read_ebadf, host_pipe_ios);
    exit(0);
}

tick-1s
/secs >= 20 && write_ebadf == 0/
{
    printf("PEA1|error=timeout-missing-write-EBADF|entries=%d|returns=%d|write_ebadf=%d|read_ebadf=%d\n",
        entries, returns, write_ebadf, read_ebadf);
    exit(1);
}

tick-1s
/secs >= 20 && write_ebadf > 0 && read_ebadf == 0/
{
    printf("PEA1|error=timeout-missing-read-EBADF|entries=%d|returns=%d|write_ebadf=%d|read_ebadf=%d\n",
        entries, returns, write_ebadf, read_ebadf);
    exit(1);
}
