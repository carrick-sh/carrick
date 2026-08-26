/*
 * Identify the exact Linux syscall that returns ENOSYS during CPython's
 * test_cgi.CgiTests.test_log cleanup on HVPatch.
 *
 * Provider ABI qualified against this tree's carrick USDT declarations and
 * the live `carrick trace` contract on 2026-08-26:
 *   syscall-entry(arg0=Linux nr, arg1=name, arg2=host SyscallArgs pointer)
 *   syscall-return(arg0=Linux nr, arg1=name, arg2=signed retval, arg3=errno)
 *   unhandled-syscall(arg0=Linux nr, arg1=name, arg2=host SyscallArgs pointer)
 * `$target` is the carrick process spawned by libdtrace; HVPatch keeps the
 * logical guest tasks in that carrier. `progenyof` remains included so the
 * script stays correct if launch topology changes.
 *
 * Correctness-only, not performance evidence. This prints only ENOSYS returns
 * and unhandled-write events, but any USDT tracing perturbs scheduling. The
 * terminal CGE1 receipt fails closed on zero syscall returns, zero write
 * ENOSYS returns, or zero unhandled-write events; unrelated permitted ENOSYS
 * calls such as rseq cannot satisfy it. The 30-second tick is a hard bound.
 *
 * Source-88286d1b capture (binary SHA-256 e7612539...) reproduced test_cgi
 * 22/23 and reported two 28-byte writes to fd 3 as both unhandled and ENOSYS;
 * the tightened capture and its CGE1 pass receipt were accepted by the wrapper.
 * Use this only for correctness localization, never timing.
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    secs = 0;
    returns = 0;
    write_enosys = 0;
    other_enosys = 0;
    unhandled_write = 0;
    printf("CGE1|begin\n");
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 64/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    self->write_fd = this->args[0];
    self->write_len = this->args[2];
}

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{
    returns++;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 64 && (int)arg3 == 38/
{
    write_enosys++;
    printf("CGE1|write-enosys|pid=%d|fd=%d|len=%d|ret=%d|errno=%d\n",
        pid, (int)self->write_fd, (int)self->write_len,
        (int)arg2, (int)arg3);
    self->write_fd = 0;
    self->write_len = 0;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 != 64 && (int)arg3 == 38/
{
    other_enosys++;
    printf("CGE1|other-enosys|pid=%d|nr=%d|name=%s|ret=%d|errno=%d\n",
        pid, (int)arg0, copyinstr(arg1), (int)arg2, (int)arg3);
}

carrick*:::unhandled-syscall
/(pid == $target || progenyof($target)) && arg0 == 64/
{
    unhandled_write++;
    printf("CGE1|unhandled-write|pid=%d|nr=%d|name=%s\n",
        pid, (int)arg0, copyinstr(arg1));
}

proc:::exit
/pid == $target && returns > 0 && write_enosys > 0 && unhandled_write > 0/
{
    printf("CGE1|pass|returns=%d|write-enosys=%d|unhandled-write=%d|other-enosys=%d\n",
        returns, write_enosys, unhandled_write, other_enosys);
    exit(0);
}

proc:::exit
/pid == $target && returns == 0/
{
    printf("CGE1|error=no-syscall-return|write-enosys=%d|unhandled-write=%d\n",
        write_enosys, unhandled_write);
    exit(1);
}

proc:::exit
/pid == $target && returns > 0 && (write_enosys == 0 || unhandled_write == 0)/
{
    printf("CGE1|error=missing-write-enosys|returns=%d|write-enosys=%d|unhandled-write=%d|other-enosys=%d\n",
        returns, write_enosys, unhandled_write, other_enosys);
    exit(2);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 30 && returns > 0 && write_enosys > 0 && unhandled_write > 0/
{
    printf("CGE1|pass|timeout-bound=1|returns=%d|write-enosys=%d|unhandled-write=%d|other-enosys=%d\n",
        returns, write_enosys, unhandled_write, other_enosys);
    exit(0);
}

tick-1s
/secs >= 30 && returns == 0/
{
    printf("CGE1|error=timeout-no-syscall-return|write-enosys=%d|unhandled-write=%d\n",
        write_enosys, unhandled_write);
    exit(1);
}

tick-1s
/secs >= 30 && returns > 0 && (write_enosys == 0 || unhandled_write == 0)/
{
    printf("CGE1|error=timeout-missing-write-enosys|returns=%d|write-enosys=%d|unhandled-write=%d|other-enosys=%d\n",
        returns, write_enosys, unhandled_write, other_enosys);
    exit(2);
}
