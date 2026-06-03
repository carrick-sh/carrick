/*
 * Prove (a) whether carrick's RLIMIT_NOFILE raise + self-pipe F_DUPFD_CLOEXEC
 * relocation actually engage, and (b) who closes the guest pipe's read end.
 *
 *   carrick trace --script scripts/trace-relocation.d -- run-elf <fixture>
 */

#pragma D option quiet
#pragma D option strsize=256

/* rlimit raise: did setrlimit succeed and to what? */
syscall::setrlimit:entry
/pid == $target || progenyof($target)/
{
    printf("[%d HOST] setrlimit(resource=%d) cur(via rlimit ptr) ...\n", pid, (int)arg0);
}
syscall::setrlimit:return
/pid == $target || progenyof($target)/
{
    printf("[%d HOST]   setrlimit -> ret=%d errno=%d\n", pid, (int)arg0, errno);
}

/* F_DUPFD_CLOEXEC (cmd 67) = the self-pipe relocation. minfd is arg2. */
syscall::fcntl:entry
/(pid == $target || progenyof($target)) && arg1 == 67/
{
    self->minfd = (int)arg2;
    self->isdup = 1;
}
syscall::fcntl:return
/(pid == $target || progenyof($target)) && self->isdup/
{
    printf("[%d HOST] fcntl(F_DUPFD_CLOEXEC, minfd=%d) -> fd=%d errno=%d %s\n",
        pid, self->minfd, (int)arg1, errno,
        (int)arg1 >= 16384 ? "(RELOCATED HIGH)" : "(stayed low!)");
    self->isdup = 0;
}

/* Who closes a LOW host fd (the guest pipe range)? Show the carrick stack. */
syscall::close:entry
/(pid == $target || progenyof($target)) && arg0 >= 3 && arg0 < 16/
{
    printf("[%d HOST] close(fd=%d)\n", pid, (int)arg0);
    ustack(12);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    printf("[%d] guest host-pipe-io host_fd=%d dir=%d n=%d\n",
        pid, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] === fork-post child=%d ===\n", pid, (int)arg0);
}
