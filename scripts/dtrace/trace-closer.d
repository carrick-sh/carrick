/*
 * Who closes the guest pipe read end? Probe carrick's close_open_file via the
 * pid provider (symbols are present) and dump the symbolicated user stack, so
 * we see the exact carrick call path that closes the fd — plus the raw host
 * close() for correlation.
 *
 *   carrick trace --script scripts/trace-closer.d -- run-elf <fixture>
 */

#pragma D option quiet
#pragma D option strsize=256

/* The actual host close() of a low fd, with the carrick stack. */
syscall::close:entry
/(pid == $target || progenyof($target)) && arg0 >= 3 && arg0 < 16/
{
    printf("[%d] HOST close(fd=%d)\n", pid, (int)arg0);
    ustack(12);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    printf("[%d] host-pipe-io host_fd=%d dir=%d n=%d\n",
        pid, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] === fork-post child=%d ===\n", pid, (int)arg0);
}
