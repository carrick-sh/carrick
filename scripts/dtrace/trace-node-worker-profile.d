/*
 * Bounded profile for Node worker_threads shutdown hangs. Runs long enough for
 * the worker to post a message and exit, then samples the residual live Carrick
 * task to show whether it is spinning, parked in futex/io wait, or repeatedly
 * taking scheduler/thread syscalls.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=64m
#pragma D option aggsize=64m

dtrace:::BEGIN
{
    printf("node-worker profile started at %Y\n", walltimestamp);
}

profile-997
/pid == $target || progenyof($target)/
{
    @hoststack[pid, ustack(16)] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 22 || arg0 == 23 || arg0 == 63 || arg0 == 64 || arg0 == 73 ||
  arg0 == 93 || arg0 == 94 || arg0 == 96 || arg0 == 98 || arg0 == 99 ||
  arg0 == 120 || arg0 == 121 || arg0 == 124 || arg0 == 131 ||
  arg0 == 172 || arg0 == 178 || arg0 == 220 || arg0 == 275 || arg0 == 435)/
{
    @entry[copyinstr(arg1)] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 22 || arg0 == 23 || arg0 == 63 || arg0 == 64 || arg0 == 73 ||
  arg0 == 93 || arg0 == 94 || arg0 == 96 || arg0 == 98 || arg0 == 99 ||
  arg0 == 120 || arg0 == 121 || arg0 == 124 || arg0 == 131 ||
  arg0 == 172 || arg0 == 178 || arg0 == 220 || arg0 == 275 || arg0 == 435)/
{
    @ret[arg0, (int)arg2, (int)arg3] = count();
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
    @wait_begin[(int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5] = count();
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
    @wait_end[(int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5] = count();
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
    @epoll_result[(int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4] = count();
}

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    @futex_route[(int)arg1, (int)arg2, (int)arg3] = count();
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d] guest-exit code=%d\n", pid, (int)arg1);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 30/
{
    exit(0);
}

dtrace:::END
{
    printf("\n==== syscall entries ====\n");
    printa("  %-24s %@d\n", @entry);
    printf("\n==== syscall returns ====\n");
    printa("  nr=%-3d ret=%-6d errno=%-3d %@d\n", @ret);
    printf("\n==== io wait begin ====\n");
    printa("  tid=%-6d count=%-2d timeout=%-6d fd0=%-5d events0=%#-4x fd1=%-5d %@d\n", @wait_begin);
    printf("\n==== io wait end ====\n");
    printa("  tid=%-6d result=%-2d count=%-2d fd0=%-5d fd1=%-5d fd2=%-5d %@d\n", @wait_end);
    printf("\n==== epoll result ====\n");
    printa("  epfd=%-3d ready=%-3d wait=%-3d timeout=%-6d kind=%-2d %@d\n", @epoll_result);
    printf("\n==== futex route ====\n");
    printa("  op=%-3d shared=%-2d host=%-2d %@d\n", @futex_route);
    printf("\n==== hottest host stacks ====\n");
    trunc(@hoststack, 12);
    printa(@hoststack);
}
