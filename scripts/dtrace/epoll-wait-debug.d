/*
 * Focused epoll/kqueue wait tracing for Carrick.
 *
 * This intentionally avoids the full syscall stream and prints only epoll
 * wait decisions plus masked-ready interest samples. It self-exits after 20s
 * because `carrick trace -s` intentionally lets custom scripts outlive the
 * directly-spawned child; an unbounded script can otherwise leave a root trace
 * parent behind after the guest is killed. Use through:
 *
 *   carrick trace -s scripts/dtrace/epoll-wait-debug.d -- ...
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option destructive
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("carrick epoll wait trace started at %Y\n", walltimestamp);
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
    @results[(int)arg4] = count();
    printf("[%d epoll-result] epfd=%d ready=%d wait=%d timeout=%d kind=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::epoll-wait-fd
/pid == $target || progenyof($target)/
{
    @wait_fds[(int)arg3, (int)arg4] = count();
    printf("[%d epoll-wait-fd] epfd=%d fd=%d host_fd=%d events=%#x timeout=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::epoll-interest
/(pid == $target || progenyof($target)) && (int)arg5 == 0 && (uint32_t)arg3 != 0/
{
    @masked[(uint32_t)arg2, (uint32_t)arg3, (uint32_t)arg4] = count();
    printf("[%d epoll-masked] epfd=%d fd=%d requested=%#x raw=%#x last=%#x ready=0\n",
        pid, (int)arg0, (int)arg1, (uint32_t)arg2, (uint32_t)arg3, (uint32_t)arg4);
}

carrick*:::epoll-masked
/(pid == $target || progenyof($target))/
{
    this->m = (uint64_t *)copyin(arg0, 64);
    @masked_origin[(int)this->m[0], (uint32_t)this->m[3], (uint32_t)this->m[4], (uint32_t)this->m[5]] = count();
    @masked_avail[(int)this->m[0], (uint32_t)this->m[4], (uint64_t)this->m[6], (uint64_t)this->m[7]] = count();
    printf("[%d epoll-masked-origin] fd=%d host_fd=%d requested=%#x raw=%#x last=%#x read_avail=%d last_read_avail=%d origin=%d\n",
        pid, (int)this->m[1], (int)this->m[2], (uint32_t)this->m[3], (uint32_t)this->m[4], (uint32_t)this->m[5], (int)this->m[6], (int)this->m[7], (int)this->m[0]);
}

carrick*:::epoll-rebind
/(pid == $target || progenyof($target))/
{
    this->r = (uint64_t *)copyin(arg0, 48);
    @rebind[(int)this->r[0], (uint32_t)this->r[4], (uint32_t)this->r[5]] = count();
    printf("[%d epoll-rebind] reason=%d host_fd=%d survivor=%d gen=%d union=%#x effective=%#x\n",
        pid, (int)this->r[0], (int)this->r[1], (int)this->r[2], (int)this->r[3], (uint32_t)this->r[4], (uint32_t)this->r[5]);
}

carrick*:::io-wait-begin
/(pid == $target || progenyof($target))/
{
    @io_wait_begin[(int)arg1, (int)arg3, (int)arg4] = count();
    printf("[%d io-wait-begin] tid=%d fds=%d timeout=%d fd0=%d events0=%#x fd1=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::io-wait-end
/(pid == $target || progenyof($target))/
{
    @io_wait_end[(int)arg1, (int)arg2, (int)arg3] = count();
    printf("[%d io-wait-end] tid=%d result=%d fds=%d fd0=%d fd1=%d fd2=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

tick-1s
{
    printf("\n========= epoll tick %Y =========\n", walltimestamp);
    printf("--- result kinds ---\n");
    printa("  kind=%-4d %@d\n", @results);
    printf("--- wait fds ---\n");
    printa("  events=%#x timeout=%-8d %@d\n", @wait_fds);
    printf("--- masked interest samples ---\n");
    printa("  requested=%#x raw=%#x last=%#x %@d\n", @masked);
    printf("--- masked origins ---\n");
    printa("  origin=%-2d requested=%#x raw=%#x last=%#x %@d\n", @masked_origin);
    printf("--- masked read availability ---\n");
    printa("  origin=%-2d raw=%#x read_avail=%-6d last_read_avail=%-6d %@d\n", @masked_avail);
    printf("--- rebinds ---\n");
    printa("  reason=%-2d union=%#x effective=%#x %@d\n", @rebind);
    printf("--- io wait begin ---\n");
    printa("  fds=%-3d fd0=%-8d events0=%#x %@d\n", @io_wait_begin);
    printf("--- io wait end ---\n");
    printa("  result=%-3d fds=%-3d fd0=%-8d %@d\n", @io_wait_end);
}

tick-20s
{
    exit(0);
}

dtrace:::END
{
    printf("\n=================== epoll wait aggregations ===================\n");
    printf("--- result kinds ---\n");
    printa("  kind=%-4d %@d\n", @results);
    printf("--- wait fds ---\n");
    printa("  events=%#x timeout=%-8d %@d\n", @wait_fds);
    printf("--- masked interest samples ---\n");
    printa("  requested=%#x raw=%#x last=%#x %@d\n", @masked);
    printf("--- masked origins ---\n");
    printa("  origin=%-2d requested=%#x raw=%#x last=%#x %@d\n", @masked_origin);
    printf("--- masked read availability ---\n");
    printa("  origin=%-2d raw=%#x read_avail=%-6d last_read_avail=%-6d %@d\n", @masked_avail);
    printf("--- rebinds ---\n");
    printa("  reason=%-2d union=%#x effective=%#x %@d\n", @rebind);
    printf("--- io wait begin ---\n");
    printa("  fds=%-3d fd0=%-8d events0=%#x %@d\n", @io_wait_begin);
    printf("--- io wait end ---\n");
    printa("  result=%-3d fds=%-3d fd0=%-8d %@d\n", @io_wait_end);
}
