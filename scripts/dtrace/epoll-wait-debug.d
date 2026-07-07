/*
 * Focused epoll/kqueue wait tracing for Carrick.
 *
 * This intentionally avoids the full syscall stream and prints only epoll
 * wait decisions plus masked-ready interest samples. Use through:
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

tick-1s
{
    printf("\n========= epoll tick %Y =========\n", walltimestamp);
    printf("--- result kinds ---\n");
    printa("  kind=%-4d %@d\n", @results);
    printf("--- wait fds ---\n");
    printa("  events=%#x timeout=%-8d %@d\n", @wait_fds);
    printf("--- masked interest samples ---\n");
    printa("  requested=%#x raw=%#x last=%#x %@d\n", @masked);
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
}
