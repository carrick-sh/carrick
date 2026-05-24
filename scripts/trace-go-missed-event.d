/*
 * Minimal Carrick/Go missed-event trace.
 *
 * Intentionally avoids broad syscall-entry/return probes so the traced
 * workload stays close to the untraced timing. Focuses only on the Carrick
 * USDT probes that matter for the residual Go c50 stall:
 *   - epoll_ctl registration
 *   - epoll wait handoff / result
 *   - thread-directed signal publish / deliver / inject
 *   - io_wait completion shape
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{
	printf("go-missed-event trace started at %Y\n", walltimestamp);
}

carrick*:::epoll-ctl
/pid == $target || progenyof($target)/
{
	@epoll_ctl[(int)arg0, (int)arg1, (int)arg2, (uint32_t)arg3] = count();
}

carrick*:::epoll-wait-fd
/pid == $target || progenyof($target)/
{
	@epoll_wait_fd[(int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4] = count();
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
	@epoll_result[(int)arg1, (int)arg2, (int)arg3, (int)arg4] = count();
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
	@io_wait_end[(int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5] = count();
}

carrick*:::signal-publish
/(pid == $target || progenyof($target)) && (int)arg1 == 23/
{
	@sigurg_publish[(int)arg0, (int)arg2] = count();
}

carrick*:::signal-deliver
/(pid == $target || progenyof($target)) && (int)arg1 == 23/
{
	@sigurg_deliver[(int)arg0] = count();
}

carrick*:::signal-inject
/(pid == $target || progenyof($target)) && (int)arg0 == 23/
{
	@sigurg_inject[arg1, arg3] = count();
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= 8/
{
	exit(0);
}

dtrace:::END
{
	printf("\n==== epoll ctl ====\n");
	trunc(@epoll_ctl, 80);
	printa("epfd=%-3d op=%-2d fd=%-4d events=%#-5x %@d\n", @epoll_ctl);

	printf("\n==== epoll wait handoff ====\n");
	printa("epfd=%-3d guest_fd=%-3d host_fd=%-6d events=%#-4x timeout=%-5d %@d\n", @epoll_wait_fd);

	printf("\n==== epoll result ====\n");
	printa("ready=%-3d wait=%-3d timeout=%-5d kind=%-2d %@d\n", @epoll_result);

	printf("\n==== io wait end ====\n");
	printa("tid=%-6d result=%-2d count=%-2d fd0=%-5d fd1=%-5d fd2=%-5d %@d\n", @io_wait_end);

	printf("\n==== SIGURG publish ====\n");
	printa("target=%-6d kind=%-2d %@d\n", @sigurg_publish);

	printf("\n==== SIGURG deliver ====\n");
	printa("tid=%-6d %@d\n", @sigurg_deliver);

	printf("\n==== SIGURG inject ====\n");
	trunc(@sigurg_inject, 80);
	printa("saved_pc=%#-14x handler=%#-14x %@d\n", @sigurg_inject);
}
