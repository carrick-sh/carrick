/*
 * Focused trace for high-concurrency Go HTTP stalls.
 *
 * Aggregates network, epoll, futex, read/write, and timer-ish syscall returns
 * without printing every syscall. Intended for failing -benchmark -c 50 runs.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=64m
#pragma D option aggsize=64m

dtrace:::BEGIN
{
	printf("go-net trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 21 || arg0 == 22 || arg0 == 63 || arg0 == 64 || arg0 == 73 ||
  arg0 == 98 || arg0 == 198 || arg0 == 202 || arg0 == 203 || arg0 == 206 ||
  arg0 == 207 || arg0 == 242)/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	self->nr = arg0;
	self->fd = (int)this->sa[0];
	@entry[arg0] = count();
	@fd_entry[arg0, self->fd] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 21 || arg0 == 22 || arg0 == 63 || arg0 == 64 || arg0 == 73 ||
  arg0 == 98 || arg0 == 198 || arg0 == 202 || arg0 == 203 || arg0 == 206 ||
  arg0 == 207 || arg0 == 242)/
{
	@return[arg0, (int)arg2, (int)arg3] = count();
	@fd_return[arg0, self->fd, (int)arg2, (int)arg3] = count();
	self->nr = 0;
	self->fd = 0;
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
	@epoll_result[(int)arg1, (int)arg2, (int)arg3, (int)arg4] = count();
}

carrick*:::epoll-wait-fd
/pid == $target || progenyof($target)/
{
	@epoll_wait_fd[(int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4] = count();
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
	@wait_begin[(int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5] = count();
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
	@wait_end[(int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5] = count();
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
	printf("\n==== syscall entries ====\n");
	printa("nr=%-3d %@d\n", @entry);
	printf("\n==== fd entries ====\n");
	trunc(@fd_entry, 80);
	printa("nr=%-3d fd=%-5d %@d\n", @fd_entry);
	printf("\n==== returns ====\n");
	printa("nr=%-3d ret=%-6d errno=%-3d %@d\n", @return);
	printf("\n==== fd returns ====\n");
	printa("nr=%-3d fd=%-5d ret=%-6d errno=%-3d %@d\n", @fd_return);
	printf("\n==== epoll results ====\n");
	printa("ready=%-3d wait=%-3d timeout=%-5d kind=%-2d %@d\n", @epoll_result);
	printf("\n==== epoll wait fd ====\n");
	printa("epfd=%-3d guest_fd=%-3d host_fd=%-6d events=%#-4x timeout=%-5d %@d\n", @epoll_wait_fd);
	printf("\n==== waits begin ====\n");
	printa("count=%-2d timeout=%-5d fd0=%-5d events0=%#-4x fd1=%-5d %@d\n", @wait_begin);
	printf("\n==== waits end ====\n");
	printa("result=%-2d count=%-2d fd0=%-5d fd1=%-5d fd2=%-5d %@d\n", @wait_end);
}
