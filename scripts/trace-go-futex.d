/*
 * Focused trace for the residual high-concurrency Go stall.
 *
 * Captures futex wait/wake args and returns, plus epoll/io wait decisions.
 * Keep this bounded with a host timeout when looping; the script itself exits
 * after 7s so a wedged guest still yields END aggregations.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=64m
#pragma D option aggsize=64m

dtrace:::BEGIN
{
	printf("go-futex trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 98/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	self->faddr = this->sa[0];
	self->fop = this->sa[1];
	self->fcmd = this->sa[1] & 0x7f;
	self->fval = this->sa[2];
	@futex_entry[(int)self->fcmd] = count();
	@futex_addr[(int)self->fcmd, self->faddr] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 98/
{
	@futex_ret[(int)self->fcmd, self->faddr, (int)arg2, (int)arg3] = count();
	self->faddr = 0;
	self->fop = 0;
	self->fcmd = 0;
	self->fval = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 21 || arg0 == 22)/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	@epoll_entry[arg0] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 21 || arg0 == 22)/
{
	@epoll_ret[arg0, (int)arg2, (int)arg3] = count();
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

carrick*:::epoll-interest
/pid == $target || progenyof($target)/
{
	@epoll_interest[(int)arg0, (int)arg1, (uint32_t)arg2, (uint32_t)arg3, (uint32_t)arg5] = count();
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
/secs >= 7/
{
	exit(0);
}

dtrace:::END
{
	printf("\n==== futex entries ====\n");
	printa("cmd=%-3d %@d\n", @futex_entry);
	printf("\n==== hottest futex addresses ====\n");
	trunc(@futex_addr, 30);
	printa("cmd=%-3d addr=%#-14x %@d\n", @futex_addr);
	printf("\n==== futex returns ====\n");
	printa("cmd=%-3d addr=%#-14x ret=%-4d errno=%-3d %@d\n", @futex_ret);
	printf("\n==== epoll entries ====\n");
	printa("nr=%-3d %@d\n", @epoll_entry);
	printf("\n==== epoll returns ====\n");
	printa("nr=%-3d ret=%-4d errno=%-3d %@d\n", @epoll_ret);
	printf("\n==== epoll result decisions ====\n");
	printa("ready=%-3d wait=%-3d timeout=%-5d kind=%-2d %@d\n", @epoll_result);
	printf("\n==== epoll wait fd handoffs ====\n");
	printa("epfd=%-3d guest_fd=%-3d host_fd=%-6d events=%#-4x timeout=%-5d %@d\n", @epoll_wait_fd);
	printf("\n==== epoll interest checks ====\n");
	trunc(@epoll_interest, 80);
	printa("epfd=%-3d guest_fd=%-3d req=%#-5x raw=%#-5x ready=%#-5x %@d\n", @epoll_interest);
	printf("\n==== io wait begin ====\n");
	printa("count=%-2d timeout=%-5d fd0=%-4d events0=%#-4x fd1=%-4d %@d\n", @wait_begin);
	printf("\n==== io wait end ====\n");
	printa("result=%-2d count=%-2d fd0=%-4d fd1=%-4d fd2=%-4d %@d\n", @wait_end);
}
