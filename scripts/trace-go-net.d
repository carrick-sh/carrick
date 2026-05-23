#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
	printf("go-net trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 21 || arg0 == 22 || arg0 == 57 || arg0 == 63 || arg0 == 64 ||
     arg0 == 198 || arg0 == 200 || arg0 == 201 || arg0 == 203 ||
     arg0 == 204 || arg0 == 205 || arg0 == 208 || arg0 == 209 ||
     arg0 == 242)/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	printf("[%d g-ent] %-14s nr=%-3d args=[%#x,%#x,%#x,%#x,%#x,%#x]\n",
	    pid, copyinstr(arg1), arg0,
	    this->sa[0], this->sa[1], this->sa[2],
	    this->sa[3], this->sa[4], this->sa[5]);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 21/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	printf("[%d epctl-ent] op=%d fd=%d event_addr=%#x\n",
	    pid, (int)this->sa[1], (int)this->sa[2], this->sa[3]);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 22/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	self->epoll_events_addr = this->sa[1];
	self->epoll_maxevents = this->sa[2];
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 21 || arg0 == 22 || arg0 == 57 || arg0 == 63 || arg0 == 64 ||
     arg0 == 198 || arg0 == 200 || arg0 == 201 || arg0 == 203 ||
     arg0 == 204 || arg0 == 205 || arg0 == 208 || arg0 == 209 ||
     arg0 == 242)/
{
	printf("[%d g-ret] %-14s nr=%-3d ret=%d errno=%d\n",
	    pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
	@guest_ret[copyinstr(arg1), (int)arg2, (int)arg3] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 22 && arg2 > 0 && self->epoll_events_addr != 0/
{
	this->ev = (uint64_t *)copyin(self->epoll_events_addr, 16);
	printf("[%d epout] n=%d event0.events=%#x event0.data=%#x\n",
	    pid, (int)arg2, (uint32_t)(this->ev[0] & 0xffffffff), this->ev[1]);
}

carrick*:::epoll-ctl
/pid == $target || progenyof($target)/
{
	printf("[%d epctl] epfd=%d op=%d fd=%d events=%#x data=%#x errno=%d\n",
	    pid, (int)arg0, (int)arg1, (int)arg2, (uint32_t)arg3, arg4, (int)arg5);
}

carrick*:::epoll-interest
/pid == $target || progenyof($target)/
{
	printf("[%d epint] epfd=%d fd=%d req=%#x raw=%#x last=%#x ready=%#x\n",
	    pid, (int)arg0, (int)arg1, (uint32_t)arg2, (uint32_t)arg3,
	    (uint32_t)arg4, (uint32_t)arg5);
}

carrick*:::epoll-wait-fd
/pid == $target || progenyof($target)/
{
	printf("[%d epwfd] epfd=%d fd=%d host_fd=%d poll_events=%#x timeout=%d\n",
	    pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
	printf("[%d epres] epfd=%d ready_count=%d wait_count=%d timeout=%d kind=%d\n",
	    pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
	printf("[%d waitb] tid=%d count=%d timeout_ms=%d fd0=%d events0=%#x fd1=%d\n",
	    pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
	printf("[%d waite] tid=%d result=%d count=%d fd0=%d fd1=%d fd2=%d\n",
	    pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
	printf("[%d hp-io] host_fd=%d dir=%d n=%d\n",
	    pid, (int)arg1, (int)arg2, (int)arg3);
	@host_pipe_io[(int)arg1, (int)arg2, (int)arg3] = count();
}

syscall::read:entry, syscall::read_nocancel:entry,
syscall::write:entry, syscall::write_nocancel:entry
/(pid == $target || progenyof($target)) && arg0 < 64/
{
	self->io_fd = (int)arg0;
	self->io_len = (int)arg2;
}

syscall::read:return, syscall::read_nocancel:return,
syscall::write:return, syscall::write_nocancel:return
/(pid == $target || progenyof($target)) && self->io_fd < 64/
{
	printf("[%d h-io ] %s(fd=%d,len=%d) ret=%d errno=%d\n",
	    pid, probefunc, self->io_fd, self->io_len, (int)arg1, errno);
	@host_io[probefunc, self->io_fd, (int)arg1, errno] = count();
	self->io_fd = 0;
	self->io_len = 0;
}

syscall::socket:return,
syscall::accept:return,
syscall::accept_nocancel:return
/pid == $target || progenyof($target)/
{
	printf("[%d h-sock] %s ret=%d errno=%d\n",
	    pid, probefunc, (int)arg1, errno);
	@host_sock_ret[probefunc, (int)arg1, errno] = count();
}

syscall::bind:entry,
syscall::listen:entry,
syscall::connect:entry,
syscall::getsockname:entry,
syscall::getpeername:entry,
syscall::shutdown:entry,
syscall::setsockopt:entry,
syscall::sendto:entry,
syscall::recvfrom:entry
/(pid == $target || progenyof($target)) && arg0 < 64/
{
	self->sock_fd = (int)arg0;
	self->sock_arg1 = (uintptr_t)arg1;
	self->sock_arg2 = (uintptr_t)arg2;
	printf("[%d h-sent] %s fd=%d arg1=%#x arg2=%#x\n",
	    pid, probefunc, self->sock_fd, self->sock_arg1, self->sock_arg2);
}

syscall::bind:entry,
syscall::connect:entry
/(pid == $target || progenyof($target)) && arg0 < 64 && arg1 != 0/
{
	this->sau8 = (uint8_t *)copyin(arg1, 28);
	printf("[%d h-saddr-ent] %s fd=%d len=%d fam=%d port=%d addr=%d.%d.%d.%d\n",
	    pid, probefunc, (int)arg0, this->sau8[0], this->sau8[1],
	    (((int)this->sau8[2] & 0xff) << 8) | ((int)this->sau8[3] & 0xff),
	    this->sau8[4], this->sau8[5], this->sau8[6], this->sau8[7]);
}

syscall::getsockname:return,
syscall::getpeername:return
/(pid == $target || progenyof($target)) && self->sock_fd < 64 && self->sock_arg1 != 0 && arg1 == 0/
{
	this->sau8 = (uint8_t *)copyin(self->sock_arg1, 28);
	printf("[%d h-saddr-ret] %s fd=%d len=%d fam=%d port=%d addr=%d.%d.%d.%d\n",
	    pid, probefunc, self->sock_fd, this->sau8[0], this->sau8[1],
	    (((int)this->sau8[2] & 0xff) << 8) | ((int)this->sau8[3] & 0xff),
	    this->sau8[4], this->sau8[5], this->sau8[6], this->sau8[7]);
}

syscall::bind:return,
syscall::listen:return,
syscall::connect:return,
syscall::getsockname:return,
syscall::getpeername:return,
syscall::shutdown:return,
syscall::setsockopt:return,
syscall::sendto:return,
syscall::recvfrom:return
/(pid == $target || progenyof($target)) && self->sock_fd < 64/
{
	printf("[%d h-sret] %s fd=%d ret=%d errno=%d\n",
	    pid, probefunc, self->sock_fd, (int)arg1, errno);
	@host_sock_call[probefunc, self->sock_fd, (int)arg1, errno] = count();
	self->sock_fd = 0;
	self->sock_arg1 = 0;
	self->sock_arg2 = 0;
}

syscall::fcntl:entry
/(pid == $target || progenyof($target)) && arg0 < 64/
{
	self->fcntl_fd = (int)arg0;
	self->fcntl_cmd = (int)arg1;
	self->fcntl_arg = (uintptr_t)arg2;
	printf("[%d h-fcnt] entry fd=%d cmd=%d arg=%#x\n",
	    pid, self->fcntl_fd, self->fcntl_cmd, self->fcntl_arg);
}

syscall::fcntl:return
/(pid == $target || progenyof($target)) && self->fcntl_fd < 64/
{
	printf("[%d h-fcnt] return fd=%d cmd=%d ret=%d errno=%d\n",
	    pid, self->fcntl_fd, self->fcntl_cmd, (int)arg1, errno);
	@host_fcntl[self->fcntl_fd, self->fcntl_cmd, (int)arg1, errno] = count();
	self->fcntl_fd = 0;
	self->fcntl_cmd = 0;
	self->fcntl_arg = 0;
}

syscall::close:entry
/(pid == $target || progenyof($target)) && arg0 < 64/
{
	self->close_fd = (int)arg0;
	printf("[%d h-clo] entry fd=%d\n", pid, self->close_fd);
}

syscall::close:return
/(pid == $target || progenyof($target)) && self->close_fd < 64/
{
	printf("[%d h-clo] return fd=%d ret=%d errno=%d\n",
	    pid, self->close_fd, (int)arg1, errno);
	@host_close[self->close_fd, (int)arg1, errno] = count();
	self->close_fd = 0;
}

syscall::poll:entry, syscall::poll_nocancel:entry
/pid == $target || progenyof($target)/
{
	self->poll_addr = (uintptr_t)arg0;
	self->poll_nfds = (int)arg1;
	self->poll_timeout = (int)arg2;
}

syscall::poll:return, syscall::poll_nocancel:return
/pid == $target || progenyof($target)/
{
	printf("[%d h-pol] %s(nfds=%d,timeout=%d) ret=%d errno=%d\n",
	    pid, probefunc, self->poll_nfds, self->poll_timeout, (int)arg1, errno);
	@host_poll[probefunc, self->poll_nfds, self->poll_timeout, (int)arg1, errno] = count();
}

syscall::poll:return, syscall::poll_nocancel:return
/(pid == $target || progenyof($target)) && self->poll_addr != 0 && self->poll_nfds == 1/
{
	this->pfd = (int *)copyin(self->poll_addr, 8);
	printf("[%d h-pfd] fd=%d events=%#x revents=%#x\n",
	    pid, this->pfd[0], (uint16_t)(this->pfd[1] & 0xffff),
	    (uint16_t)((this->pfd[1] >> 16) & 0xffff));
}

syscall::kevent:entry
/pid == $target || progenyof($target)/
{
	self->kevent_kq = (int)arg0;
	self->kevent_changelist = (uintptr_t)arg1;
	self->kevent_nchanges = (int)arg2;
	self->kevent_eventlist = (uintptr_t)arg3;
	self->kevent_nevents = (int)arg4;
	self->kevent_timeout = (uintptr_t)arg5;
	printf("[%d h-kev] entry tid=%d kq=%d nchanges=%d nevents=%d timeout_ptr=%#x\n",
	    pid, tid, self->kevent_kq, self->kevent_nchanges,
	    self->kevent_nevents, self->kevent_timeout);
}

syscall::kevent:entry
/(pid == $target || progenyof($target)) && self->kevent_changelist != 0 && self->kevent_nchanges > 0/
{
	this->kev = (uintptr_t *)copyin(self->kevent_changelist, 32);
	printf("[%d h-kch] tid=%d change0 ident=%#x word1=%#x data=%#x\n",
	    pid, tid, this->kev[0], this->kev[1], this->kev[2]);
}

syscall::kevent:entry
/(pid == $target || progenyof($target)) && self->kevent_changelist != 0 && self->kevent_nchanges > 1/
{
	this->kev = (uintptr_t *)copyin(self->kevent_changelist + 32, 32);
	printf("[%d h-kch] tid=%d change1 ident=%#x word1=%#x data=%#x\n",
	    pid, tid, this->kev[0], this->kev[1], this->kev[2]);
}

syscall::kevent:return
/pid == $target || progenyof($target)/
{
	printf("[%d h-kev] return tid=%d kq=%d nchanges=%d nevents=%d ret=%d errno=%d\n",
	    pid, tid, self->kevent_kq, self->kevent_nchanges,
	    self->kevent_nevents, (int)arg1, errno);
}

syscall::kevent:return
/(pid == $target || progenyof($target)) && arg1 > 0 && self->kevent_eventlist != 0/
{
	this->kev = (uintptr_t *)copyin(self->kevent_eventlist, 32);
	printf("[%d h-keo] tid=%d event0 ident=%#x word1=%#x data=%#x\n",
	    pid, tid, this->kev[0], this->kev[1], this->kev[2]);
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
	printf("\n--- guest returns ---\n");
	printa("GRET name=%s ret=%d errno=%d count=%@d\n", @guest_ret);
	printf("\n--- host pipe io ---\n");
	printa("HPIO host_fd=%d dir=%d n=%d count=%@d\n", @host_pipe_io);
	printf("\n--- host io ---\n");
	printa("HIO func=%s fd=%d ret=%d errno=%d count=%@d\n", @host_io);
	printf("\n--- host socket returns ---\n");
	printa("HSOCK func=%s ret=%d errno=%d count=%@d\n", @host_sock_ret);
	printf("\n--- host socket calls ---\n");
	printa("HSCALL func=%s fd=%d ret=%d errno=%d count=%@d\n", @host_sock_call);
	printf("\n--- host fcntl ---\n");
	printa("HFCNTL fd=%d cmd=%d ret=%d errno=%d count=%@d\n", @host_fcntl);
	printf("\n--- host close ---\n");
	printa("HCLOSE fd=%d ret=%d errno=%d count=%@d\n", @host_close);
	printf("\n--- host poll ---\n");
	printa("HPOLL func=%s nfds=%d timeout=%d ret=%d errno=%d count=%@d\n", @host_poll);
}
