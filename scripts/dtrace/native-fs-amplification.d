#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option strsize=256

/*
 * Join selected Darwin filesystem syscalls to Carrick's active guest syscall.
 *
 * The decision metric is host-call amplification, not traced elapsed time.
 * `guest=carrick-only` covers image setup, supervision, and other work outside
 * a native guest syscall-service interval.
 */

dtrace:::BEGIN
{
	seconds = 0;
	tracked[$target] = 1;
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
}

proc:::exit
/tracked[pid] && pid != $target/
{
	tracked[pid] = 0;
}

proc:::exit
/pid == $target/
{
	tracked[pid] = 0;
	exit(0);
}

carrick*:::native-syscall-service-entry
/tracked[pid]/
{
	service_active[pid, tid] = 1;
	service_name[pid, tid] = copyinstr(arg1);
	@guest_syscall[service_name[pid, tid]] = count();
}

carrick*:::native-syscall-service-end
/tracked[pid] && service_active[pid, tid]/
{
	service_active[pid, tid] = 0;
	service_name[pid, tid] = 0;
}

syscall:::entry
/tracked[pid] &&
    (probefunc == "openat" ||
    probefunc == "unlinkat" ||
    probefunc == "close" ||
    probefunc == "fstatat64" ||
    probefunc == "fcntl" ||
    probefunc == "fgetxattr" ||
    probefunc == "flistxattr" ||
    probefunc == "clonefileat" ||
    probefunc == "renameat" ||
    probefunc == "mkdirat" ||
    probefunc == "getdirentries64" ||
    probefunc == "pread" ||
    probefunc == "pwrite")/
{
	self->fs_started = timestamp;
	self->fs_host = probefunc;
	self->fs_guest = service_active[pid, tid] ?
	    service_name[pid, tid] : "carrick-only";
	@host_by_guest[self->fs_host, self->fs_guest] = count();
}

syscall:::return
/tracked[pid] && self->fs_started != 0/
{
	this->duration = timestamp - self->fs_started;
	@host_ns_by_guest[self->fs_host, self->fs_guest] =
	    sum(this->duration);
	@host_max_ns_by_guest[self->fs_host, self->fs_guest] =
	    max(this->duration);
	self->fs_started = 0;
	self->fs_host = 0;
	self->fs_guest = 0;
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 45/
{
	exit(0);
}

dtrace:::END
{
	printf("FSAMP1|section=guest-syscalls\n");
	printa("FSAMP1|guest=%s|count=%@d\n", @guest_syscall);

	printf("FSAMP1|section=host-by-guest\n");
	printa("FSAMP1|host=%s|guest=%s|count=%@d\n", @host_by_guest);

	printf("FSAMP1|section=host-duration-by-guest\n");
	printa("FSAMP1|host=%s|guest=%s|duration-ns=%@d\n",
	    @host_ns_by_guest);
	printa("FSAMP1|host=%s|guest=%s|max-ns=%@d\n",
	    @host_max_ns_by_guest);
}
