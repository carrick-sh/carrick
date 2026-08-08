#pragma D option quiet
#pragma D option dynvarsize=128m
#pragma D option bufsize=32m
#pragma D option aggsize=128m
#pragma D option ustackframes=64
#pragma D option strsize=16k

/*
 * Attribute Darwin openat calls made while Carrick's translated or direct
 * native lane services Linux/AArch64 openat (guest syscall 56) to exact host
 * user stacks.
 *
 * Unlike an arbitrary native-DSR profile sample, syscall entry/return happens
 * after Carrick has restored its host stack. The resulting ustack is therefore
 * authoritative for the Carrick caller. Every aggregation key also carries
 * the contemporaneous Carrick image base so short-lived, self-reexec'd guest
 * processes can be symbolicated offline after they exit. Tier D publishes
 * that shared `host-image-base` ABI immediately before its first guest entry;
 * a capture with host openat events but only base=0 is an instrumentation
 * error, not symbolication evidence.
 */

dtrace:::BEGIN
{
	seconds = 0;
	tracked[$target] = 1;
	host_base[$target] = (uint64_t)0;
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
	host_base[args[0]->pr_pid] = (uint64_t)host_base[pid];
}

proc:::exit
/tracked[pid] && pid != $target/
{
	tracked[pid] = 0;
	host_base[pid] = (uint64_t)0;
}

proc:::exit
/pid == $target/
{
	tracked[pid] = 0;
	exit(0);
}

carrick*:::host-image-base
/tracked[pid]/
{
	host_base[arg0] = (uint64_t)arg1;
	@host_base[arg0, arg1] = count();
}

carrick*:::native-syscall-service-entry
/tracked[pid]/
{
	service_openat[pid, tid] = arg0 == 56;
	@guest_service[arg0, copyinstr(arg1)] = count();
}

carrick*:::native-syscall-service-end
/tracked[pid]/
{
	service_openat[pid, tid] = 0;
}

syscall::openat:entry
/tracked[pid] && service_openat[pid, tid]/
{
	self->open_started = timestamp;
	self->open_base = (uint64_t)host_base[pid];
	@open_count = count();
	@open_by_pid_base[pid, self->open_base] = count();
	@open_entry_stack[self->open_base, ustack(64)] = count();
}

syscall::openat:return
/tracked[pid] && self->open_started != 0/
{
	this->duration = timestamp - self->open_started;
	@open_ns = sum(this->duration);
	@open_max_ns = max(this->duration);
	@open_hist_us = quantize(this->duration / 1000);
	@open_return_stack_ns[self->open_base, ustack(64)] =
	    sum(this->duration);
	self->open_started = 0;
	self->open_base = 0;
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
	printf("OPENSTACK1|section=totals\n");
	printa("OPENSTACK1|host=openat|count=%@d\n", @open_count);
	printa("OPENSTACK1|host=openat|duration-ns=%@d\n", @open_ns);
	printa("OPENSTACK1|host=openat|max-ns=%@d\n", @open_max_ns);
	printa("OPENSTACK1|pid=%d|base=0x%x|count=%@d\n",
	    @open_by_pid_base);
	printa("OPENSTACK1|host-base|pid=%d|base=0x%x|count=%@d\n",
	    @host_base);

	printf("OPENSTACK1|section=histogram-us\n");
	printa("OPENSTACK1|host=openat\n%@d\n", @open_hist_us);

	trunc(@open_entry_stack, 128);
	printf("OPENSTACK1|section=entry-count-stacks\n");
	printa("OPENSTACK1|begin|class=entry-count|base=0x%x|value=%@d\n%kOPENSTACK1|end\n",
	    @open_entry_stack);

	trunc(@open_return_stack_ns, 128);
	printf("OPENSTACK1|section=return-duration-stacks\n");
	printa("OPENSTACK1|begin|class=return-duration|base=0x%x|value-ns=%@d\n%kOPENSTACK1|end\n",
	    @open_return_stack_ns);
}
