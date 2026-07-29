#pragma D option quiet
#pragma D option dynvarsize=128m
#pragma D option bufsize=32m
#pragma D option aggsize=128m
#pragma D option ustackframes=64
#pragma D option strsize=16k

/*
 * Deep host-stack attribution for Darwin native waits.
 *
 * Arbitrary native-DSR samples can carry a JIT PC and guest SP, so their
 * `ustack()` is intentionally diagnostic. Host syscall entry/return probes
 * are different: Carrick has restored its host stack before issuing the
 * Darwin syscall, making their deep user stacks authoritative for the caller.
 *
 * The whole process tree is admitted through proc:::create. The hot
 * profile predicate is therefore one associative-array lookup rather than
 * `progenyof($target)`.
 */

dtrace:::BEGIN
{
	started = timestamp;
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

proc:::create
/tracked[pid] && host_base[pid] != 0/
{
	@host_base[args[0]->pr_pid, host_base[pid]] = count();
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

carrick*:::host-image-catalog
/tracked[pid]/
{
	printf("NWIMAGES1|%s\n", copyinstr(arg0));
}

carrick*:::native-syscall-service-entry
/tracked[pid]/
{
	service_active[pid, tid] = 1;
	futex_wait_kind[pid, tid] = 0;
}

/*
 * `futex-route` fires after the guest word check and records the dispatcher
 * route: op 0 is WAIT, shared 0 is Carrick's process-private parking lot,
 * shared 1 is the native cross-process futex implementation.
 */
carrick*:::futex-route
/tracked[pid] && service_active[pid, tid] && arg2 == 0/
{
	futex_wait_kind[pid, tid] = arg3 == 0 ? 1 : 2;
}

carrick*:::native-syscall-service-end
/tracked[pid] && service_active[pid, tid]/
{
	service_active[pid, tid] = 0;
	futex_wait_kind[pid, tid] = 0;
}

syscall:::entry
/tracked[pid] &&
    (probefunc == "psynch_cvwait" ||
    probefunc == "psynch_cvsignal" ||
    probefunc == "psynch_cvbroad" ||
    probefunc == "psynch_cvclrprepost" ||
    probefunc == "kevent" ||
    probefunc == "waitid" ||
    probefunc == "poll" ||
    probefunc == "poll_nocancel")/
{
	self->wait_started = timestamp;
	self->wait_name = probefunc;
	self->wait_base = (uint64_t)host_base[pid];
	self->wait_reason = futex_wait_kind[pid, tid];
	@wait_count[probefunc] = count();
	@wait_reason_count[self->wait_reason, probefunc] = count();
	@wait_entry_stack_count[pid, self->wait_base, probefunc, ustack(64)] =
	    count();
}

syscall:::return
/tracked[pid] && self->wait_started != 0/
{
	this->duration = timestamp - self->wait_started;
	@wait_ns[self->wait_name] = sum(this->duration);
	@wait_max_ns[self->wait_name] = max(this->duration);
	@wait_hist_us[self->wait_name] = quantize(this->duration / 1000);
	@wait_reason_ns[self->wait_reason, self->wait_name] =
	    sum(this->duration);
	@wait_reason_max_ns[self->wait_reason, self->wait_name] =
	    max(this->duration);
	@wait_stack_ns[pid, self->wait_base, self->wait_name, ustack(64)] =
	    sum(this->duration);
	@wait_return_stack_count[pid, self->wait_base, self->wait_name,
	    ustack(64)] = count();
	self->wait_started = 0;
	self->wait_name = 0;
	self->wait_base = 0;
	self->wait_reason = 0;
}

/*
 * This mixed-domain stream is a calibration plane. Host and dyld stacks
 * should unwind deeply; samples interrupted in translated guest code are
 * expected to stop at a JIT PC until a guest/JIT unwinder is added.
 */
profile-499
/tracked[pid] && arg1 != 0/
{
	@oncpu_stack[pid, host_base[pid], ustack(64)] = count();
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
	printf("DEEPWAIT1|section=totals\n");
	printa("DEEPWAIT1|host=%s|count=%@d\n", @wait_count);
	printa("DEEPWAIT1|host=%s|duration-ns=%@d\n", @wait_ns);
	printa("DEEPWAIT1|host=%s|max-ns=%@d\n", @wait_max_ns);
	printa("DEEPWAIT1|host-base|pid=%d|base=0x%x|count=%@d\n",
	    @host_base);

	printf("DEEPWAIT1|section=reasons|legend=0-other,1-private-futex,2-shared-futex\n");
	printa("DEEPWAIT1|reason=%d|host=%s|count=%@d\n",
	    @wait_reason_count);
	printa("DEEPWAIT1|reason=%d|host=%s|duration-ns=%@d\n",
	    @wait_reason_ns);
	printa("DEEPWAIT1|reason=%d|host=%s|max-ns=%@d\n",
	    @wait_reason_max_ns);

	printf("DEEPWAIT1|section=histograms-us\n");
	printa("DEEPWAIT1|host=%s\n%@d\n", @wait_hist_us);

	trunc(@wait_stack_ns, 64);
	printf("DEEPWAIT1|section=duration-stacks\n");
	printa("DEEPSTACK1|begin|class=wait-duration|pid=%d|base=0x%x|host=%s|value-ns=%@d\n%kDEEPSTACK1|end\n",
	    @wait_stack_ns);

	trunc(@wait_entry_stack_count, 64);
	printf("DEEPWAIT1|section=entry-count-stacks\n");
	printa("DEEPSTACK1|begin|class=wait-entry-count|pid=%d|base=0x%x|host=%s|value=%@d\n%kDEEPSTACK1|end\n",
	    @wait_entry_stack_count);

	trunc(@wait_return_stack_count, 64);
	printf("DEEPWAIT1|section=return-count-stacks\n");
	printa("DEEPSTACK1|begin|class=wait-return-count|pid=%d|base=0x%x|host=%s|value=%@d\n%kDEEPSTACK1|end\n",
	    @wait_return_stack_count);

	trunc(@oncpu_stack, 64);
	printf("DEEPWAIT1|section=oncpu-stacks\n");
	printa("DEEPSTACK1|begin|class=oncpu|pid=%d|base=0x%x|value=%@d\n%kDEEPSTACK1|end\n",
	    @oncpu_stack);
}
