#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option strsize=256

/*
 * Join Darwin host syscalls to Carrick's active guest syscall (native lane).
 *
 * (a) WHAT IT MEASURES. Host-call amplification: how many macOS syscalls one
 *     Linux syscall costs. Two joins, deliberately distinct:
 *       section=host-by-guest      the FILTERED fs set below, with per-call
 *                                  durations -- the fs lane's shape.
 *       section=host-all-by-guest  EVERY host syscall, no filter -- the honest
 *                                  denominator. Without it a reported
 *                                  "host per guest op" ratio silently means
 *                                  "fs-class host calls only" and undercounts.
 *     `guest=carrick-only` covers image setup, supervision, teardown and other
 *     work outside a native guest syscall-service interval; it is real cost but
 *     it is NOT amplification of any guest op, so never fold it into a ratio.
 *     The decision metric is host-call COUNT, not traced elapsed time.
 *
 * (b) PROVIDER ABI FACTS (qualified on macOS 27 / Apple Silicon).
 *     - Scope is the `tracked[]` table seeded from `$target` and grown through
 *       `proc:::create`, NOT `execname == "carrick"`. That matters: `carrick
 *       trace` runs libdtrace IN-PROCESS inside a `carrick` binary, so an
 *       execname filter counts the TRACER's own syscalls as if they were the
 *       guest's. (AGENTS.md records a profile that was 54% profiler for
 *       exactly this reason.)
 *     - `native-syscall-service-entry`/`-end` bracket the native lane only.
 *       Under the VMM backend they never fire and every host call lands in
 *       `carrick-only` -- a run whose guest-syscall total is 0 is a
 *       wrong-backend error, not an empty result.
 *     - `self->` does not survive entry->return pairing across probes here, so
 *       the duration clauses use `self->fs_started` set in the same thread.
 *
 * (c) PERTURBATION: YES, and materially. Two probes fire on every host syscall
 *     the tracked tree issues, so wall time from a traced run is not a
 *     performance number. Only same-instrument counts and ratios are citable.
 *     The tick bound below prints an explicit `section=truncated` marker and
 *     exits non-zero if it fires, so a partial capture can never be mistaken
 *     for a complete census.
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
	@guest_total = count();
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

/*
 * The unfiltered denominator. Same join, no host-call allow-list, no timing --
 * counts only, so the extra cost is one aggregation per host syscall.
 */
syscall:::entry
/tracked[pid]/
{
	@host_total = count();
	@host_all_by_guest[service_active[pid, tid] ?
	    service_name[pid, tid] : "carrick-only"] = count();
	@host_all_fn[probefunc] = count();
	@host_all_pair[service_active[pid, tid] ?
	    service_name[pid, tid] : "carrick-only", probefunc] = count();
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

/*
 * Safety net only -- the census normally ends on the target's own exit above.
 * Adding the unfiltered clause roughly doubles probe traffic, so the old 45 s
 * bound could fire mid-walk and silently truncate the counts; a truncated
 * census is an ERROR, so say so in-band and exit non-zero.
 */
tick-1s
/seconds >= 300/
{
	printf("FSAMP1|section=truncated|reason=tick-limit|seconds=%d\n",
	    seconds);
	exit(1);
}

dtrace:::END
{
	printf("FSAMP1|section=totals\n");
	printa("FSAMP1|metric=guest-syscall-total|count=%@d\n", @guest_total);
	printa("FSAMP1|metric=host-syscall-total|count=%@d\n", @host_total);

	printf("FSAMP1|section=guest-syscalls\n");
	printa("FSAMP1|guest=%s|count=%@d\n", @guest_syscall);

	printf("FSAMP1|section=host-all-by-guest\n");
	printa("FSAMP1|guest=%s|host-total=%@d\n", @host_all_by_guest);

	printf("FSAMP1|section=host-all-by-function\n");
	printa("FSAMP1|host=%s|count=%@d\n", @host_all_fn);

	printf("FSAMP1|section=host-all-pairs\n");
	printa("FSAMP1|guest=%s|host=%s|count=%@d\n", @host_all_pair);

	printf("FSAMP1|section=host-by-guest\n");
	printa("FSAMP1|host=%s|guest=%s|count=%@d\n", @host_by_guest);

	printf("FSAMP1|section=host-duration-by-guest\n");
	printa("FSAMP1|host=%s|guest=%s|duration-ns=%@d\n",
	    @host_ns_by_guest);
	printa("FSAMP1|host=%s|guest=%s|max-ns=%@d\n",
	    @host_max_ns_by_guest);
}
