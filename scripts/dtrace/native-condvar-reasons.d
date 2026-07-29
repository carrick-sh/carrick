#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option strsize=256

/*
 * Directional Darwin/native condvar-reason capture.
 *
 * This is deliberately a fast hypothesis tool, not an accepted wall profile:
 * it joins Carrick's typed synchronization-acquisition boundaries to psynch
 * condvar calls. The launch-owned predicate excludes unrelated Carrick runs.
 * Full native service probes distinguish dispatcher work, post-dispatch
 * outcome/completion work, and Carrick-only work on the current thread.
 *
 * Synchronization kinds:
 *   1 = generation-table write
 *   2 = process-state read
 *   3 = process-state write
 *
 * Run only through `carrick trace`, which owns the target for its lifetime:
 *
 *   CARRICK_RUN_ID=<unique> target/release/carrick trace \
 *     --script scripts/dtrace/native-condvar-reasons.d \
 *     --trace-out <raw.txt> -- run --exec-backend native ...
 *
 * Branch-child service context is intentionally not reconstructed here. The
 * authoritative joined profile owns that machinery. This spike ranks caller
 * stacks; its context split is directional and must not be published as an
 * exact guest/Carrick population. User stacks are intentionally absent:
 * native DSR can expose the guest SP to unwinding, making those frames
 * non-authoritative.
 */

dtrace:::BEGIN
{
	seconds = 0;
}

carrick*:::native-syscall-service-entry
/pid == $target || progenyof($target)/
{
	service_active[pid, tid] = 1;
	service_name[pid, tid] = copyinstr(arg1);
}

carrick*:::native-syscall-service-end
/(pid == $target || progenyof($target)) && service_active[pid, tid]/
{
	service_active[pid, tid] = 0;
	service_name[pid, tid] = 0;
	dispatch_active[pid, tid] = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && service_active[pid, tid]/
{
	dispatch_active[pid, tid] = 1;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && dispatch_active[pid, tid]/
{
	dispatch_active[pid, tid] = 0;
}

carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
	@host_base[arg0, arg1] = count();
}

carrick*:::dsr-synchronization-begin
/pid == $target || progenyof($target)/
{
	sync_started[pid, tid] = timestamp;
	sync_kind[pid, tid] = (int)arg0;
	@sync_begin[(int)arg0] = count();
}

carrick*:::dsr-synchronization-end
/(pid == $target || progenyof($target)) &&
    sync_kind[pid, tid] && sync_started[pid, tid]/
{
	this->kind = sync_kind[pid, tid];
	@sync_acquire_count[this->kind] = count();
	@sync_acquire_ns[this->kind] = sum(timestamp - sync_started[pid, tid]);
	@sync_acquire_max_ns[this->kind] = max(timestamp - sync_started[pid, tid]);
	sync_kind[pid, tid] = 0;
	sync_started[pid, tid] = 0;
}

syscall:::entry
/(pid == $target || progenyof($target)) &&
    (probefunc == "psynch_cvwait" ||
    probefunc == "psynch_cvsignal" ||
    probefunc == "psynch_cvbroad" ||
    probefunc == "psynch_cvclrprepost")/
{
	@condvar_total[probefunc] = count();
	@condvar_context[
	    service_active[pid, tid] ?
	        (dispatch_active[pid, tid] ? "guest-inside-dispatch" :
	        "guest-outcome-completion") :
	        "carrick-only",
	    probefunc,
	    service_active[pid, tid] ? service_name[pid, tid] : "-"] = count();
	@condvar_sync[sync_kind[pid, tid], probefunc] = count();
	condvar_started[pid, tid] = timestamp;
	condvar_sync_kind[pid, tid] = sync_kind[pid, tid];
	condvar_active[pid, tid] = 1;
}

syscall:::return
/(pid == $target || progenyof($target)) && condvar_active[pid, tid]/
{
	this->duration = timestamp - condvar_started[pid, tid];
	@condvar_duration_total[probefunc] = sum(this->duration);
	@condvar_duration_ns[condvar_sync_kind[pid, tid], probefunc] =
	    sum(this->duration);
	@condvar_duration_max_ns[condvar_sync_kind[pid, tid], probefunc] =
	    max(this->duration);
	condvar_active[pid, tid] = 0;
	condvar_started[pid, tid] = 0;
	condvar_sync_kind[pid, tid] = 0;
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 30/
{
	exit(0);
}

dtrace:::END
{
	printf("CONDVAR1|section=totals\n");
	printa("CONDVAR1|host=%s|count=%@d\n", @condvar_total);

	printf("CONDVAR1|section=context\n");
	printa("CONDVAR1|context=%s|host=%s|guest=%s|count=%@d\n",
	    @condvar_context);

	printf("CONDVAR1|section=synchronization\n");
	printa("CONDVAR1|sync-kind=%d|host=%s|count=%@d\n",
	    @condvar_sync);
	printa("CONDVAR1|duration-total-ns|host=%s|value=%@d\n",
	    @condvar_duration_total);
	printa("CONDVAR1|duration-ns|sync-kind=%d|host=%s|value=%@d\n",
	    @condvar_duration_ns);
	printa("CONDVAR1|duration-max-ns|sync-kind=%d|host=%s|value=%@d\n",
	    @condvar_duration_max_ns);
	printa("CONDVAR1|sync-begin|kind=%d|count=%@d\n", @sync_begin);
	printa("CONDVAR1|sync-acquire-count|kind=%d|count=%@d\n",
	    @sync_acquire_count);
	printa("CONDVAR1|sync-acquire-ns|kind=%d|value=%@d\n",
	    @sync_acquire_ns);
	printa("CONDVAR1|sync-acquire-max-ns|kind=%d|value=%@d\n",
	    @sync_acquire_max_ns);

	printf("CONDVAR1|section=host-bases\n");
	printa("CONDVAR1|host-base|pid=%d|base=0x%x|count=%@d\n",
	    @host_base);
}
