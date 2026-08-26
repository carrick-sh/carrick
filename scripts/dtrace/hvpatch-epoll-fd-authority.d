/*
 * HVPatch epoll file-authority seam for the signed go-go_importer run.
 *
 * This is a correctness-only trace. It distinguishes a wrong captured
 * FileTable from a real fd-11 slot removal/replacement; never use it for
 * performance measurement.
 *
 * Provider ABI, qualified against crates/carrick-observability/src/probes.rs:
 *   hvpatch-syscall-service-begin:
 *     arg0=Linux pid (i32), arg1=Linux tid (i32), arg2=ASID (u32),
 *     arg3=Linux syscall number (u64).
 *   epoll-lookup:
 *     arg0=file_table_id (u64), arg1=epfd (i32), arg2=slot_generation (u64),
 *     arg3=file_description_id (u64), arg4=lookup_kind (u32):
 *     0=live epoll, 1=live non-epoll replacement, 2=absent slot.
 * The consumer pairs both probes through self->epoll_syscall on the same host
 * thread. Use through `carrick trace --script ... --require-script-exit -- ...`
 * so $target is the carrier and this script's terminal receipt is strict.
 *
 * The script self-exits after 12 seconds and fails closed unless it sees an
 * epoll syscall-service begin, a live fd-11 epoll lookup, and an fd-11 absent
 * or replacement lookup. Any uncorrelated or invalid lookup also fails closed.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=4m

dtrace:::BEGIN
{
    printf("EFA1|begin|wall=%Y\n", walltimestamp);
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (arg3 == 22 || arg3 == 441)/
{
    service_begins++;
    self->epoll_syscall = arg3;
    printf("EFA1|service-begin|hostpid=%d|hosttid=%d|pid=%d|tid=%d|asid=%d|nr=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && (arg3 == 22 || arg3 == 441)/
{
    self->epoll_syscall = 0;
}

carrick*:::epoll-lookup
/(pid == $target || progenyof($target)) && arg1 == 11/
{
    if (self->epoll_syscall != 22 && self->epoll_syscall != 441) {
        uncorrelated++;
        printf("EFA1|error=uncorrelated-lookup|hostpid=%d|hosttid=%d|table=%d|epfd=%d|kind=%d\n",
            pid, tid, arg0, (int)arg1, (int)arg4);
    } else if (arg4 == 0) {
        live_epoll++;
        printf("EFA1|lookup=live-epoll|hostpid=%d|hosttid=%d|nr=%d|table=%d|epfd=%d|slot=%d|description=%d\n",
            pid, tid, (int)self->epoll_syscall, arg0, (int)arg1, arg2, arg3);
    } else if (arg4 == 1 || arg4 == 2) {
        absent_or_replaced++;
        printf("EFA1|lookup=%s|hostpid=%d|hosttid=%d|nr=%d|table=%d|epfd=%d|slot=%d|description=%d\n",
            arg4 == 1 ? "replacement" : "absent", pid, tid,
            (int)self->epoll_syscall, arg0, (int)arg1, arg2, arg3);
    } else {
        invalid_kind++;
        printf("EFA1|error=invalid-lookup-kind|hostpid=%d|hosttid=%d|kind=%d\n",
            pid, tid, (int)arg4);
    }
}

tick-12s
{
    if (service_begins == 0 || live_epoll == 0 || absent_or_replaced == 0 ||
        uncorrelated != 0 || invalid_kind != 0) {
        printf("EFA1|fail|service-begins=%d|live-epoll=%d|absent-or-replaced=%d|uncorrelated=%d|invalid-kind=%d\n",
            service_begins, live_epoll, absent_or_replaced, uncorrelated, invalid_kind);
        exit(1);
    }
    printf("EFA1|pass|service-begins=%d|live-epoll=%d|absent-or-replaced=%d\n",
        service_begins, live_epoll, absent_or_replaced);
    exit(0);
}
