#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-maintenance-service-attribution.d — identify which forwarded guest
 * syscall owns HVPatch's host-driven EL1 maintenance exits.
 *
 * WHAT IT MEASURES
 *   Counts `vcpu-run-exit` class 5 while the same executor thread services a
 *   forwarded guest syscall, grouped by Linux syscall number. Counts exits
 *   outside forwarded service separately. In particular, this distinguishes
 *   per-page work inside MADV_DONTNEED from later guest first touches. Also
 *   counts fault/COW/grant probes to identify the outside-service source.
 *
 * PROVIDER ABI
 *   Qualified from carrick-observability on macOS/arm64:
 *   `hvpatch-syscall-service-begin(pid, tid, asid, nr)` and
 *   `hvpatch-syscall-service(pid, tid, asid, nr, duration_ns)` bracket a
 *   forwarded syscall on one executor thread. `vcpu-run-exit(vcpu, class,
 *   esr)` reports class 5 for each maintenance HVC, including host-driven
 *   EL1 calls. The CLI's carrier is its descendant; both arms use
 *   `pid == $target || progenyof($target)`.
 *   `vcpu-fault` is the host trap, `pt-fault-walk` the host-side stage-1
 *   walk, and `hvpatch-frame-cow-trigger` the guest COW trigger. The
 *   `hvpatch-el1-frame-grant-plan` probe marks host-planned EL1 grants;
 *   `hvpatch-fork-frame-identity` marks each child frame inheritance.
 *
 * PERTURBATION
 *   One aggregation update per maintenance exit and two thread-local writes
 *   per forwarded syscall. Counts only; never use this trace for timing.
 *   A 10-second bound prints the aggregate even when an external test runner
 *   has exited before DTrace observes its `proc:::exit`.
 */
#pragma D option quiet

dtrace:::BEGIN
{
    seconds = 0;
    maintenance = 0;
    errors = 0;
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->in_service = 1;
    self->nr = (uint64_t)arg3;
}

carrick*:::vcpu-run-exit
/(pid == $target || progenyof($target)) && arg1 == 5/
{
    maintenance++;
    @by_service[self->in_service ? self->nr : (uint64_t)-1] = count();
}

carrick*:::vcpu-fault,
carrick*:::pt-fault-walk,
carrick*:::hvpatch-frame-cow-trigger,
carrick*:::hvpatch-el1-frame-grant-plan,
carrick*:::hvpatch-fork-frame-identity
/pid == $target || progenyof($target)/
{
    @path[probename] = count();
}

carrick*:::hvpatch-syscall-service
/pid == $target || progenyof($target)/
{
    self->in_service = 0;
}

dtrace:::ERROR
{
    errors++;
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 10/
{
    exit(maintenance > 0 && errors == 0 ? 0 : 1);
}

dtrace:::END
{
    printf("MAINTSVC1|summary|maintenance=%d|errors=%d|seconds=%d\n",
        maintenance, errors, seconds);
    printa("MAINTSVC1|service_nr=%u|count=%@u\n", @by_service);
    printa("MAINTSVC1|path=%s|count=%@u\n", @path);
}
