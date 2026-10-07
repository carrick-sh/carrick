/*
 * Which host-served syscall returns the first Linux error in a signed test?
 *
 * Measures syscall-return errors and positive owner-bind controls, following
 * the target and descendants. Source ABI: syscall-return(nr, name, retval,
 * errno); hvpatch-el1-owner-bind-result(errno, ...). Live qualification must
 * show both return and bind events; zero events cannot establish no errors.
 * Embed scheduler witnesses register the existing CompatReporter probe hook
 * with CARRICK_SCHED_TRACE_RETURNS=1, preserving guest fast-path admission.
 * Live-qualified on the corrected 0d154a9a4-based pipe artifact: return and
 * bind controls fired, errors=0, bounded=0; the consumer reported no drops.
 * The preparation arm reports VA, length, phase and detail; phase 4/detail 2
 * was live-qualified as an Editor wait on the pre-fix pipe2 error capture.
 * Perturbation: one aggregate per host return, output only on errors; this
 * is diagnostic mechanism evidence, never a runtime measurement.
 * Ends on target exit; the 30-second diagnostic bound fails closed.
 */
#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{ returns = 1; @calls[arg0] = count(); }

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg3 != 0/
{
    printf("HOSTERR1|pid=%d|tid=%d|nr=%llu|name=%s|retval=%lld|errno=%d\n",
        pid, tid, (uint64_t)arg0, copyinstr(arg1), (int64_t)arg2, (int32_t)arg3);
}

carrick*:::hvpatch-el1-owner-bind-result
/pid == $target || progenyof($target)/
{ bind = 1; }

carrick*:::hvpatch-el1-host-write-prepare
/(pid == $target || progenyof($target)) && arg2 != 0 && arg2 != 3/
{
    printf("HOSTERR1|prepare|va=%llx|len=%llu|phase=%u|detail=%llu\n",
        (uint64_t)arg0, (uint64_t)arg1, (uint32_t)arg2, (uint64_t)arg3);
}

dtrace:::ERROR { errors = 1; exit(3); }
proc:::exit /pid == $target/ { exit(returns && bind && !errors ? 0 : 2); }
tick-1s { seconds++; }
tick-1s /seconds >= 30/ { bounded = 1; exit(4); }
END {
    printf("HOSTERR1|summary|returns=%d|bind=%d|errors=%d|bounded=%d\n",
        returns, bind, errors, bounded);
    printa("HOSTERR1|nr=%lld|count=%@u\n", @calls);
}
