#!/usr/sbin/dtrace -qs
/*
 * Count selected COW/retirement invalidation scope. Scalar ABI qualified from
 * carrick-observability: ASID u32, start VA u64, page count u32 (0=full ASID).
 * Fired after maintenance entry validation and before vCPU execution; target
 * success is required to claim the requested maintenance completed.
 *
 * A private Rust pid-provider entry attempt yielded zero events despite the
 * lifecycle proving host == target. It was rejected, not called zero usage.
 * Use this explicit USDT surface instead of relying on private-symbol arming.
 * Perturbation: one probe per invalidation, potentially high. Counts only;
 * timings are never performance acceptance. Let the short capture end naturally.
 */
#pragma D option quiet

dtrace:::BEGIN
{ started = timestamp; events = 0; errors = 0; seen = 0; code = -1; bounded = 0; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{ printf("COWTLBI|exec|host=%d|target=%d\n", pid, $target); }

carrick*:::hvpatch-tlb-invalidation
/(pid == $target || progenyof($target))/
{
    errors += arg0 == 0 || arg2 > 4 || (arg2 != 0 && (arg1 & 4095) != 0);
    events++;
    @scope[arg2] = count();
}

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && events > 0 && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 30 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("COWTLBI|summary|events=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", events, errors, seen, code, bounded);
    printa("COWTLBI|pages=%d|count=%@d\n", @scope);
}
