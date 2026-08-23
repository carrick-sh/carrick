/*
 * Shared-futex KEY IDENTITY census: do all guest tasks resolve one shared
 * futex word to the SAME waiter identity?
 *
 * (a) What it measures: for every non-private futex syscall the runtime
 *     routes (carrick*:::futex-route), the (guest VA, op, shared?, resolved
 *     host wait address) tuple. On HVF/HVPatch the host wait address IS the
 *     waiter key for an anonymous MAP_SHARED word (shared_key_base == 0 in
 *     `shared_futex_location_for_ipa`), so two tasks parked/waking on the
 *     same guest word with DIFFERENT host= values are provably on disjoint
 *     wait queues — writes stay coherent through the shared frame while
 *     every wake/requeue finds zero waiters (the sharedanonfutexfork /
 *     futexforkrequeue defect shape). File-backed shared words key by
 *     (file, offset) instead, so a host= split there is NOT a queue split.
 * (b) Provider ABI facts (qualified live on macOS 26/arm64, 2026-08-23):
 *     carrick*:::futex-route args are (arg0 unused, arg1 = guest VA,
 *     arg2 = futex op (99 = pre-wait expected-value channel, skip it),
 *     arg3 = shared-routed flag 0/1, arg4 = resolved host wait VA or 0).
 *     HVPatch guest fork does NOT create host processes: parent and child
 *     tasks share one carrier pid, so `pid` does not distinguish guest
 *     tasks — the discriminator is the host= value itself. Use dtrace -Z:
 *     the probe set arms before the carrier registers its DOF.
 * (c) Perturbation: fires once per guest futex syscall. On a futex-storm
 *     workload (1000-waiter LTP shapes) that is ~thousands of firings/s —
 *     fine for a boolean identity verdict, but do not cite wall-clock from
 *     a traced run.
 */

#pragma D option quiet
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("shared-futex key identity census started at %Y\n", walltimestamp);
}

/* Per-op stream for WAIT(0) and WAKE(1): one line per routed futex op. */
carrick*:::futex-route
/(pid == $target || progenyof($target)) && ((int)arg2 == 0 || (int)arg2 == 1)/
{
    printf("[route] guest=%#x op=%d shared=%d host=%#x\n",
        arg1, (int)arg2, (int)arg3, arg4);
}

/* Identity summary: distinct host keys observed per (guest VA, op, shared). */
carrick*:::futex-route
/(pid == $target || progenyof($target)) && (int)arg2 != 99/
{
    @keys[arg1, (int)arg2, (int)arg3, arg4] = count();
}

tick-1s { secs++; }
tick-1s /secs >= 60/ { timed_out = 1; exit(0); }

END
{
    printf("\ntrace_timed_out=%d\n", timed_out);
    printf("\n==== (guest VA, op, shared, host key) -> firings ====\n");
    printa("  guest=%#x op=%d shared=%d host=%#x %@d\n", @keys);
}
