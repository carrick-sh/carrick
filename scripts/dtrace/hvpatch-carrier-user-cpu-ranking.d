#!/usr/sbin/dtrace -qs
/*
 * hvpatch-carrier-user-cpu-ranking.d — rank the NAMED Carrick functions that
 * burn user CPU inside one HVPatch VM carrier.
 *
 * (a) What it measures. `scripts/dtrace/hvpatch-phase4-whole-cpu.d`
 * deliberately refuses to walk stacks: it answers "which Linux syscall service
 * dominates" and treats guest registers and trap-context unwind as
 * non-authoritative. That leaves the complementary question unanswered — WHICH
 * Carrick code is executing — which is the question you must ask when hunting
 * super-linear algorithms rather than expensive services. This script samples
 * the carrier's user stacks and reports them ranked, so a hot O(global-state)
 * scan shows up as a named frame instead of as an unexplained CPU share.
 *
 * It is deliberately blunt: no windowing, no per-syscall join, no state. That
 * is what makes it trustworthy for RANKING under a workload that has already
 * been shown to lose DTrace associative joins.
 *
 * (b) Provider ABI, qualified live on Darwin/arm64 (macOS 27, 2026-08-30).
 * `profile-1997` fires per CPU; `pid`/`tid` are the INTERRUPTED thread's host
 * identities. `ustack()` is trustworthy only because `.cargo/config.toml`
 * forces frame pointers — without that flag DTrace prints plausible nonsense
 * assembled by snapping stack words to the nearest preceding symbol.
 * Guest-executing samples land in the HVF vCPU-run call, not in guest code, so
 * a large `hv_vcpu_run` share is guest execution and NOT a Carrick cost.
 *
 * Attach to the VM CARRIER. Under the in-process conformance-next lane the
 * carrier is a grandchild carrying the `carrick:<run-id>:` proctitle; the
 * process that spawned it runs no guest and profiles as idle:
 *   sudo dtrace -qs scripts/dtrace/hvpatch-carrier-user-cpu-ranking.d \
 *     -p "$(pgrep -f 'carrick:<run-id>:' | head -1)"
 *
 * (c) Perturbation: moderate — one 24-frame user unwind at 1997 Hz per CPU
 * while the target is on CPU. Sample RANK and relative shares are citable;
 * absolute wall/CPU time under this script is not.
 *
 * (d) UNDER `carrick trace` THE STACKS COME OUT AS BARE ADDRESSES, and they
 * are still fully recoverable — do not throw the capture away or re-run it
 * under an external consumer (learned 2026-09-08, cpython-compile fault-cost
 * attribution). `carrick trace` runs libdtrace IN-PROCESS inside the CLI,
 * which is not the VM carrier, so the lazy `ustack()` symbol resolution has no
 * process to grab and prints raw runtime addresses. Recover them offline:
 *
 *   1. The carrick binary is PIE with `__TEXT` at vmaddr `0x100000000` and
 *      fileoff 0, so a runtime address maps to file offset `addr - load_base`
 *      and the only unknown is `load_base`.
 *   2. Every frame ABOVE the leaf is a RETURN address, so for the true
 *      `load_base` the 4 bytes at `addr - 4 - load_base` decode as `BL`
 *      (`insn >> 26 == 0b100101`) or `BLR` (`insn & 0xFFFFFC1F == 0xD63F0000`)
 *      for essentially every sampled frame. Sweep `load_base` over the 16 KiB-
 *      aligned candidates allowed by the observed address span and the
 *      `__TEXT` vmsize (`otool -l`): the correct one scores ~100 %, every
 *      other one ~12 %. Measured on the compile row: 248/248 vs 30/248, one
 *      unambiguous winner (`0x102fe4000`).
 *      Do NOT score by "does the offset land inside some symbol" — symbols are
 *      contiguous, so every candidate scores 100 % and nothing is learned.
 *   3. Then `atos -o <the exact binary> -l <load_base> <addr>...`.
 *
 * Attribute each SAMPLE to the highest-level owner in its stack (the first
 * `munmap`/`resolve_mutating_fault`/`hv_vcpu_run` frame walking leaf→root),
 * not to its leaf: the hot leaves are shared runtime helpers (`Vec::from_iter`,
 * `memmove`) that say nothing on their own.
 */

#pragma D option quiet
#pragma D option bufsize=96m
#pragma D option aggsize=96m

dtrace:::BEGIN
{
    started = timestamp;
    samples = 0;
    errors = 0;
    bounded = 0;
}

profile-1997
/pid == $target || progenyof($target)/
{
    samples++;
    @stacks[ustack(24)] = count();
}

dtrace:::ERROR
{
    errors++;
}

/*
 * Print the ranking in 5-second slices WHILE the carrier is alive: DTrace
 * resolves `ustack()` symbols lazily at output time by grabbing the live
 * process, so an aggregation printed from `dtrace:::END` (or even from
 * `proc:::exit`, when the process is already tearing down) comes out as bare
 * addresses. Observed twice on the arena-churn profile, 2026-09-04. Each
 * slice is a complete ranking of that window; sum slices for a whole-run
 * ranking. The END clause is the fallback for a bounded/aborted capture.
 */
profile:::tick-5sec
{
    printf("HVPUSERCPU|slice|samples=%d\n", samples);
    printf("HVPUSERCPU|stacks\n");
    trunc(@stacks, 60);
    printa(@stacks);
    trunc(@stacks);
    printed = 1;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 150 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
/printed == 0/
{
    printf("HVPUSERCPU|summary|samples=%d|empty=%d|bounded=%d|errors=%d\n",
        samples, samples == 0, bounded, errors);
    printf("HVPUSERCPU|stacks\n");
    trunc(@stacks, 120);
    printa(@stacks);
}
