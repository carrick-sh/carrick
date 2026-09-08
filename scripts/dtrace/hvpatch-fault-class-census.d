#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-fault-class-census.d — WHY the guest fault COUNT is super-linear.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * `docs/conformance-campaigns/2026-09-04-ecosystem.md` (2026-09-08 07:00)
 * closed the per-fault LOOKUP cost on `cpython-compile` and left one item
 * open: "the fault count itself is still super-linear (8x depth = 22.8x
 * faults, rows 14.9x, lumpy)". Per-fault instruments
 * (`hvpatch-mapping-index-census.d`) cannot answer that: they measure the
 * cost of a fault, never why there are so many.
 *
 * This script counts EL0 aborts and classifies each one three ways:
 *
 *   1. by VMA CLASS, from the FAR against the fixed guest layout in
 *      `crates/carrick-mem/src/memory.rs`:
 *        heap  0x40_0000_0000 + 128 MiB   (LINUX_HEAP_BASE, brk)
 *        mmap  0x60_0000_0000 + 32 GiB    (LINUX_MMAP_BASE, the sparse arena)
 *        img   0x88_0000_0000 ..          (PIE image + interpreter)
 *        stack 0xff_7fff_0000 .. 0xff_ffff_0000 (LINUX_STACK_TOP - 8 MiB)
 *        low   everything below the heap base (boot/aperture/root slot)
 *
 *   2. by FAULT KIND, from ESR: EC (`esr >> 26`) separates a data abort
 *      (0x24) from an instruction abort (0x20); for a data abort the DFSC
 *      (`iss & 0x3f`) separates a TRANSLATION fault (0b0001xx — nothing
 *      mapped, the first-touch case) from an ACCESS-FLAG fault (0b0011xx)
 *      and a PERMISSION fault (0b0101xx — the COW/write-to-clean case); ISS
 *      bit 6 (WnR) separates read from write.
 *
 *   3. by REPEAT, entirely inside this script, from the FAR alone:
 *        - `win` = 64 KiB granule (`far >> 16`) — the DEFAULT fault window
 *          (`HvfInner::DEFAULT_FAULT_WINDOW_BYTES`, hatched by
 *          CARRICK_FAULT_WINDOW_BYTES). One first-touch fault is supposed to
 *          materialize a whole window, so a SECOND fault in a window this
 *          run already faulted is a window that did not take.
 *        - `cmp` = 16 KiB granule (`far >> 14`) — `CowArmedRanges::
 *          COMPOUND_SIZE`, the unit the window arm actually materializes and
 *          the host page size. A repeat at 64 KiB that is a FIRST touch at
 *          16 KiB says the window widened but only its own compound was
 *          published; a repeat at 16 KiB says the same compound faulted twice.
 *        - `pg` = 4 KiB granule (`far >> 12`) — the guest page. A repeat here
 *          is a genuine RE-fault of a page this run already faulted: a lost
 *          mapping, a torn-down window, or an evicted stage-1 entry.
 *      The three counts together decide the question the brief asks: whether
 *      the extra faults are new pages (a memory-footprint problem) or the
 *      same pages again (a mapping-lifetime problem).
 *
 * The distinct-granule counts are also the denominator the wall time needs:
 * `faults / distinct 4 KiB pages` is the fault AMPLIFICATION, and
 * `distinct pages / depth` is the guest's own footprint. Only the first is
 * carrick's to fix.
 *
 * (b) PROVIDER ABI (qualified live on macOS 26 / arm64, 2026-09-08, against
 *     `crates/carrick-observability/src/probes.rs`, provider `carrick`)
 * --------------------
 *   carrick*:::vcpu-fault (uint64_t esr, uint64_t elr, uint64_t far,
 *       uint64_t x30, uint64_t sp, int host_pid)
 *       — fires from `HvfInner::run_to_exit` on EVERY EL0 abort HVF
 *         surfaces, on both the direct-exit and the EL1-vector route, before
 *         the runtime decides how to service it. It is therefore the total,
 *         and the only probe whose count is not conditional on an outcome.
 *   proc:::exit — used only for self-termination.
 *
 * `-Z` is required: the carrier process does not exist yet when
 * `carrick trace` starts the script, so the probes must be allowed to arm
 * late. Without it dtrace refuses to start with "probe description ... does
 * not match any probes".
 *
 * NOTE ON SCOPE: this script does NOT name any `hvpatch-mapping-index-*`
 * probe, deliberately. Naming `hvpatch-mapping-index-begin` arms the
 * mapping-index census inside the producer, which takes two `Instant::now()`
 * reads and the alias-registry lock on every first-touch fault. That census
 * answers a different question and its cost would land inside the counts
 * here. Run the two scripts separately.
 *
 * (c) PERTURBATION
 * ----------------
 * Real and one-sided but small: one probe fire, five thread-locals and three
 * associative-array probes per EL0 abort, on a path that already does a
 * stage-1 walk and a host `mmap`. The COUNT columns are exact — they are
 * counts of a probe that fires unconditionally — so fault counts and
 * amplification ratios ARE citable across runs of this script and across
 * binaries. Wall time under this script is NOT citable against an untraced
 * run.
 *
 * The associative arrays are the real budget: one key per distinct 4 KiB
 * page touched. A 1 GiB working set is 262,144 keys, so `dynvarsize` is
 * raised to 256 MiB below. If dtrace reports "dynamic variable drops", the
 * distinct counts are UNDER-reported and the capture must be re-run with a
 * smaller depth or a larger size — a drop line is a FAILED capture, not a
 * result.
 *
 * (d) USAGE
 * ---------
 *   carrick trace -s scripts/dtrace/hvpatch-fault-class-census.d run \
 *       --fs host localhost:5050/cpython-test:3.12.13 \
 *       /usr/local/bin/python3 -c '<reducer>'
 *
 * Reads as three tables on exit, all prefixed FAULTCLASS| for grepping (the
 * gate's logs carry binary bytes, so always `grep -a`).
 */

#pragma D option dynvarsize=256m
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{
    live = 1;
    seconds = 0;
    complete = 0;
    faults = 0;
    stales = 0;
    delivers = 0;
    /*
     * D has no declaration syntax for an associative array, and reading one
     * that has never been assigned is a compile error ("winseen has not yet
     * been declared or assigned"). Seed each with key 0 to fix its key and
     * value types. Key 0 means a FAR below 64 KiB — a NULL dereference, never
     * a real first touch — so seeding it loses no measurement.
     */
    winseen[(uint64_t)0] = 1;
    cmpseen[(uint64_t)0] = 1;
    pgseen[(uint64_t)0] = 1;
    printf("FAULTCLASS|start|ns=%d|target=%d\n", timestamp, $target);
}

proc:::exit
/pid == $target/
{
    live = 0;
}

tick-100ms
/live == 0 && !complete/
{
    complete = 1;
    exit(0);
}

tick-1s
{
    seconds++;
}

/*
 * `carrick trace` fails a custom script that does not exit within 60 s of the
 * traced child ending, so the script owns its own bound.
 */
tick-1s
/seconds >= 1800 && !complete/
{
    complete = 1;
    printf("FAULTCLASS|TRUNCATED|seconds=%d\n", seconds);
    exit(3);
}

dtrace:::ERROR
{
    printf("FAULTCLASS|ERROR|cpu=%d|epid=%d\n", cpu, arg1);
    exit(2);
}

carrick*:::vcpu-fault
{
    faults++;
    this->esr = arg0;
    this->far = arg2;

    /* VMA class from the fixed guest layout. */
    this->cls =
        (this->far >= 0xff7fff0000 && this->far < 0xffffff0000) ? "stack" :
        (this->far >= 0x6000000000 && this->far < 0x6800000000) ? "mmap" :
        (this->far >= 0x4000000000 && this->far < 0x4008000000) ? "heap" :
        (this->far >= 0x8800000000) ? "img" :
        (this->far >= 0x4008000000 && this->far < 0x6000000000) ? "hole" : "low";

    /* Fault kind from ESR. */
    this->ec = this->esr >> 26;
    this->iss = this->esr & 0x1ffffff;
    this->dfsc = this->iss & 0x3f;
    this->kind =
        (this->ec == 0x20) ? "iabort" :
        (this->ec != 0x24) ? "other" :
        ((this->dfsc & 0x3c) == 0x04) ? "xlate" :
        ((this->dfsc & 0x3c) == 0x08) ? "aflag" :
        ((this->dfsc & 0x3c) == 0x0c) ? "perm" : "dabt";
    this->wnr = (this->ec == 0x24 && (this->iss & 0x40) != 0) ? "w" : "r";

    /* Repeat classification at the three granules that mean something. */
    this->win = this->far >> 16;
    this->cmp = this->far >> 14;
    this->pg  = this->far >> 12;

    this->newwin = winseen[this->win] == 0 ? 1 : 0;
    this->newcmp = cmpseen[this->cmp] == 0 ? 1 : 0;
    this->newpg  = pgseen[this->pg]  == 0 ? 1 : 0;
    winseen[this->win] = 1;
    cmpseen[this->cmp] = 1;
    pgseen[this->pg] = 1;

    @all[this->cls, this->kind, this->wnr] = count();
    @newwins[this->cls] = sum(this->newwin);
    @newcmps[this->cls] = sum(this->newcmp);
    @newpgs[this->cls] = sum(this->newpg);
    @clsfaults[this->cls] = count();

    /*
     * Amplification split: of the faults that are NOT a new page, how many
     * were within a window/compound this run already faulted? That separates
     * "the window materialized only its own compound" from "the same page
     * came back".
     */
    @refault[this->cls, this->newpg ? "first" : "repeat"] = count();
    @total = count();
    @totalnewpg = sum(this->newpg);
    @totalnewcmp = sum(this->newcmp);
    @totalnewwin = sum(this->newwin);
}

/*
 * Which ARM serviced the fault. A fault that reaches neither of these was
 * resolved by the resident-fault plan in `resolve_mutating_fault`
 * (`crates/carrick-runtime/src/vcpu_loop/signal.rs`) -- the ordinary
 * first-touch path -- so `serviced_by_plan` below is a subtraction, not a
 * probe. That is the point of counting the other two: without them the
 * dominant arm cannot be named, and naming it is what decides where a
 * fault-count fix belongs.
 */
carrick*:::hvpatch-stale-stage1-retry
{
    @stale = count();
    stales++;
}

carrick*:::hvpatch-first-touch-deliver
{
    @delivered[arg1 == 0 ? "NotTracked" :
        arg1 == 1 ? "NoPendingEdit" :
        arg1 == 2 ? "ArmingDenies" :
        arg1 == 3 ? "BackendRefused" :
        arg1 == 4 ? "StaleLeafNotRetried" : "unknown"] = count();
    delivers++;
}

dtrace:::END
/faults == 0/
{
    printf("\nFAULTCLASS|EMPTY|faults=0\n");
    printf("FAULTCLASS|EMPTY|a capture with no events is a FAILED capture, not a result: the carrick*:::vcpu-fault probe never fired, so either the guest never took an EL0 abort (impossible for a real workload) or the script was not armed with -Z against a carrier that starts after dtrace\n");
}

dtrace:::END
{
    printf("\nFAULTCLASS|end|ns=%d|faults=%d\n", timestamp, faults);

    printf("\nFAULTCLASS|TABLE1 faults by class/kind/access\n");
    printf("%-8s %-8s %-4s %12s\n", "class", "kind", "rw", "faults");
    printa("%-8s %-8s %-4s %12@d\n", @all);

    printf("\nFAULTCLASS|TABLE2 distinct granules touched, per class\n");
    printf("%-8s %12s %12s %12s %12s\n", "class", "faults", "new_4k",
        "new_16k", "new_64k");
    printa("%-8s %12@d\n", @clsfaults);
    printa("FAULTCLASS|new4k|%-8s %12@d\n", @newpgs);
    printa("FAULTCLASS|new16k|%-8s %12@d\n", @newcmps);
    printa("FAULTCLASS|new64k|%-8s %12@d\n", @newwins);

    printf("\nFAULTCLASS|TABLE3 first vs repeat page, per class\n");
    printa("FAULTCLASS|repeat|%-8s %-8s %12@d\n", @refault);

    printf("\nFAULTCLASS|TABLE4 service arm\n");
    printa("FAULTCLASS|deliver|%-22s %12@d\n", @delivered);
    printa("FAULTCLASS|stale_retry|%@d\n", @stale);
    printf("FAULTCLASS|arm|stale_retries=%d|delivered=%d|serviced_by_plan=%d\n",
        stales, delivers, faults - stales - delivers);

    printf("\nFAULTCLASS|TOTALS\n");
    printa("FAULTCLASS|total|faults=%@d\n", @total);
    printa("FAULTCLASS|total|distinct_4k=%@d\n", @totalnewpg);
    printa("FAULTCLASS|total|distinct_16k=%@d\n", @totalnewcmp);
    printa("FAULTCLASS|total|distinct_64k=%@d\n", @totalnewwin);
}
