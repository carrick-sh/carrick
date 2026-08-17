#!/usr/sbin/dtrace -Zs
/*
 * hvpatch-stop-the-world.d — does carrick RAISE its stop-the-world barrier?
 *
 * (a) What it measures
 *     Carrick has two independent process-wide barriers, and this script
 *     separates the DECISION TO RAISE one from the DRAIN that follows it:
 *
 *       pt-pause-*            the stage-1 page-table Pause-Modify-Resume.
 *                             `pt-pause-begin` fires only when an editor
 *                             actually became coordinator, so its COUNT is the
 *                             raise decision. arg1 (`others_in_guest`) and arg2
 *                             (`leases`) are the drain's inputs; arg3
 *                             (`executors`) is the population the raise is
 *                             keyed on.
 *       hvpatch-fork-quiesce  fires UNCONDITIONALLY at the end of the HVPatch
 *                             in-process fork quiesce phase, whether or not the
 *                             barrier went up. arg2 is `initial_siblings`, the
 *                             lease count the raise decision was keyed on, so a
 *                             row with arg2 == 0 is a fork that ran with NO
 *                             barrier.
 *       fork-quiesce          the legacy libc::fork lane's equivalent; arg0 is
 *                             the phase (0 = entry), arg1 the sibling count.
 *
 *     Because `hvpatch-fork-quiesce` is unconditional, the fork lane yields a
 *     POSITIVE measurement of a missing barrier (N forks, all siblings=0)
 *     rather than an absence. `pt-pause-begin` is conditional by construction,
 *     so its zero MUST be read against a positive control in the same
 *     experiment — see `fixtures/pt-barrier/stop_the_world.c`, whose `spin`
 *     mode holds the sibling in guest and therefore must make it fire.
 *
 * (b) Provider ABI facts qualified live on this host
 *     macOS 27.0 / Apple Silicon (t8132), carrick release build with
 *     `__DATA,__dof_carrick` present (`otool -l target/release/carrick | grep dof`).
 *       * USDT names lower `__` to `-`: the probe is `carrick*:::pt-pause-begin`,
 *         NOT `pt__pause__begin`. Spelling it with underscores lists nothing and
 *         silently reports zero.
 *       * `-Z` is REQUIRED. The guest carrier is spawned after dtrace arms, so
 *         without it every probe fails to match and the script exits.
 *       * The provider is `carrick<pid>`, hence the `carrick*:::` glob. Do NOT
 *         screen on `execname`: a carrier can be re-execed under another name.
 *       * EVERY clause MUST carry `pid == $target || progenyof($target)`.
 *         `carrick*:::` matches every carrick process on the host, and this
 *         box routinely has other agents' conformance guests running. Without
 *         the screen a `spin mmap 300` arm that should raise 901 pauses read
 *         7,799 pauses and 727 forks — a sibling worktree's `carrick-conformance
 *         --tier smoke --workers 3` bleeding straight into the aggregation.
 *         `carrick trace` spawns the traced command, so `$target` is the
 *         `carrick run` it launched; `progenyof` follows the carrier and any
 *         helper it forks.
 *       * `pt-pause-begin` args are
 *         (tid, others_in_guest, leases, executors) as i32. `leases` is the
 *         vCPU-registry count and `executors` the guest-executor census; a row
 *         with leases == 1 and executors > 1 is a pause the historical
 *         lease-keyed predicate would have skipped.
 *       * `hvpatch-fork-quiesce` args are
 *         (parent_pid i32, forking_tid i32, initial_siblings u32,
 *          poll_iterations u64, elapsed_ns u64).
 *
 * (c) Perturbation
 *     Negligible. Every probe here is on a stop-the-world path that already
 *     costs microseconds to milliseconds, and none is on a per-syscall or
 *     per-instruction path. Counts are safe to compare across arms; the
 *     elapsed-ns quantisation is same-instrument only.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-stop-the-world.d -o out.raw -- \
 *     run -v <dir>:/f ubuntu:24.04 /f/stop_the_world park mmap 400
 */

#pragma D option quiet
#pragma D option aggsize=8m

/*
 * The target screen `pid == $target || progenyof($target)` is repeated in full
 * on every clause rather than hidden behind a `#define`: cpp runs only under
 * `dtrace -C`, which `carrick trace -s` does not pass, so a macro would fail to
 * compile. `carrick*:::` matches EVERY carrick process on the host — including
 * other agents' conformance guests — so an unscoped clause silently aggregates
 * someone else's workload into your arm.
 */

dtrace:::BEGIN
{
	printf("hvpatch-stop-the-world: armed on target %d\n", $target);
}

/*
 * Every aggregation is STRING-KEYED so dtrace's own end-of-run dump carries the
 * label. An END clause is not reliable here: `carrick trace` tears the consumer
 * down with the guest, and a run that loses END would print bare numbers whose
 * identity a reader has to guess.
 */

/*
 * The page-table barrier was RAISED. One firing == one Pause-Modify-Resume
 * transaction that actually stopped the world.
 */
carrick*:::pt-pause-begin
/pid == $target || progenyof($target)/
{
	@c["pt-raised"] = count();
}

/*
 * One aggregation name carries ONE action in D: mixing `count()` and `sum()`
 * under `@c` is a compile error ("aggregation redefined"), so each split is a
 * predicated count rather than a summed ternary.
 */
carrick*:::pt-pause-begin
/(pid == $target || progenyof($target)) && arg1 != 0/
{
	@c["pt-raised-with-sibling-in-guest"] = count();
}

/*
 * THE DEFECT, made positive: a pause taken while the vCPU registry held only
 * this thread's lease. Every one of these is an edit the lease-keyed predicate
 * would have run with the barrier down, against a sibling parked in a futex /
 * epoll / fd wait that a host wake can return to guest at any moment.
 */
carrick*:::pt-pause-begin
/(pid == $target || progenyof($target)) && arg2 <= 1 && arg3 > 1/
{
	@c["pt-raised-LEASES-WOULD-HAVE-MISSED"] = count();
}

carrick*:::pt-pause-ready
/pid == $target || progenyof($target)/
{
	@c["pt-ready"] = count();
}

carrick*:::pt-pause-end
/pid == $target || progenyof($target)/
{
	@c["pt-released"] = count();
}

/* MUST stay zero: the coordinator failed to drain its siblings. */
carrick*:::pt-pause-timeout
/pid == $target || progenyof($target)/
{
	@c["pt-drain-TIMEOUT"] = count();
}

/*
 * MUST stay zero in a healthy run: this thread gave up waiting for the current
 * coordinator. A nonzero rate after a barrier-widening change is the expected
 * shape of a new ABBA, or of contention pushed past the 30 s election bound.
 */
carrick*:::pt-pause-election-timeout
/pid == $target || progenyof($target)/
{
	@c["pt-election-TIMEOUT"] = count();
}

/*
 * Unconditional: every HVPatch in-process fork reports here whether or not the
 * barrier went up. arg2 is the sibling population the raise decision used, so
 * splitting on it turns "no barrier" into a POSITIVE count instead of an absent
 * probe.
 */
carrick*:::hvpatch-fork-quiesce
/pid == $target || progenyof($target)/
{
	@c["fork-total"] = count();
}

carrick*:::hvpatch-fork-quiesce
/(pid == $target || progenyof($target)) && arg2 == 0/
{
	@c["fork-UNBARRIERED"] = count();
}

carrick*:::hvpatch-fork-quiesce
/(pid == $target || progenyof($target)) && arg2 > 0/
{
	@c["fork-barriered"] = count();
}

/* Legacy libc::fork lane, phase 0 (entry). arg1 is the sibling count. */
carrick*:::fork-quiesce
/(pid == $target || progenyof($target)) && arg0 == 0/
{
	@c["legacy-fork-total"] = count();
}

carrick*:::fork-quiesce
/(pid == $target || progenyof($target)) && arg0 == 0 && arg1 == 0/
{
	@c["legacy-fork-UNBARRIERED"] = count();
}
