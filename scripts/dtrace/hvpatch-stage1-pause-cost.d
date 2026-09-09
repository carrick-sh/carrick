#!/usr/sbin/dtrace -Zs
/*
 * hvpatch-stage1-pause-cost.d — what does the stage-1 Pause-Modify-Resume
 * COST, and which guest syscall pays it?
 *
 * (a) What it measures. `hvpatch-stop-the-world.d` answers "does carrick raise
 * the barrier at all" — a decision count. It cannot say whether the barrier is
 * a perf term, because a raise that drains in 2 us and a raise that spins for
 * 400 us are one row there. This script answers the cost question instead:
 *   - drain spin count and drain wall per raise (`pt-pause-ready` arg1/arg2),
 *   - the same, keyed by the LINUX SYSCALL NUMBER whose service raised it,
 *     so "the Go heap's mmap churn stops the world N times per second" is a
 *     measurement rather than an inference,
 *   - the held duration (ready -> end on the coordinator's own host thread),
 *   - the executor census the raise was keyed on (`pt-pause-begin` arg3), which
 *     separates "one other thread" from "eight".
 *
 * Read it with the totals: sum(drain_us) + sum(held_us) is the carrier time the
 * pause owns, and `raises-by-syscall` names the service to fix.
 *
 * (b) Provider ABI, qualified live on macOS 27.0 / Apple Silicon (t8132),
 * release build with `__DATA,__dof_carrick` present:
 *   * USDT `__` lowers to `-`: `carrick*:::pt-pause-ready`, never
 *     `pt__pause__ready`. The underscore spelling lists nothing and reports a
 *     silent zero.
 *   * `-Z` is REQUIRED — the carrier is spawned after dtrace arms.
 *   * EVERY clause carries `pid == $target || progenyof($target)`:
 *     `carrick*:::` matches every carrick process on the host and this box
 *     routinely runs other agents' guests.
 *   * `pt-pause-begin`  (coordinator_tid i32, other_in_guest i32,
 *                        waiting_sibling_tid i32, executor_census i32).
 *   * `pt-pause-ready`  (tid i32, spins i32, wait_us i64).
 *   * `pt-pause-end`    (tid i32).
 *   * `hvpatch-syscall-service-begin` (guest_pid i32, guest_tid i32, asid u32,
 *     linux_nr u64). HVPatch runs one host pthread per logical guest thread, so
 *     `self->` pairing from service-begin to the pause raised inside that
 *     service is sound on the same host thread.
 *
 * (c) Perturbation. LOW for the pause aggregations — every pt-pause probe sits
 * on a path that already costs microseconds. The `hvpatch-syscall-service-begin`
 * clause is per-guest-syscall but stores one scalar and prints nothing, which
 * is far cheaper than the printf-per-syscall tracers; still, absolute wall for
 * the traced run is not citable, only same-instrument shares and counts.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-stage1-pause-cost.d -o out.raw -- \
 *     run --fs host -w /usr/local/go/src/go/types \
 *     localhost:5005/carrick-go-conformance:1.24 /conformance/go_types.test \
 *     -test.run Test -test.short
 */

#pragma D option quiet
#pragma D option aggsize=32m
#pragma D option bufsize=8m

dtrace:::BEGIN
{
	printf("PTCOST1|armed|target=%d\n", $target);
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
	self->nr = (uint64_t)arg3;
}

carrick*:::pt-pause-begin
/pid == $target || progenyof($target)/
{
	@c["raises"] = count();
	@census["executor-census-at-raise"] = quantize((int32_t)arg3);
	self->raised = 1;
}

carrick*:::pt-pause-begin
/(pid == $target || progenyof($target)) && arg1 != 0/
{
	@c["raises-with-sibling-in-guest"] = count();
}

carrick*:::pt-pause-ready
/pid == $target || progenyof($target)/
{
	@c["ready"] = count();
	@sum_us["drain-us-total"] = sum((int64_t)arg2);
	@sum_us["drain-spins-total"] = sum((int32_t)arg1);
	@q["drain-us"] = quantize((int64_t)arg2);
	@q["drain-spins"] = quantize((int32_t)arg1);
	@bysc_n[self->nr] = count();
	@bysc_us[self->nr] = sum((int64_t)arg2);
	self->ready_ts = timestamp;
}

carrick*:::pt-pause-end
/(pid == $target || progenyof($target)) && self->ready_ts != 0/
{
	@c["released"] = count();
	@sum_us["held-us-total"] = sum((timestamp - self->ready_ts) / 1000);
	@q["held-us"] = quantize((timestamp - self->ready_ts) / 1000);
	@bysc_held_us[self->nr] = sum((timestamp - self->ready_ts) / 1000);
	self->ready_ts = 0;
}

/* MUST stay zero. */
carrick*:::pt-pause-timeout
/pid == $target || progenyof($target)/
{
	@c["drain-TIMEOUT"] = count();
}

carrick*:::pt-pause-election-timeout
/pid == $target || progenyof($target)/
{
	@c["election-TIMEOUT"] = count();
}

dtrace:::END
{
	printf("PTCOST1|counts\n");
	printa("PTCOST1|count|%s|%@u\n", @c);
	printf("PTCOST1|totals\n");
	printa("PTCOST1|total|%s|%@u\n", @sum_us);
	printf("PTCOST1|raises-by-syscall (nr, count)\n");
	printa("PTCOST1|bysc-n|nr=%u|%@u\n", @bysc_n);
	printf("PTCOST1|drain-us-by-syscall (nr, us)\n");
	printa("PTCOST1|bysc-drain-us|nr=%u|%@u\n", @bysc_us);
	printf("PTCOST1|held-us-by-syscall (nr, us)\n");
	printa("PTCOST1|bysc-held-us|nr=%u|%@u\n", @bysc_held_us);
	printf("PTCOST1|distributions\n");
	printa(@q);
	printa(@census);
}
