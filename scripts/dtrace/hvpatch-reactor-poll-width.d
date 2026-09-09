#!/usr/sbin/dtrace -Zs
/*
 * hvpatch-reactor-poll-width.d — is the carrier wait reactor's `poll()` a
 * super-linear term?
 *
 * (a) What it measures. `CarrierWaitServiceInner::run_reactor` rebuilds its
 * `pollfd` array from `state.entries.values()` on EVERY cycle and then calls
 * one host `poll(2)` over the whole array. Both halves are O(live enrolled
 * continuations), and the reactor is one thread per carrier, so N wakes over a
 * population of N cost O(N^2). This script measures the two numbers that decide
 * whether that shape matters on a given workload:
 *   - how many host `poll(2)` calls the carrier makes, and
 *   - the DISTRIBUTION OF nfds (the second argument), i.e. the array width.
 * A workload whose width stays at 1-2 pays nothing; one whose width runs into
 * the hundreds is paying a quadratic tax, and the width histogram says which.
 *
 * The `select`/`kevent` counters are the control: they say whether other host
 * wait mechanisms carry comparable traffic, so a `poll` count is read as a
 * share rather than in isolation.
 *
 * (b) Provider ABI, qualified live on macOS 27.0 / Apple Silicon (t8132):
 *   * `syscall::poll:entry` arg0 = `struct pollfd *`, arg1 = `nfds_t` count,
 *     arg2 = timeout ms. These are the HOST's syscall arguments — the carrier's
 *     own libc call — not a guest syscall; the guest's `poll` is serviced by
 *     carrick and need not lower to a host `poll` at all.
 *   * `syscall:::` is a kernel provider, so `-Z` is not required for it to arm,
 *     but the script is run through `carrick trace`, which spawns the child
 *     after arming; keep `-Z` so the carrick USDT clause (if any is added
 *     later) still matches.
 *   * `carrick*:::hvpatch-reactor-cycle` arg0 = registrations in the whole map,
 *     arg1 = registrations the cycle TOUCHED, arg2 = resulting pollfd width,
 *     arg3 = the poll timeout in ms. `visited` tracking `registrations` is the
 *     O(live blocked tasks) shape; `visited` flat while `registrations` climbs
 *     is the indexed one. `-Z` IS required for this clause.
 *   * EVERY clause carries `pid == $target || progenyof($target)`: this box
 *     routinely runs other agents' guests and a host-wide `syscall::poll` would
 *     aggregate every process on the machine.
 *
 * (c) Perturbation: LOW. One aggregation per host `poll`/`select`/`kevent`
 * entry, no stack walk, no printf. Counts and the width histogram are citable
 * across arms; absolute wall under the script is not.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-reactor-poll-width.d -o out.raw -- \
 *     run --fs host <image> <cmd>
 */

#pragma D option quiet
#pragma D option aggsize=16m

dtrace:::BEGIN
{
	printf("RPW1|armed|target=%d\n", $target);
}

carrick*:::hvpatch-reactor-cycle
/pid == $target || progenyof($target)/
{
	@c["reactor-cycles"] = count();
	@sum["reactor-registrations-total"] = sum((int64_t)arg0);
	@sum["reactor-visited-total"] = sum((int64_t)arg1);
	@w["reactor-registrations-per-cycle"] = quantize((int64_t)arg0);
	@w["reactor-visited-per-cycle"] = quantize((int64_t)arg1);
}

syscall::poll:entry
/pid == $target || progenyof($target)/
{
	@c["host-poll-calls"] = count();
	@sum["host-poll-fds-total"] = sum((int64_t)arg1);
	@w["host-poll-nfds"] = quantize((int64_t)arg1);
	self->poll_ts = timestamp;
}

syscall::poll:return
/(pid == $target || progenyof($target)) && self->poll_ts != 0/
{
	@sum["host-poll-wall-us-total"] = sum((timestamp - self->poll_ts) / 1000);
	self->poll_ts = 0;
	self->poll_ret = timestamp;
	self->poll_vt = vtimestamp;
}

/*
 * The REBUILD window: everything the reactor thread does between one `poll`
 * returning and the next `poll` starting is the poll-set rebuild plus the
 * dispatch of whatever became ready. `vtimestamp` is that thread's on-CPU time
 * only, so it separates "the rebuild burns CPU" (a scan) from "the rebuild
 * waited on a lock". A rebuild that is O(1) shows a flat few microseconds; an
 * O(live blocked tasks) scan shows a wide, right-heavy histogram.
 */
syscall::poll:entry
/(pid == $target || progenyof($target)) && self->poll_ret != 0/
{
	@sum["between-poll-wall-us-total"] = sum((timestamp - self->poll_ret) / 1000);
	@sum["between-poll-oncpu-us-total"] = sum((vtimestamp - self->poll_vt) / 1000);
	@w["between-poll-oncpu-us"] = quantize((vtimestamp - self->poll_vt) / 1000);
	self->poll_ret = 0;
}

syscall::select:entry
/pid == $target || progenyof($target)/
{
	@c["host-select-calls"] = count();
}

syscall::kevent*:entry
/pid == $target || progenyof($target)/
{
	@c["host-kevent-calls"] = count();
}

tick-180sec
{
	exit(0);
}

dtrace:::END
{
	printa("RPW1|count|%s|%@u\n", @c);
	printa("RPW1|total|%s|%@u\n", @sum);
	printa(@w);
}
