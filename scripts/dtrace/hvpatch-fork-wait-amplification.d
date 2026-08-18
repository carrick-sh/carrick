#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-wait-amplification.d — how much host work ONE guest
 * fork()+_exit()+waitpid() round trip costs, expressed as COUNTS.
 *
 * Counts are load-invariant, which is the point: on a contended host the wall
 * and CPU figures for a fork reducer move by 4x between runs, but "how many
 * frame-COW copies, stage-2 edits, guest faults, guest syscalls and host
 * syscalls does one guest fork+wait cost" does not. Ranking work by the
 * amplification factor of a single guest operation is this tree's stated
 * method; this script supplies that ledger for the fork/reap cycle the same
 * way the fs and build ledgers supply it for open/stat.
 *
 * Divide each total by `forks` to read it per round trip.
 *
 * Provider ABI qualified live on Darwin/arm64 (macOS 27.0, 2026-08-18):
 *   carrick*:::hvpatch-fork-runtime-stage arg0 == 9 fires exactly once per
 *     COMPLETED in-process fork and carries the cumulative parent critical
 *     section in arg4; it is the cycle counter here, not a timing source.
 *   carrick*:::hvpatch-frame-cow-copy fires once per fork-COW frame split.
 *   carrick*:::hvpatch-global-frame-stage2 arg0 is 0 for map and 1 for unmap
 *     of an HVPatch physical extent.
 *   carrick*:::hvpatch-guest-fault fires per guest-visible stage-1 fault.
 *   carrick*:::vcpu-trap fires per host-dispatched guest syscall.
 *   carrick*:::vcpu-kick fires per cross-thread vCPU kick.
 *   carrick*:::pt-pause-begin fires per stop-the-world page-table pause.
 * The predicate follows Carrick descendants: a raw HVPatch run may place the
 * VM carrier in a child of the launched process.
 *
 * Perturbation: one aggregation update per counted event. Counts and their
 * ratios are citable; wall time under this script is NOT, and the untraced
 * reducer remains the performance gate. A capture with zero forks is an
 * instrument failure, not an empty result.
 */

#pragma D option quiet
#pragma D option bufsize=16m

dtrace:::BEGIN
{
	started = timestamp;
	forks = 0;
	bounded = 0;
	errors = 0;
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 == 9/
{
	forks++;
}

carrick*:::hvpatch-frame-cow-copy
/pid == $target || progenyof($target)/
{
	@cow_copies = count();
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target)) && arg0 == 0/
{
	@stage2_maps = count();
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target)) && arg0 == 1/
{
	@stage2_unmaps = count();
}

carrick*:::hvpatch-guest-fault
/pid == $target || progenyof($target)/
{
	@guest_faults = count();
}

carrick*:::vcpu-trap
/pid == $target || progenyof($target)/
{
	@guest_syscalls = count();
}

carrick*:::vcpu-kick
/pid == $target || progenyof($target)/
{
	@vcpu_kicks = count();
}

carrick*:::pt-pause-begin
/pid == $target || progenyof($target)/
{
	@pt_pauses = count();
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
	@io_waits = count();
}

syscall:::entry
/pid == $target || progenyof($target)/
{
	@host_syscalls = count();
	@host_by_name[probefunc] = count();
}

dtrace:::ERROR
{
	errors++;
}

proc:::exit
/pid == $target/
{
	exit(0);
}

profile:::tick-1sec
/timestamp - started > 300 * 1000000000/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCHFORKAMP|summary|forks=%d|bounded=%d|errors=%d\n",
	    forks, bounded, errors);
	printa("HVPATCHFORKAMP|cow-copies|%@u\n", @cow_copies);
	printa("HVPATCHFORKAMP|stage2-maps|%@u\n", @stage2_maps);
	printa("HVPATCHFORKAMP|stage2-unmaps|%@u\n", @stage2_unmaps);
	printa("HVPATCHFORKAMP|guest-faults|%@u\n", @guest_faults);
	printa("HVPATCHFORKAMP|guest-syscalls|%@u\n", @guest_syscalls);
	printa("HVPATCHFORKAMP|vcpu-kicks|%@u\n", @vcpu_kicks);
	printa("HVPATCHFORKAMP|pt-pauses|%@u\n", @pt_pauses);
	printa("HVPATCHFORKAMP|io-waits|%@u\n", @io_waits);
	printa("HVPATCHFORKAMP|host-syscalls|%@u\n", @host_syscalls);
	printf("HVPATCHFORKAMP|host-by-name\n");
	printa("HVPATCHFORKAMP|host|%s|%@u\n", @host_by_name);
}
