/*
 * hvpatch-fs-op-callers.d — WHICH carrick code issues the host syscalls
 * inside one guest fs syscall's service window?
 *
 * Companion of hvpatch-fs-op-ledger.d: the ledger says HOW MANY host calls
 * of each name a guest `unlinkat`/`openat` costs; this script says WHO issues
 * them, so an amplification (12 host `openat` per guest `unlinkat`) can be
 * charged to the exact Rust frames (cap-std component walks, whole-file
 * `lookup` reads, DAC metadata probes) instead of guessed at.
 *
 * (a) WHAT IT MEASURES. For host syscalls named in $$2 (default: openat)
 *     issued while a guest syscall named $$1 (default: unlinkat) is in
 *     flight on the same vCPU pthread, aggregate by user stack (16 frames):
 *       @callers[guest, host, ustack]  count
 *     A frame set that appears N times per guest call is N host calls of
 *     that shape per guest call.
 *
 * (b) PROVIDER ABI FACTS (qualified on macOS 27 / Apple Silicon, 2026-09-01).
 *     - `carrick*:::syscall-entry` arg1 is the guest syscall NAME; the
 *       matching `syscall-return` fires on the same pthread (self-> pairing).
 *     - `ustack()` needs frame pointers; the shipped `just build` binary keeps
 *       them (release profile), so carrick and cap-std frames symbolize.
 *       Frames inside the JIT / MAP_JIT cache print as raw addresses.
 *     - macOS spells the host probes `open_nocancel`, `close_nocancel`,
 *       `fstatat64`, `getdirentries64`; pass the macOS spelling in $$2.
 *
 * (c) PERTURBATION: YES, heavy -- a ustack per matched host call. Only the
 *     per-guest-call COUNTS by frame set are citable, never the timing.
 *     Bounded at 120 s.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-fs-op-callers.d -- run ...
 *   sudo dtrace -q -s scripts/dtrace/hvpatch-fs-op-callers.d unlinkat openat -c "<command>"
 */
#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=64m
#pragma D option strsize=128
#pragma D option defaultargs
#pragma D option ustackframes=16

dtrace:::BEGIN
{
	guest_want = $$1 != "" ? $$1 : "unlinkat";
	host_want = $$2 != "" ? $$2 : "openat";
	secs = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && copyinstr(arg1) == guest_want/
{
	self->in = 1;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->in/
{
	self->in = 0;
	@calls = count();
}

syscall:::entry
/(pid == $target || progenyof($target)) && self->in && probefunc == host_want/
{
	@callers[guest_want, probefunc, ustack()] = count();
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= 120/
{
	printf("section=truncated after %d s\n", secs);
	exit(2);
}

dtrace:::END
{
	printf("section=guest-calls\n");
	printa("calls=%@d\n", @calls);
	printf("section=callers\n");
	printa("guest=%s host=%s count=%@d%k\n", @callers);
}
