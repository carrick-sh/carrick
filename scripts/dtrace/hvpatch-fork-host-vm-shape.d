#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-host-vm-shape.d — count the host virtual-memory operations
 * induced by a guest fork()+_exit()+waitpid() loop, grouped by byte length and
 * madvise operation.
 *
 * This answers whether rapid-exit children allocate and discard fixed-size
 * Carrick metadata arenas rather than recycling them. It complements
 * hvpatch-fork-host-syscall-callers.d without taking a user stack on every
 * call, so the LTP fork14 loop can finish inside its own 30 second bound.
 *
 * Provider ABI qualified live on Darwin/arm64 (macOS 27.0, 2026-09-18):
 * syscall::mmap:entry, syscall::munmap:entry and syscall::madvise:entry expose
 * length as arg1; madvise exposes advice as arg2. Carrick's host-image-base
 * and fork-runtime-stage probes follow the carrier when the launcher has
 * children. Phase 9 fires once for every completed in-process fork.
 *
 * Perturbation: LOW — aggregate increments on three host syscall entry paths.
 * Counts are work receipts only; elapsed time under this script is not a
 * performance result. Zero forks or zero VM calls is an instrument failure.
 */

#pragma D option quiet
#pragma D option aggsize=16m

dtrace:::BEGIN
{
	started = timestamp;
	forks = 0;
	vm_calls = 0;
	bounded = 0;
	errors = 0;
}

carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
	printf("HVPATCHFORKVMSHAPE|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
	    (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 == 9/
{
	forks++;
}

syscall::mmap:entry
/pid == $target || progenyof($target)/
{
	vm_calls++;
	@mmap_by_len[(uint64_t)arg1] = count();
}

syscall::munmap:entry
/pid == $target || progenyof($target)/
{
	vm_calls++;
	@munmap_by_len[(uint64_t)arg1] = count();
}

syscall::madvise:entry
/pid == $target || progenyof($target)/
{
	vm_calls++;
	@madvise_by_len_advice[(uint64_t)arg1, (int)arg2] = count();
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
/timestamp - started > 120 * 1000000000/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCHFORKVMSHAPE|summary|forks=%d|vm_calls=%d|bounded=%d|errors=%d\n",
	    forks, vm_calls, bounded, errors);
	printa("HVPATCHFORKVMSHAPE|mmap|len=%llu|count=%@u\n", @mmap_by_len);
	printa("HVPATCHFORKVMSHAPE|munmap|len=%llu|count=%@u\n", @munmap_by_len);
	printa("HVPATCHFORKVMSHAPE|madvise|len=%llu|advice=%d|count=%@u\n",
	    @madvise_by_len_advice);
}
