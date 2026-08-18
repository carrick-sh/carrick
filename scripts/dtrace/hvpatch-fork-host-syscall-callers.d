#!/usr/sbin/dtrace -qs
/*
 * hvpatch-fork-host-syscall-callers.d — attribute the host syscalls a guest
 * fork()+_exit()+waitpid() round trip induces to their exact Carrick user
 * stacks.
 *
 * hvpatch-fork-wait-amplification.d ranks the induced host syscalls but cannot
 * say WHO issues them. A bare fork/exit/reap loop touches no files and
 * allocates no guest memory, so every `openat`, `stat64`, `unlink`,
 * `getentropy`, `madvise`, `mmap` and `munmap` it provokes is carrick's own
 * host-side lowering and is therefore removable in principle. This script
 * names the caller of each so the removal can be aimed.
 *
 * Provider ABI qualified live on Darwin/arm64 (macOS 27.0, 2026-08-18):
 * - the `syscall` provider's entry probes run on Carrick's own restored host
 *   stack, so ustack() is authoritative for the user caller;
 * - carrick*:::host-image-base(host_pid, runtime_TEXT_base, slide, path)
 *   publishes the exact Mach-O identity before the guest loads, so an offline
 *   `atos` resolution cannot silently use a different build;
 * - the predicate follows Carrick descendants because a raw HVPatch run may
 *   place the VM carrier in a child of the launched process.
 *
 * Perturbation: VERY HIGH — a 32-frame user stack on every matched host
 * syscall. Only caller SHARES and RANKS are citable; elapsed time under this
 * script is not, and the untraced reducer stays the performance gate. A
 * capture with zero stacks is an instrument failure, not an empty result.
 */

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=128m
#pragma D option dynvarsize=64m
#pragma D option ustackframes=32
#pragma D option strsize=16k

dtrace:::BEGIN
{
	started = timestamp;
	stacks = 0;
	bounded = 0;
	errors = 0;
}

carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
	printf("HVPATCHFORKCALLER|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
	    (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

syscall::madvise:entry,
syscall::mmap:entry,
syscall::munmap:entry,
syscall::mprotect:entry,
syscall::getentropy:entry,
syscall::stat64:entry,
syscall::openat:entry,
syscall::unlink:entry,
syscall::fcntl:entry,
syscall::read:entry,
syscall::write:entry,
syscall::close:entry,
syscall::thread_selfusage:entry,
syscall::sigaltstack:entry
/pid == $target || progenyof($target)/
{
	stacks++;
	@by_caller[probefunc, ustack()] = count();
	@by_name[probefunc] = count();
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
/timestamp - started > 600 * 1000000000/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCHFORKCALLER|summary|stacks=%d|bounded=%d|errors=%d\n",
	    stacks, bounded, errors);
	printa("HVPATCHFORKCALLER|name|%s|%@u\n", @by_name);
	printf("HVPATCHFORKCALLER|callers\n");
	trunc(@by_caller, 40);
	printa("HVPATCHFORKCALLER|caller|%s|%@u|%k\n", @by_caller);
}
