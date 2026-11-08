# KVM loader descriptor custody (#1714)

The production `cpl0_initial_mm` binding
`serial_host_loader_open_close_reopen_uses_one_native_descriptor_namespace`
reduces the glibc loader's first failing operation to three read-only
`openat`/`close` pairs. Each successful open must reuse the descriptor just
closed. Its bounded native Linux control runs the same ELF against the same
file. The guest returns a failing open's errno as its exit status, 42 for a
failed close, and 43 for a descriptor-reuse mismatch. The initial KVM result
is **16**, on the second open; the native control succeeds.

The real Ubuntu loader reaches the same failure: opening `/etc/ld.so.cache`
returns descriptor 3, `fstat` succeeds, private mapping supply succeeds, and
`close` succeeds. Opening `/lib/x86_64-linux-gnu/libc.so.6` then returns
`EBUSY` (16). Missing hardware-capability subdirectories produce `ENOENT`
(2), and the final libc open again returns 16. The loader exits 127. The
complete refusal census also records `writev` (native 20), hiding its error
message; the host adapter refuses legacy `access` (native 21) separately.
Those refusals do not explain the reproduced open/close failure: the reduced
binding has zero guest refusals and still returns 16.

## Ownership mismatch

CPL0 registers the initial execution record with the shared native process
registry. The descriptor family consequently closes the published ring
namespace. Its `openat` still crosses as a raw syscall into the initial host
`KernelContext`, installing a host `FileTable` slot and its IPC projection.
After the ring close, the shared allocator can reserve descriptor 3 again,
but `FileTable::commit_reserved_slot` correctly rejects the still-occupied
host slot. Dropping that check or guessing a different descriptor would hide
the split ownership rather than repair it.

ARM's native host-file route stages `HostFileCall` through
`native_host_file_stage`, retains it with
`NativeProcessEntry::begin_host_file_service`, and serves its typed record
through `SyscallDispatcher::serve_native_host_file`. `NativeOpenSink` installs
only in the caller's ring table. Its close therefore does not leave a host
numeric descriptor slot behind. Host-owned ARM root records retain their
existing host mutation authority.

## Required service binding

The correction must bind CPL0 to that shared service owner rather than add
an x86 open implementation, reconcile numeric slots heuristically, widen the
host crossing allowlist, or treat EBUSY as a retryable syscall result.

The current synchronous `HostFileCrossing` transport admits **MapPrivate
only**. It is a retained byte-source transport, not the general native file
service consumer. General service admission must preserve the exact request,
caller filesystem/credential authority, and completed output while an owner
wait releases execution capacity. It must join the same supply consumer
used for guest faults and host copyouts (#1728). The initial shared root
constructor currently retains host filesystem authority (`initial.fs = None`);
registering its execution as native does not supply native pathname authority.
That authority must be transferred explicitly, not replaced with a guessed
`/` or root credentials. X86 `fstat` and `newfstatat` also require their Linux
ABI layouts at the shared personality boundary.

This binding is red-first evidence, not a loader fix. Private-source tests
alone do not prove any of these service, contention or loader obligations.
No runtime ratio or ecosystem scoreboard improvement is established.
