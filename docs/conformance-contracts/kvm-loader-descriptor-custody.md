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
wait releases execution capacity. It must join one supply consumer
for guest faults and host copyouts. The historical #1728 reference in the
private-source note does not identify an active dependency; that issue is
closed and concerns bounded image table stock. The initial shared root
constructor currently retains host filesystem authority (`initial.fs = None`);
registering its execution as native does not supply native pathname authority.
That authority must be selected explicitly, not replaced with a guessed
`/` or root credentials. X86 `fstat` and `newfstatat` also require their Linux
ABI layouts at the shared personality boundary.

This binding is red-first evidence, not a loader fix. Private-source tests
alone do not prove any of these service, contention or loader obligations.
No runtime ratio or ecosystem scoreboard improvement is established.

## Root authority decision before the first implementation slice

`root_exec_access_refusal_is_counted_before_service_publication` now starts
with the production root constructor and `register_root`, without assigning
a fixture cwd. Calling `begin_host_file_service` for an open returns errno
38 with no service notice or handoff. The production guard is correct: this
row has no pathname authority. Simply wiring the loader into this entry does
not solve open/close/reopen.

Two ownership choices need review before changing that contract:

- Preserve host-root resource custody independently of native execution
  custody, and consistently use the shared ARM host-root mutation owner.
  Descriptor cleanup must authenticate the exact slot/description; deleting
  whichever host slot occupies a reused number is not valid.
- Transfer the root's exact filesystem context, credentials, groups, umask
  and resource limits to the ring owner at admission, then bind its retained
  host-file service as for native children. This fits the desired native
  route, but requires an explicit authority-transfer interface before code.

The existing `RootForkSeed` is intentionally a live cwd/root snapshot for a
host root's child. It neither transfers the root's authority nor supplies its
credential and resource-limit state, so repurposing it silently would not
implement the second choice. A synchronous bridge cannot substitute for that
decision or for the retained native-service consumer.

## Selected correction: separate host-root resource custody

The director selected option A for this slice; option B is separate work in
#1861. Native execution registration must not imply ownership of the root's
filesystem, credentials, supplementary groups, umask or resource limits.
The host retains those resources. Open must install into the ring descriptor
namespace that close already owns, using the shared native host-file service.
Stat layouts and the remaining loader calls are later slices.

The red witness was rerun after rebasing onto current main. The native
control passed; KVM again returned 16 after four guest entries, with two host
opens and zero guest refusals. No implementation correction or green result
is established by that rebase.

The general retained service consumer also needs a CPL0 binding:
`NativeProcessEntry::begin_host_file_service` publishes an authenticated
service notice and retains its request, while the current carrier intake
and completion implementation lives in the HVF adapter's `native_service`
module. CPL0's `capture_host_file` deliberately accepts only synchronous
MapPrivate records. Widening that transport to open would not satisfy the
required retained-service binding. The shared intake must preserve exact
member/MM authentication, metadata retention, cancellation exclusion,
completion publication and waiter notification, outside physical custody.

## Step 2: retained CPL0 service binding

The open/close/reopen binding is now green on real KVM: three pairs reuse
one ring descriptor, the guest exits 0 after seven entries, and no guest
refusals are recorded. The stacked pre-routing control returned 16 after
four entries and two host forwards. These are focused descriptor-custody
results, not a claim that the complete Ubuntu loader works.

Both payload descriptors expose `ring_storage()` for carrier authentication
of supervisor staging. The shared ring entry publishes host-root records
without access-context stamping when the admitted root still has no ring
filesystem. Its existing stamped entry continues to refuse that root. Write
(including staged writev) and chdir remain refused by the new host-root entry.

CPL0 claims the existing native service notice and retains its ticket with
RAM custody. File I/O executes after dropping physical custody and the CPU-I/O
borrow. Completion reauthenticates the stopped context and staging, writes the
reply before ACK, and counts genuine carrier refusal without publishing a
reply. MapPrivate stays on its existing HostFileCrossing transport.

The runtime selects host-root resources for Initial service origins and
native authority for Descendant origins. CPL0 admits only Openat, Faccessat and Statx to shared staging. Descriptor-based
Read, Pread, Lseek and Getdents64 retain their existing routes, including for
ring-opened descriptors; binding those descriptors is slice 3. Legacy stat
layouts, write/FSIZE and staging-fault supply remain later work. The
director-owned crossing policy is unchanged.

The first full regression run exposed the planned Pread admission as a
regression: `private_file_write_preserves_source_bytes` returned exit 33, and
a bounded fixture reduction observed errno 38 from pread64 instead of one
byte. The stacked baseline passed twice. The director therefore narrowed
this slice to the three pathname calls above, rather than expand read/output
preparation or introduce a fallback for open. The diagnostic fixture and the
speculative copyout binding were removed. The narrowed regression results
are recorded on the draft PR.

After narrowing, the full KVM target passes 43 tests with zero failures,
one existing ignore and the requested child-retirement exclusion. This
includes every private-file case, all eight getrandom cases and reopen.
The exact reopen command also passes separately. The native EL1 lib suite
passes 779 tests; its three existing ignores are unchanged.

The release Ubuntu `/bin/true` run still exits 127. Its complete terminal
refusal census contains exactly one refusal: writev, x86 native ordinal 20
(canonical 66), in the root ring venue. Thus writev is the first recorded
refusal, not a claim about the first failing syscall. Faccessat and openat
record no refusals. Scoped cleanup finds no remaining processes. The
remaining fd-based loader reads are deliberately not routed in this slice.
