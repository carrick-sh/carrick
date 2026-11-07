# Native file staging must retain descriptor admission

Issue #1694, Bet 6 slice 3, extends `kernel.native.host-file-venue` and
`kernel.memory.owner-wait`. This is an implementation design, not passing
retention evidence. The existing input outcome changes do not close this
contract.

Linux `write(2)` and `writev(2)` act on the admitted open description. A
Carrick-internal memory wait must not admit the numeric descriptor again.
The same rule applies when preparing `read(2)` and `readv(2)` destinations.
Only `CopyOutcome::Fault` becomes errno 14; `NotYet` retains the operation
and uses the existing owner-memory notification and rerun protocol.

## Two admission boundaries currently remain

`native_host_file_stage` resolves the descriptor through
`ipc::native_descriptor`, which reads the table without owning a pin. Its
`HostFileStage::Fault` result reaches the native service fault adapter,
which retains the syscall frame and reruns staging after supply. Closing
and reusing the number during that wait changes the next lookup.

The carrier then calls `HostIpc::with_pinned_host_resource` in
`serve_native_host_file_in`. That helper creates a new pin from the record's
table and numeric fd. Retaining a pin only in the ring is insufficient:
the carrier must serve the admitted description too.

## Ownership change required before claiming closure

1. Pin through `carrick_fd_core::Authority::pin` before any potentially
   suspending input gather or output preparation. Check access against that
   pinned description. Keep the owned `OfdPin` in exact-task pending state,
   outside the temporary dispatch entry. Re-entry takes that state before
   consulting a numeric fd. A reference-count observation is not ownership.
2. Extend the typed host-file record to identify the retained pin using its
   authority, index and generation. Define the record layout in
   `carrick-core-abi`, with layout tests and independent review before code
   changes. Do not hide the identity in untyped operation argument words or
   add a service-time numeric-fd fallback. Path-only operations need no pin.
3. Authenticate the retained pin with `Authority::pinned` at carrier service,
   resolve its `IpcBacking::Host` resource, and run the existing resource
   operation. Reuse the resource lookup and release code in `el1_ipc` rather
   than duplicating it. The published service record borrows this identity;
   it must not manufacture a second owner with `OfdPin::from_raw`.
4. Keep ownership until carrier completion or cancellation acknowledgement.
   Release exactly once on every terminal path. A final host-backed release
   belongs to the existing host cleanup authority; the ring-only IPC
   `release_pin` helper cannot finalize it. No editor or copy permit survives
   a memory wait.
5. Retain the gathered input and byte cursor across subsequent refusals.
   A refused piece has no host effect; a completed piece is never replayed.
   Use the existing neutral `UserCopy` and `CopyOutcome` throughout the file
   and delegation adapters, with ISA code limited to access mechanics.

This changes a crossing record, so the wire-layout design requires its own
review under AGENTS.md. It does not require a second copy outcome or a new
wait protocol. The ordinary file delegation adapters are shared with x86;
an ARM-only staging test does not qualify that shared surface.

## Required production witnesses

Use the VM-free EL1 native-process harness and production dispatch, owner
wait and carrier service entries. For `write` and `writev`, refuse one valid,
read-only lazy source piece, observe the owner park, close/reuse the original
numeric fd, release the owner, and resume. Require the original pin identity,
exactly one copy of the expected bytes in the original description, and no
bytes in the replacement. Exercise a later vector/piece too, so a successful
prefix cannot be replayed. For `read` and `readv`, refuse destination
preparation and require the same description and cursor on resumption.

Count one enrollment and one successful completion, and verify pin retirement
after completion and fatal cancellation. Bound actor coordination waits. Run
each witness red on the pre-fix production implementation, then green; a
direct call to the staging helper cannot prove these ownership transitions.
The existing adapter classification tests remain useful but are not these
witnesses. Signed and Docker evidence remain separate higher-layer gates.

## Borrowed-pin API checkpoint

`OfdPin::identity` now lends an `OfdPinIdentity`, which can authenticate a
lookup through `Authority::pinned_identity` without manufacturing ownership.
`HostIpc::with_retained_host_resource` uses that lookup and the existing host
resource table. `release_host_pin` shares the existing final backing release
authority with numeric admission. The borrowed key cannot be passed to
`unpin`; the owned pin must remain live through every borrower.

The fd-core binding closes/reuses the numeric descriptor and checks the
original description, unchanged hold count, foreign authority, oversized
index, retirement and generation reuse. The carrier binding writes the
original host resource after numeric reuse, checks the replacement remains
empty, and counts exactly one final release per resource. These are API and
carrier-resource witnesses only. No crossing wire change, exact-task staging
retention or production lazy-memory syscall witness is claimed by this
checkpoint. The production staging path still has the two admission
boundaries described above.

## Completed host-file output checkpoint

Host-file completion now validates the reply without touching user memory.
The native service owner moves the validated output into its existing
`OwnedCopyout` before retiring the request record and releases the previous
service claim before attempting output. An owner refusal retains the bytes,
original result and next page cursor; it does not issue another host read.
The obsolete plain syscall-output copy hook and boolean completion callback
are removed. A genuine copy or preparation fault remains errno 14.

The VM-free native-process bindings
`native_read_reply_retains_bytes_and_cursor_across_owner_wait` and
`native_read_reply_fatal_cancellation_commits_no_more_bytes` run production
read staging and HostFile service completion with a supplied carrier reply.
They require one first-page delivery, an owner gate park on the second page,
and either the remaining page alone on resume or no more bytes after fatal
cancellation. The first binding fails on the preceding completion code
because it returns EFAULT instead of parking. These bindings do not serve
an actual host resource and do not establish descriptor retention.

Descriptor admission before staging, retained vector input, carrier pin
integration and production write/writev retention witnesses remain open.
The completion checkpoint alone does not satisfy issue #1694.

## Crossing layout review checkpoint

The borrowed `OfdPinIdentity` lives in `carrick-core-abi` and is re-exported
by `carrick-fd-core`. It is the same lookup-only type used by the existing
carrier helper. Moving it removes the dependency cycle that would otherwise
prevent the crossing header from using it: fd-core already depends on
core-abi. This move changes neither ownership nor the current wire format.

The independently reviewed integration design extends `HostFileHeader` with
`Option<OfdPinIdentity>` and appends authority, index and generation at byte
offsets 96, 104 and 112. The header becomes 120 bytes and its version becomes
2. An absent identity is exactly three zero words. A present identity needs
nonzero authority and generation, and an index fitting `u32` (zero is valid).
Encoding, parsing and `request_parts` must enforce the same validation.
Layout witnesses must check the offsets, first payload byte, maximum record
length, old-version rejection, malformed identities and reply handling.

That activation must be one coherent change with production retention:
direct descriptor operations, including empty-path statx, require the
borrowed identity and exclusively use `with_retained_host_resource`.
Path operations retain their table authority; poll retains its separate
per-entry admission contract. There is no numeric-fd fallback for direct
operations. The ring owns the pin through terminal completion or cancellation
acknowledgement and retires it exactly once via the host cleanup authority.

Activating the layout without those producer and ownership changes would
break existing calls. This checkpoint therefore leaves the header untouched.
The required production write/writev and read/readv retention witnesses,
retained vector input, carrier integration and delegation conversions are
still open; the type move supplies no red/green behavioral evidence.

## Remaining native input classification checkpoint

The two native ppoll input copies now preserve the same typed outcome as
path and write staging. A true fault returns errno 14 without requesting
backing; an owner refusal forwards its exact address and access rather than
substituting the start of the timespec or pollfd array. The staging binding
`ppoll_input_preserves_fault_and_exact_owner_request` covers both inputs and
successful staging after a one-shot refusal. It was red for both the fault
classification and the requested-address assertion. It proves neither an
owner park nor descriptor retention. Existing poll admission and readiness
policy are unchanged.

The CPL0 `MappingUser` adapter now returns the typed fault for its unsupported
input direction. `MapPrivate` stages no user input; the old boolean signature
failed the actual freestanding image build with E0053. A successful host KVM
compile check alone did not expose that stale signature on earlier workers'
hosts. The full `just build-cpl0` red/green check qualifies this adapter port.

The guest-copy syntax debt remains 243: neither the missed `.is_done()`
classification nor the stale implementation signature was a counted trait
obligation. No ceiling is lowered for this checkpoint. Descriptor retention,
gathered-input retention, delegation conversions and production retention
witnesses remain required before issue acceptance.

## Neutral staging input interface checkpoint

`HostFileUser` now extends the neutral `UserCopy` interface instead of
declaring its own `copy_in` method. All native staging inputs use `UserVa`
at the transfer boundary. ARM forwards the shared interface directly to
`ValidatedCopy`; the CPL0 mapping-only adapter refuses unsupported transfers
with the same `CopyOutcome::Fault`. Test adapters also implement that interface.
This is an interface consolidation with unchanged staging decisions and work;
it adds no allocation, transfer, wait or host operation. The existing staging
classification and real-fork output-admission bindings remain applicable.

This checkpoint does not retain descriptor admission or gathered vectors,
convert the separate delegation file interface, or supply the required
production write/writev/read/readv retention witnesses. Guest-copy debt
reduction and full issue acceptance remain open.
