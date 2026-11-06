# Native child descriptor family (#1678): incomplete implementation

The shared fd-core now provides `close_range_retained`: callers supply empty
receipt storage for the complete selected population. Under the existing table
guard it pins every selected description before vacating any slot. Insufficient
receipt storage or pin saturation preserves the entire range, returning any
prefix pins. Each non-Copy receipt owns its original table/fd identity and an
exact incarnation pin; `pinned_close_effects` reads sticky effects through that
pin after removal. No numeric replay or backing callback is part of this API.
Work is three linear passes over the allocated selected extent, independent
of a UINT_MAX endpoint, with no allocation or additional lock ordering.

The fd-core witnesses cover replacement-slot survival (including flags and
offset), a second live table, late effect publication, and admission rollback.
They do not exercise carrier cleanup. Crossing integration must still bind
receipts to the caller and operation, retain the host OpenFile before reuse,
and settle canonical cleanup by description identity. Single close has the
same numeric-replay hazard and must use that integration too. Plain range
close remains Forward; this foundation does not complete item 1 or authorize
allowlist promotion.

The existing `kernel.el1.ipc-fd-authority` contract covers this family.
Linux authority is dup(2), fcntl(2), close(2), and close_range(2). Fork copies
slots and descriptor flags while sharing open descriptions and pipe state.
Carrick must keep one descriptor namespace and settle each mutation once.

The production-entry two-child fixture already exercises dup, dup3 with
O_CLOEXEC, F_DUPFD, F_GETFD/F_SETFD, F_GETFL/F_SETFL and close. Its shared
setup also drives the following witnesses:

- `serial_host_native_child_pipe_size_commands_lack_ring_handler` calls
  F_GETPIPE_SZ and F_SETPIPE_SZ with 12288 and 131072. Each currently returns
  Forward without changing the input fd. Acceptance must instead serve them,
  with Linux capacities 65536, 16384 and 131072 respectively.
- `serial_host_native_child_close_range_cloexec_is_served` now requires
  CLOSE_RANGE_CLOEXEC to be Served, including a sparse range ending at
  UINT_MAX, an in-zone pipe and a host-backed descriptor. Both fork children
  remain live: only the caller's descriptor flags change. Invalid flags and
  reversed ranges return errno 22. Plain close and UNSHARE retain the measured
  effect-free Forward baseline; their selected descriptors remain live.

The original plain-close and pipe-size acceptance targets were run red on admitted main
`81c091aef5e8aaff3e5e770127c6e31c2b7a03f1` with only the fixture extension:
`just test-el1-native --only serial_host_native_child`. Both failed with
`left: Forward`, `right: Served` (GETPIPE_SZ command 1032 and close_range).
Previous commits retained that measured defect baseline. This slice serves
only the additional CLOEXEC case; plain close and pipe sizing remain Forward.
These direct dispatch fixtures do not call the final native unclaimed-capture
policy or assert errno 38. No carrier service, capacity result or full-family
acceptance is proved by the remaining baseline.

The fixture explicitly seeds the shared HostIpc table before real fork
admission. Its existing dup/flags/close success does not reproduce or explain
the director's Mac `dupclosestdin` setup failure. Production carrier table
seeding and inherited stdio must still be compared with this fixture; removing
Forward entries alone is not evidence that the Mac child can reach the owner.

Backed-pipe growth, plain range close/UNSHARE, cancellation, concurrent close/reuse,
and signed execution remain unproved. The implementation is unfinished; keep
this branch draft and do not promote its allowlist.

## Independent review: prerequisites

Review found no need for a second descriptor path. It identified P1 gaps that
must be resolved in the crossing-owner design before implementing new wire
layouts or cross-crate lock ordering, as AGENTS.md requires:

1. The ring descriptor owner has no pipe-size fcntl arm. Existing pipe capacity
   mutation and host pool allocation belong to `IpcZone::resize_pipe` in
   `crates/carrick-kernel/src/el1_ipc.rs`. Do not duplicate its algorithm in
   ring, cap requests at the default size, or claim unbacked-only success as
   complete support. A proposed typed host-file capacity service must retain
   the authenticated caller/table/description or select its admission point
   explicitly. Numeric fd re-resolution after close/reuse must not redirect a
   previously admitted operation. Review the wire encoding before coding it.
2. Plain range close must reuse filtered IPC release, delegated binding
   settlement and host close effects from the existing close owner. The raw
   fd-core range callback runs under the table lock and cannot reenter that
   authority to perform these effects.
3. UNSHARE needs a process-runtime resource transition. Existing
   `Aarch64NativeProcessService::fork_fd_table` can prepare the copied fd-map,
   descriptor table and owned IPC mapping, but does not publish a calling
   process's successor resource identity. Updating only CurrentTask or the IPC
   map breaks the graph's ownership. Design reserve/prepare/commit/rollback
   with exact task generation and old table identity before implementation.

The proposed pipe service should reuse the existing authenticated HostFile
record and ticket, rather than raw fcntl forwarding. Its storage ordering must
preserve the current allocator protocol: sample the object under its lock,
release it, provision storage, release the allocator lock, replace storage and
publish readiness under the object lock, release it, deliver wakes, then
reclaim retired storage. No allocator or object lock survives carrier execution
or a guest park. Both ISA clients need a shared service binding.

The UNSHARE transaction's actual graph/resource/fd-map/IPC-map acquisition and
publication order remains unresolved. Admission refusal must retain the
operation on its existing release notification; cancellation before commit
reclaims the prepared successor, and cancellation after commit settles it once.
A separate independent review of that order is still required. No wire or
lock-order change is implemented here.

Director-owned signed smoke, complete EL1 population comparison, and the Mac
`dupclosestdin`/`fcntlpipesz` root-versus-child census and Linux oracle remain
required. This Linux fixture cannot substitute for them.

## CLOEXEC implementation and plain-close stop

CLOSE_RANGE_CLOEXEC uses the existing fd-core range operation. It holds the
existing fd-map mutation guard across fd-core flag publication and projection,
following the same fd-map → fd-core acquisition order as descriptor duplication.
The projection visits at most FD_MAP_CAPACITY entries once. The core visits at
most the selected allocated descriptor extent, independent of the numeric upper
bound; UINT_MAX does not cause UINT_MAX iterations. No object is closed, no
host service is replayed and no lock survives a park. No new wire record or
second descriptor namespace is introduced.

Independent review rejected the first plain-close implementation before commit.
It accumulated CommitOwed after per-fd removal, but CommitOwed replays the
original numeric syscall. A CLONE_FILES sibling can reuse a removed fd before
that replay; the host range would then target a different description. A
later settlement error could also discard an already committed prefix's
obligations. The VM-free WithWork assertion did not exercise this host cleanup.
The implementation was removed, rather than asserting it safe from that pass.

A zero-effects preflight is insufficient: effects can be added on pinned open
descriptions outside the descriptor-table lock. Plain close needs retained
per-description close-effect receipts in the crossing owner, with exact
incarnation and caller identity, admission before mutation, cancellation and
settlement after releasing the table lock. The existing numeric replay cannot
be used as that receipt. UNSHARE additionally needs the reviewed process-resource
publication transaction described above. These remain design blockers for the
full family; the Forward allowlist stays unchanged.

Pipe-capacity reads also need their operation-record exhaustion admission and
signal policy resolved. Internal object-lock contention must not introduce
EINTR for this nonblocking metadata operation. The reviewed scalar completion
must not be placed in byte-transfer progress. No pipe-capacity runtime change
is included in this slice.

The CLOEXEC production target was also run red with only its harness change
against the preceding implementation: it returned Forward rather than Served.
The separate projection witness uses admitted stdio bindings at incarnation 1,
checks authority refusal leaves flags unchanged, and checks only selected slots
in the caller's table acquire CLOEXEC. This catches an incorrect `incarnation >
1` live-slot predicate that would pass core-only F_GETFD assertions.
