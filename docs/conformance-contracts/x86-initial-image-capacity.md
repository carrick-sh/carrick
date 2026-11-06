# Large x86 initial images (#1715)

The first two sections record earlier witnesses and the table-stock correction.
The current candidate and its remaining blocker are recorded at the end.

The `x86.mm.initial-image` contract now includes a 100 MiB initialized ELF
through production carrier boot and a similarly sized fork/wait assertion.
The boot assertion passes; the fork assertion currently fails at the separate
physical child-residency capacity and is retained as a red witness. The aperture remains 512 MiB. For the dense fixture,
the complete initial extent must be below 256 MiB, including staged bytes,
private user grants, publication records and Prepare stock.

Initial table stock follows unique 512 GiB, 1 GiB and 2 MiB virtual buckets
across ELF and the full configured stack. It includes the initial root and hierarchy, its private COW branch and the
maintenance root. Each admitted lifecycle slot stocks a complete child
hierarchy, a private COW branch and the nonempty parent scratch run required
by fork admission. It does not
reserve three tables per user page. The guest installer and host grant planner
use the same geometry authority. Geometry tests cover three sizes, disjoint
spans sharing buckets and crossings at every intermediate-table boundary.

Each initial leaf edit offers at most three table grants, and host receipt
validation reconstructs that exact offer. Passing the complete pool exceeded
the descriptor transaction's eight-grant limit once the image spanned enough
table buckets; it also rescanned unrelated zero pages on every leaf.

Red evidence on admitted main: the 100 MiB fixture fails `table stock must
follow topology`; Node 22 slim fails `initial image exceeds carrier memory
budget`. After sizing alone, the fixture is refused with status 2 because
of the oversized descriptor offer.

This correction sizes table grants to the image's required topology. It does
not implement demand-loaded ELF data: the guest still copies and publishes
every PT_LOAD page before entry. KVM host windows already use anonymous
MAP_NORESERVE backing; that is distinct from guest demand loading. ARM's
AddressSpace keeps initialized prefixes and permits demand-zero tails rather
than charging worst-case per-leaf table stock to this x86 aperture.

## Demand-allocation witness

`production_initial_image_extent_excludes_untouched_data_grants` tightens the
allocation requirement at 4, 32 and 100 MiB. It permits one staged copy of the
initialized ELF, the production table-stock geometry, and eight alignment
pages. Private output frames and publication records for untouched ELF pages
must not be charged at boot. Each scale then enters the production carrier
and checks exit(7); an allocation failure prevents that runtime assertion.
This is separate from the earlier 256 MiB table-stock bound, which admits
two full copies of the 100 MiB payload and therefore cannot prove demand
allocation.

On the topology-sized implementation, the first scale is red before entering
KVM: `4 MiB untouched image reserves data eagerly: 9056256 > 4792680`.
The existing real-KVM large-fork witness is also red; a fresh run reports
`physical fork source residency capacity`, rather than the child-side
capacity named in the earlier handoff. The fallback source publication in
`cpl0_anonymous.rs` consumes one residency record per 4 KiB leaf. A 100 MiB
population needs 25,600 such records, exceeding the shared 4,096-slot table.
Increasing either capacity would leave the allocation shape wrong.

The remaining integration is not a new anonymous-fault path. The shared
reservation owner already supports `insert_opaque_backed` and
`select_fault_window` retains its `HostBackingIdentity`. The kernel's retained
`PrivateFileBacking::LoadedImage` source already supplies initialized bytes
and zero padding. CPL0's physical grant service currently explicitly rejects
windows with `host_backing`; its boot publisher imports ELF regions without
source identities. These two boundaries need to consume the existing retained
source authority, while the guest initial editor stops allocating ELF output
frames before entry. Source custody must survive fork, parent exit and exec;
partial pages, BSS, protection changes and kernel user-copy materialization
must use that same authority. No such implementation or acceptance is claimed
by this witness commit.

## Source-backed candidate and remaining blocker

The candidate prepopulates only the entry leaf and configured bootstrap stack.
The KVM aperture planner charges those grants and publications, one staged copy
of initialized bytes, and topology-sized tables. It does not raise the 512 MiB
aperture. Untouched ELF pages are imported with a retained source identity in
the sole reservation graph. The shared physical service authenticates that
identity and fills private grants only when selected by the existing fault
owner. Partial initialized pages and BSS use zero padding. The immutable source
retains the actual `BackingExtent`, rather than a bootstrap `GuestRam` window.
Initial source handles and open-file handles share one neutral monotonic issuer.

Fork authenticates byte-source custody separately from resident-frame custody.
The extended 100 MiB witness requires child and parent to read a nonzero byte
from a distant leaf absent at fork. Both this witness and the 4/32/100 MiB
allocation witness pass on real KVM. Initial sources remain retained until the
carrier is destroyed, bounded by its one initial image.

The candidate is not ready to land. `ForwardVenue::read_bytes_raw` and
`write_bytes_raw` require present, authenticated stage-1 leaves. An untouched
ELF syscall buffer can therefore fail or change a valid guest result. The full
initial-MM suite reports 22 passes, eight failures, one ignored. User instruction
faults alone do not cover kernel user copies.

The required integration is the shared `MmPortal::begin` / `select` /
`revalidate` / `complete` protocol, with `UserRead` or `UserWrite` intent before
forwarding. It must preserve the syscall and transfer continuation across
`Supply`, `CowSupply` and owner waits. The current synchronous host `GuestMemory`
API has no owned suspension venue. A direct retained-source fallback would make
a second copy authority; lowering contention to EFAULT or spinning would be
incorrect. Independent review requests changes for this P0 regression.

## Wait output has two distinct completion stages

The production `production_wait_retains_reaped_child_across_untouched_rusage_output`
binding forks a real child, keeps status resident, and leaves the page-aligned
rusage BSS page untouched. Native Linux exits 7; the candidate exits 92. A
paired `BAD_RUSAGE` control uses address 1 instead and passes on both: wait4
returns errno 14, the resident status is delivered, and a second wait returns
errno 10 because the child was already reaped. The successful-output binding
also requires that second wait to return errno 10.

These are different stages of the same operation. In the shared native runtime,
`wait_query` copies status through `copy_status` before `CopiedWait::consume`,
then copies rusage through `copy_signal_bytes` after consumption. Neither copy
uses the retained `OwnedCopyout` path. Retrying the whole wait after rusage
supply would report ECHILD instead of the already-completed child's PID. The
continuation must retain the selected status/reap/rusage stage, not only the
original syscall words. Preflighting invalid rusage before reaping would also
change the Linux result demonstrated by the control.

The x86 native service still lacks the `prepare_owned_write` and `copyout_fault`
mechanics used by ARM's retained copyout service. Its `NativeWriteVenue` uses
the default unsupported backing-supply method. Adding a synchronous physical
crossing alone is insufficient: `grant_target` can refuse with an owner wait
after physical supply, while the local generic `error` mapper collapses that
wait into Fault. Physical custody and the exact transfer must survive that
refusal. No runtime correction is claimed by these additional witnesses.

## Admitted-base suspension audit

Fresh real-KVM execution of `cpl0_initial_mm` reproduces ten failures, with
23 passes and one existing ignored test. The 100 MiB carrier-boot, distant
fork-source and 4/32/100 MiB allocation bindings pass. The untouched status
binding exits 91 and the post-reap rusage binding exits 92; the invalid-rusage
control passes. These are current failures, not a green acceptance result.

The instruction to reuse the shared valid-but-unbacked suspension mechanism
requires a consumer in the CPL0 lane as well as a producer in the copy adapter.
The admitted tree has the following boundaries:

- `ForwardVenue` converts every failed `translate_leaf` into `OutOfBounds`.
  It inherits `GuestMemory::supply_memory`, whose default is `Unsupported`.
- `DispatchOutcome::from_owner_memory_error` can represent owner waits and
  supply requests. The HVPatch binding consumes those outcomes before ordinary
  continuation construction; the CPL0 executor does not.
- `Cpl0PersistentExecutor::block_forward` calls
  `prepare_blocked_continuation`. Its builder explicitly rejects
  `OwnerMemoryWait`, `OwnerMemorySupply`, and retained copy outcomes with
  `ContinuationBuildError::NonBlockingOutcome`. Emitting `ReadSuspended`
  alone therefore changes the failure venue without completing the copy.
- The cited typed `UserCopy` / `CopyOutcome::NotYet` prerequisite is absent:
  both existing `UserCopy` traits still return bool, and the tree has no
  `CopyOutcome` definition. The native wait witnesses use
  `NativeProcessService::copy_status` / `copy_signal_bytes`, rather than the
  forwarded host `GuestMemory` adapter. Their post-reap stage must survive
  independently of a saved syscall's redispatch.

The next integration needs the shared owner transfer and its suspension
consumer in both affected venues. A second x86 source lookup, synchronous
fault-in fallback, eager ELF population, or a larger carrier aperture would
not satisfy this requirement. The freestanding CPL0 image builds, but that
compile result does not resolve these live failures. No runtime fix is
claimed by this audit.

The native x86 Linux oracle exits 7 for both lazy-output fixtures and the
`BAD_RUSAGE` control. On the rebuilt Linux CLI, Node 22 slim with entrypoint
`/usr/local/bin/node` and `-e 'console.log(1)'` passes carrier boot, then exits
127 with no stdout or stderr. Its existing terminal syscall census identifies
the loader's `openat` refusal (native x86 ordinal 257, 41 refusals, zero host
services). It also records one `writev` refusal (ordinal 20) and 41 refusals in
the unknown-ordinal overflow bucket. This population census does not establish
temporal syscall order. The JSON execution witness records 85 guest entries,
16 owner-grant crossings and one root-exit crossing, with no host forwards.
The next demonstrated blocker is loader service coverage, tracked separately
by #1722; exit 127 is not a Node execution pass.

## Rebase over prefix-driven acquisition and retained rusage

The rebase onto the admitted main keeps #1720's per-leaf prefix-driven table
acquisition and its exact linked-table receipt reconstruction. The older
three-grant offer helper and eager table acquisition are not restored.
The fresh real-KVM initial-MM run executes 35 tests: 24 pass, 10 fail and
one remains ignored. Both lazy wait witnesses fail (status 91 and 92), while
the invalid-rusage control, 100 MiB boot, distant fork-source and allocation
witnesses pass. This is not acceptance.

The shared wait runtime now sends the already-consumed child's rusage and PID
to the existing completed-copyout owner. Its VM-free production-entry witness
`wait4_rusage_busy_retains_consumed_child_result` reaps a real fixture child,
refuses the output once, acknowledges the retained service, and requires the
original PID, one status copy, the rusage bytes and ECHILD on a second wait.
The test is red before the correction at `rusage Busy retains the completed
wait`. This is preparation for the required suspension integration, not proof
of a working KVM supply consumer.

A producer-only x86 native suspension experiment was discarded: publishing a
backing selection and entering the native service parks the task, but the
CPL0 executor has no native service-ticket intake. The production consumer in
`vcpu_loop/executor/backend.rs` is guarded by macOS/aarch64 configuration.
The experiment's waiting test process was terminated explicitly; it is not a
passing test or a reason to increase timeouts. Adding only `ReadSuspended` to
`ForwardVenue` likewise cannot work because CPL0's continuation builder rejects
owner-memory outcomes. Completing this integration needs a shared suspension
consumer and retained physical/copy custody; an x86 synchronous fault-in
fallback would violate the selected design. Neither incomplete producer is
included in the tree.
