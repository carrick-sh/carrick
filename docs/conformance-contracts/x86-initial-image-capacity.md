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
