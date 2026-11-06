# Large x86 initial images (#1715)

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
