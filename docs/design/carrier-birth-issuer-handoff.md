# Carrier birth issuer: production connection (#489)

Status: production task/thread allocation is connected; Linux verification is
recorded in the worker receipt. Signed execution, Mac compilation and final
portable/runtime acceptance remain director gates. The neutral word by itself
was a prerequisite; this change connects actual producers and retains exact
receiver authentication.

Contracts: `kernel.el1.signal-delivery-owner`, `kernel.el1.thread-lifecycle`,
`core.lifecycle.publication`, and `process.native.arm-admission`. Linux
semantic authority remains signal(7), kill(2), tgkill(2), clone(2), and exit(2).
The structural obligation is non-reuse across reserved, retired, unpublished
and rolled-back births, without a receiver scan or a graph lock across MM
preparation.

## One source, before publication

`ZoneTables<C>::serial_issuer()` is the only task/thread birth source for an
admitted carrier. Its zero-valid atomic word stores last-issued, starts at
zero, issues one first, and issues MAX once before terminal refusal. Neither
rollback nor handle transfer resets it. Protocol two authenticates production
shared issuance, distinct from the earlier inert-storage prerequisite. The
ARM ABI hash and x86 initial-boot version reject incompatible old images.

The HAL `BirthSerialSource` exposes owned operations rather than a raw pointer
or an unchecked static borrow. `BirthSourceIdentity` retains the actual backend
owner and compares its Arc identity, backend carrier identity and generation.
Two independent custody objects both numbered generation one do not match.
The identity itself cannot publish or allocate a birth without the source.

ARM's engine exports the source before `Kernel::bootstrap_root`. Only the
existing fixed EL1 region can promote its exclusive host mmap to retained
`BirthZoneBacking`; other mappings stay exclusive. Existing stage-2 retirement
remains with the mapping owner. Host issuance retains the mmap and custody,
checks the exact live VM generation under `custody.state`, and borrows only
that mapping's zone word. Mapping retirement invalidates the backing handle;
VM destruction/recreation rejects the old generation. No global zone lookup,
new metadata page or `GuestMetadataPin` participates.

`RootBootstrap::with_birth_source` installs that source before the root's first
task/thread issuance. Later ARM containers authenticate their engine's source
against the already-bound registry before preparing their root. A missing or
foreign source cannot silently fall back to local issuance in an active carrier.
The later factory extraction retains the same promoted EL1 backing, including
persistent launches; it does not reconstruct or reseed the issuer.

The x86 physical source retains the actual VM Arc and owning `Arc<GuestRam>`,
not `SharedWindows` descriptors. Acquisition validates the complete initialized
zone span and caches a typed pointer inside this owner. A separate revocation
owner belongs to `Cpl0HostCustody`; teardown takes its write guard and revokes
all retained source handles before inventory, mappings or VM custody retire.
Each source operation holds the corresponding read guard through its atomic
operation. Retained bytes after teardown therefore cannot authorize issuance.

The Linux x86 launch's private host kernel precedes the physical VM. Its stopped
initial handoff holds the registry's existing issuance write authority across
complete local high-water capture, zero-only zone adoption, and permanent source
replacement. The capture burns a ticket from the actual allocator, including all
previous reserved, retired and unpublished values. Zero-only CAS refuses a live
source: an independent local registry cannot join after any allocation escaped.
The root identity is then bound and its guest MM loaded. Native admission and
EL0 execution follow this handoff. Other x86 host product launch lanes remain
explicitly unsupported by the existing runtime rather than receiving a local
birth fallback.

## Producers and handle transfer

`ObjectIdRegistry::{task_serial,thread_serial}` use the bound source, including
`ThreadIdentity::reserve` and subsequent host pool replenishment. A singleton
binding still does not imply stocked siblings: `prepare_executable_thread_births`
returns before replenishment when `live() == 1`, and default pool depth is four.
Eight control slots are not evidence of eight issued identities.

Every native graph obtains task/thread fork tickets directly from its actual
zone before unlocking for MM preparation. Its previous cursor remains only for
non-birth MM/transaction accounting. Host MM IDs keep their existing carrier
owner; file, transaction and snapshot domains are not substituted for births.
Cold admission may idempotently observe authenticated roots, Reserved, Claimed,
Born, Published and host-birth records. Those observations are supplementary
accounting; source custody before issuance is the concurrency proof.

Boot export captures the shared birth handle and revokes old host issuance under
the same registry write authority. The exported local `serials` cursor is for
non-birth objects when a shared `birth_source` is present. Existing births and
other graphs keep the unchanged shared word; the old registry refuses further
task/thread and MM admission. Exclusive pre-carrier export retains its original
one-way local-cursor contract. Neither case transfers or zeroes a zone word.

## Authentication, work and evidence

Receiver record, exact identity, process birth, thread prefix and rehome checks
are unchanged. Indexed lookup cost remains
`O(log N + matching incarnation + target members)`. No retired observer record
is kept alive and no wait4, origin or noninterrupting signal policy changes.

Guest issuance is one successful checked atomic RMW, with contention-dependent
CAS retries and no trap callback. Host births additionally take the registry's
existing issuance read lock and dispatch through the retained source. ARM takes
the custody-state mutex; x86 takes its revocation read guard. Zone address
resolution is constant on ARM and cached at x86 acquisition. No per-birth page
allocation or receiver scan is added. Relaxed atomic ordering proves uniqueness;
existing publication protocols still publish birth records. No latency or native
runtime-ratio claim follows from these checks.

The canonical receiver witness now obtains the observer serial from the actual
host `ObjectIdRegistry`, retires that observer, reuses its internal TID and
snapshot, and requires a distinct native child birth before draining P1's durable
event. A second schedule reserves before native admission, allocates an
unpublished native fork before later host supply, and checks rollback burning and
partial exhaustion without child publication. The two-root real fork witness
also checks distinct shared-source births.

Kernel tests exercise pre-bootstrap roots, host/native issuance orders, repeated
host supply, complete initial handoff, refusal of an active-source join, two
retained owners both generation one, revocation, exhaustion and shared transfer.
Full boot-export resource checks exercise both exclusive and shared modes. x86
source tests exercise the production retained source and revocation owner without
VM execution; ARM custody-generation tests are registered for the Mac gate.
The private-cursor negative control and original canonical RED remain durable
worker evidence. Higher-layer acceptance must use the exact final top artifact.

Necessary layout consequences are confined to the source protocol/hash, x86 boot
version and the EL1 host-mapping custody enum. Existing HVF mapping tests wrap
exclusive owners in that enum; their mapping expectations are unchanged.

## Distinct carrier MM authority

The two-live-root MM witness is a separate correctness obligation. On the RED
head, native children used MM keys 3 and 5 while later host supply returned 3
and 4. The adapted older baseline passed that schedule; it was not proof that
independent MM cursors were universally safe. Task/thread birth correctness
alone does not establish MM identity composition.

`MmIssuerWord` now stores a separate zero-valid carrier-wide MM source in the
existing zone. Its borrowed API returns `MmGeneration`, not a birth serial or
bare semantic integer. It uses the same checked atomic protocol, burns tickets
on rollback, issues MAX once and remains terminal. ABI protocol/hash facts and
x86 initial-boot version authenticate the new storage/behavior. Fixture inputs
change and require a newly identified bundle; the separate publisher is not
part of this worker change.

The retained HAL capability exposes typed MM operations under the same exact
custody/generation/backing/liveness guard as births. ARM installs that capability
in `RootBootstrap` before `Kernel::bootstrap_root` calls `mm_id`. Later container
roots and host supply allocate from the same word. Native `fork_reserve` uses
its actual zone MM source; the graph cursor is now only a graph-owned transaction
source, with no birth/file/MM maximum-scalar seed. Context and snapshot revisions,
physical roots, file IDs and task/thread births retain their distinct domains.

The actual x86 prepared launch creates its private host root before the physical
carrier. Its existing stopped binding now takes the registry issuance write lock
and then **the current global MM source's write lock**. All reference/pre-carrier
`mm_id` allocations take that global source's read lock. Under both guards, the
handoff burns/captures the complete global MM high-water (including reserved,
unpublished and retired values), adopts it only into a zero MM word, adopts the
complete local birth high-water, and permanently switches the registry before
releasing either authority. The caller binds the initial task identity and loads
the guest MM afterward, before native entry. Failure burns values and publishes
no child; it cannot join an active independently issued source. The per-registry
birth lock alone is not presented as global MM authority.

Already-bound handles authenticate the same retained owner and never reseed
later roots. Boot export transfers the existing retained capability and revokes
old MM admission; surviving peers keep both unchanged words. There is no active
carrier fallback to the reference/pre-carrier global allocator. Production
admission performs no MM inventory scan or late advancement. Existing fixtures
that manually publish root MM values account for those values in test-only
setup; the unchanged production-bound MM witness needs no such import.

Guest MM issuance is one checked atomic RMW (with contention retries), no trap
or allocation. Host MM issuance adds its registry read lock and the existing ARM
custody mutex or x86 revocation read guard. Only initial pre-carrier transfer takes
the global write lock. No graph lock spans backend preparation and receiver
record/identity/process-birth/thread-prefix/rehome checks and indexed cost remain
unchanged. No runtime-ratio claim follows from VM-free checks.

The unchanged MM regression now tests host-before-native and native-before-host
supply with two live roots. A second production-bound witness starts real native
forks in two graphs on separate host threads with bounded actor coordination,
then checks later host supply, unpublished rollback burning and terminal partial
allocation without child publication. Kernel bootstrap tests cover later root
MMs, complete initial transfer, foreign custody and export revocation. Physical
source controls apply the actual retained backing/revocation protocol to MM
operations too. Full cross-host, signed/runtime and exact-top acceptance remain
director gates.
