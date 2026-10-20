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
