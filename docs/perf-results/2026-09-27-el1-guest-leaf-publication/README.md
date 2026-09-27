# EL1 authenticated guest leaf publication checkpoint

This checkpoint connects the existing authenticated frame-grant host service
to the production EL1 data-abort path. It is source and VM-free validation for
the impact-bearing path; signed first-touch acceptance is deliberately not
claimed here.

Guest-transaction commit: `dae6f092c3a8eed2f574f93231d320edd6cc96b8`.
Release-service fix: `afdf580392fd8244253b4a19c219e1f96d48885a`.

On the first recoverable translation or permission fault, EL1 publishes one
carrier-wide request bound to the loaded task's exact MM, FAR, access class and
nonzero generation, then forwards through the existing host boundary. On the
retry, EL1 observes only the matching response, acquires and reauthenticates
the exact MM editor before claiming Ready, validates every existing invalid L3
leaf before the first store, publishes the returned linear IPA span with the
host-authoritative permissions and per-MM `nG`, broadcasts one ASID
invalidation, acknowledges the response and returns directly to EL0.

A closed MM gate leaves Ready published. The host recognizes that exact pending
response and retries after the mutation guard drops; it does not fall through
to signal delivery. A refusal is consumed once and forwarded without issuing a
new request in the same dispatch. An authenticated Ready response that passes
editor admission but cannot publish its pre-provisioned invalid span is a
fail-closed invariant violation rather than a fabricated guest `SIGSEGV`.

## Red-first evidence

- `guest-claim-red.log`: the mailbox had no exact-fault response claim.
- `leaf-publisher-red.log`: the neutral MMU core had no all-or-nothing guest
  leaf publisher.
- `fault-flow-red.log`: the EL1 production flow and publisher boundary were
  absent.
- `gate-retry-red.log`: the first implementation consumed Ready before editor
  admission, so a closed gate lost the response and would have misdelivered the
  fault. The corrected flow preserves Ready across that host boundary.

## Green evidence

- `focused-libs-green.log`: 62 EL1, 25 ABI, 174 memory and 95 MMU tests pass.
- `fault-flow-green.log`, `guest-claim-green.log`,
  `leaf-publisher-green.log`, and `gate-retry-green.log`: the focused
  transaction controls pass.
- `host-retry-green.log`: the runtime recognizes an exact pending response as
  a retry before ordinary fault delivery.
- `el1-image-green.log`: the audited embedded EL1 image builds and its header
  test passes; the direct `aarch64-unknown-none-softfloat` release build also
  passed during development.
- `clippy.log`: targeted all-target warning-denied Clippy passes for EL1, ABI,
  MMU, memory and runtime.
- `contract-green.log`: all 62 registered contracts, 15 claims and 143 surfaces
  validate.
- `personality-boundary-green.log`: both substrate crates remain clean; the new
  EL1 dependency reaches only neutral `carrick-mmu-core`.

The first broad memory run exposed an inherited stale assertion in
`stage1_identity_tables_layout`: it still expected the accepted dynamic
metadata aperture to be user-accessible, while the builder and its dedicated
tests require kernel-only AP/UXN attributes. The test now derives both EL1
kernel ranges from their ABI constants; the full 174-test memory suite passes.

`lint-domains.log` is nonzero on three unchanged inline-assembly findings in
`crates/carrick-el1/src/alloc.rs` (stack pointer and DAIF save/mask/restore).
This checkpoint does not edit that accepted allocator source and does not add
an exemption or weaken the rule. The relevant resolved Cargo-graph personality
gate was run separately and passes.

## Open acceptance

`afdf58039` fixes the release-only host service build by exposing the exact MM
identity through the existing borrow-bound permit in shipped configurations.
The exact release CLI build passes; `artifact-identity.txt` records source HEAD,
SHA-256, CDHash, LC_UUID, entitlement and DOF identity for that signed binary.
The release check, focused Clippy, contract registry and exact product-diff
receipts are retained beside it.

The first exact signed execution reaches the EL1 publication invariant and
aborts. The durable panic bridge then preserved the source location and stable
publication detail across HVC. `signed-first-touch-panic-code.log` reports
`frame_grant_publication_detail=3`, which is `MissingTable`: request publication,
the authenticated host grant, Ready delivery and exact guest-editor admission
all completed, but the anonymous range had no existing L3 table for the
existing-invalid-leaf publisher to edit. The negative entitlement control and
scoped cleanup passed.

The diagnostic reruns contain uncommitted panic instrumentation and therefore
are discovery evidence, not acceptance receipts for `afdf58039`. The previous
signed three-scale witness remains red at about 0.9954 host exits per page
versus the `<0.125` contract, so no performance improvement is claimed.

The current correction replaces the existing-leaf-only publisher with the
shared live `PageTableManager`. It reconstructs the occupied primary cursor,
preflights the complete semantic span, allocates missing hierarchy under the
admitted guest editor, publishes terminal RW/UXN/nG descriptors before table
pointers, synchronizes descendant pointers before ancestors, and uses the
existing undo journal for every error. Current-pool exhaustion refuses before
any hardware-visible byte changes; guest extension-arena growth remains a
separate stage-2-backed protocol rather than fabricated capacity.

`missing-hierarchy-red.log` is the compile-red for the absent transaction.
`missing-hierarchy-green.log` covers successful missing-hierarchy publication,
neighbor isolation, permission bits, nG and whole-range occupied refusal.
The same test group covers byte-identical capacity refusal. The full 97-test
MMU suite, 174-test memory suite, targeted warning-denied Clippy, bare-metal
EL1 release build and 62-contract registry pass; focused retained receipts are
beside this file.

This source has not yet run as one frozen signed artifact. The next gate is the
256-page signed witness; only after it passes run the 1,024- and 4,096-page
scales. Checkpoint 2, extension growth, full CI and full EL1 migration
completion remain open.

The first committed missing-hierarchy artifact is recorded in
`missing-hierarchy-artifact-identity.txt`; its exact signed build is in
`missing-hierarchy-signed-build.log`. The 256-page witness in
`missing-hierarchy-signed-first-touch.log` crossed the old `MissingTable`
invariant and reached the first write to the newly allocated table page. It
then exited at `FAR=0x2d0002c008`, the fixed primary-table alias plus `0xc008`,
with a write abort. The backing root extent and alias already cover that page;
the root cause was that the allocator-backed root mapping inherited the
semantic region's read-only permission at stage 2. EL0 remained excluded by
stage-1 AP bits, but EL1 could read and not update its own table image.

`stage2-write-red.log` captures the production-shaped contract observing
`Read` stage-2 permission. The correction upgrades only the physical table
backing to `ReadWriteExec` (the existing HVF writable-map policy) and leaves
the mapping's `guest_writable` flag false. `stage2-write-green.log` and
`stage2-write-clippy.log` preserve the focused green test and warning-denied
Clippy. `stage2-write-gic-control.log` keeps the GIC-window exclusion negative
control green, and `stage2-write-product-diff.log` records exact changed-surface
coverage with a revision-bound exemption for that unchanged GIC contract. The
prescribed host test gate reached the unchanged GIC source-shape
assertion already documented by the host-service checkpoint; the new test and
the affected production crate otherwise pass. A new exact signed artifact and
256-page rerun remain the next acceptance step.

The exact `4a939f00f` artifact is recorded in
`stage2-write-artifact-identity.txt`, with signed build output in
`stage2-write-signed-build.log`. The 256-page run
`el1-stage2-table-write-first-touch-20260927` crossed the write-abort boundary:
EL1 allocated and published the missing hierarchy and the carrier reached fork
child preparation. It then failed because VA `0x6000001000` resolved in the
child snapshot to the old identity IPA `0x6000001000` instead of the newly
granted global IPA `0x9b40001000`. The negative entitlement control and scoped
run-ID cleanup passed. This is signed discovery evidence, not a passing
first-touch receipt.

`live-snapshot-cursor-red.log` reduces that exact failure to two serialized
live editors over one backing. The guest editor allocates and links hierarchy
beyond the host manager's cached prefix; the base snapshot returns no
translation. `9d521e6be` makes snapshot discovery walk the reachable four-level
table graph against live physical capacity and extend the copied prefix only
through the highest linked primary page. It does not scan or copy the whole
1.75 MiB arena and adds no traversal allocation. The focused green receipt,
all 98 MMU tests, warning-denied MMU Clippy and the existing warmed recycled
snapshot allocation witness pass in `live-snapshot-cursor-green.log`,
`live-snapshot-mmu-tests.log` and `live-snapshot-clippy.log`.

The exact signed `0a1c70a47` artifact is recorded in
`live-snapshot-artifact-identity.txt`, with its build in
`live-snapshot-signed-build.log`. The run
`el1-live-snapshot-first-touch-20260927` reproduced the same pre-touch fork
mismatch, so the snapshot correction fixed a real stale-image defect but did
not move this signed acceptance boundary. The fixture forks before either side
touches the anonymous range. `live-snapshot-forkdiag.log` proves the mapping
and alias inventory already name IPA `0x9b40001000`, while the parent stage-1
leaf is intentionally invalid and retains the old identity output
`0x6000001000`.

`fork-invalid-alias-red.log` is the compile-red for the absent projection
correction. `a6b32fe6b` repoints only an inherited dynamic private alias whose
leaf is invalid and retains a superseded output. It preserves validity and all
permission attributes, so fork does not make an untouched page accessible.
The focused control, warning-denied HVF Clippy, formatting, and the prescribed
serial HVF library suite pass; the suite reports 573 passed, three ignored and
one already documented GIC source-shape assertion filtered.

The frozen `58c76fdfd` artifact and exact in-process signed test executable are
attested in `fork-invalid-alias-artifact-identity.txt`; the build and run are
in `fork-invalid-alias-signed-build.log` and
`fork-invalid-alias-signed-first-touch.log`. The signed fixture now completes
both parent and child semantics at every scale:

| Pages per process | Total pages | Carrick host exits | Semantics |
|---:|---:|---:|---|
| 256 | 512 | 612 | parent and child pass |
| 1,024 | 2,048 | 2,148 | parent and child pass |
| 4,096 | 8,192 | 8,292 | parent and child pass |

The fork projection correction therefore closes the signed semantic blocker.
It does not yet deliver the structural impact: `(2148 - 612) / 1536` and
`(8292 - 2148) / 6144` are both exactly `1.0000` host exit per added page,
against the `<0.125` contract. The entitlement negative control passes and
scoped cleanup reports zero remaining processes for both run IDs.

The next bounded task is an exit-class census on this exact fixture. One host
exit still scales with every touched page; classify it as grant/first-touch,
stage-1 frame COW, stage-2 replay or another exact boundary before changing
code. Checkpoint 2 and measured performance acceptance remain open.

## Accepted first-touch structural boundary

The bounded census found that the bulk grant path was active but a
carrier-wide single-flight mailbox forced the other concurrently faulting vCPU
slot through page-granular fallback. The post-coherence capture recorded 207
matching grant-service function entries alongside 1,291
`commit_resident_fault` entries. This explained the residual scale-dependent
exit count without reopening general MM or fork design.

The red-first ABI contract `frame_grant_mailboxes_are_single_flight_per_vcpu_slot`
required two slots to publish and claim independently. The checked ABI now
contains one exact single-flight mailbox per persistent vCPU slot. EL1 selects
it from the trap-frame slot; the host selects the same mailbox from the active
engine's mailbox slot. MM key, request generation, fault address, access class,
frame/mapping identity and owner generation authentication are unchanged.

The preceding signed run also exposed one live-table coherence defect: a host
manager created before guest hierarchy growth rejected the guest-linked table
as outside its cached allocated prefix. Red-first MMU contracts now require a
host edit to follow and adopt that live hierarchy and require its allocator not
to reissue a guest-owned table page. All 101 MMU tests pass with that
correction.

The first signed acceptance execution after the slot-local correction reports:

| Pages per process | Total pages | Carrick host exits | Semantics |
|---:|---:|---:|---|
| 256 | 512 | 99 | parent and child pass |
| 1,024 | 2,048 | 102 | parent and child pass |
| 4,096 | 8,192 | 119 | parent and child pass |

The incremental slopes are `(102 - 99) / 1536 = 0.0020` and
`(119 - 102) / 6144 = 0.0028` host exits per added page. Both are far below the
strict `<0.125` contract. The unentitled negative control passes and scoped
cleanup reports zero remaining processes. The first-touch semantic and
structural boundary is accepted; checkpoint 2 remains open for permission and
retirement paths, elastic frame return, fork COW ownership, migration of the
memory syscalls, removal of the superseded host writer/pause, and paired
workload timing.
