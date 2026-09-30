# Private/shared alias callers joined to EL1 publication

Development on adapter parent `ec366760f`, contract
`kernel.el1.stage1-publication`. Production admission remains disabled. This
connects real callers in source; it is not signed execution or checkpoint acceptance.

`Aarch64EngineCore::repoint_private` and `repoint_shared_leaf` now select the
existing driving-vCPU descriptor service on the guest-owned lane, before entering
the host edit funnel. `HvfVmState::repoint_guest_alias` retains exact-MM exclusion,
authenticates every target inventory extent and pins its exact physical owner
before seeding private content or publishing any descriptor. Shared aliases do
not copy bytes. Logical mapping extents and physical-owner extents are separate
inputs to the existing kernel authority; containment, exact live kernel row,
revision and independent current owner are checked. The caller verifies returned
MM, frame, mapping and generation against its retained backend record.

Descriptor protocol v5 adds MapAlias to the existing journal and transport.
It matches user RWX alias publication with nG and no private-anonymous tags.
Missing tables use existing grants. Whole aligned 2 MiB outputs remain blocks;
unaligned outputs split rather than masking to a wrong physical address. Valid
terminals use clear, publication barrier, invalidation, install; both stores are
journaled. Requests are bounded to 2 MiB within each authenticated logical extent.
Pins and exclusion survive every receipt through final alias bookkeeping.
A prepublication planning refusal returns an error; unknown completion, later
partial-publication failure or metadata failure after publication is fatal.

The private metadata hook now validates the completed mapping, like the shared
hook, rather than refusing merely because EL1 owns descriptors. Both production
engine callers retain their existing host paths until complete lane activation.
The other host-writer guards and global admission fences remain intact.

Evidence:
- Alias operation red: NotPrepared before implementing the journal operation.
- BBM red: the initial operation had only four stores instead of clear/install
  pairs. Final witness checks invalidation occurs between each clear and install,
  and all eight failure positions restore the full preimage.
- MMU 165 tests pass: wire round trip, missing hierarchy, coarse output alignment,
  exact permissions/outputs and rollback included. Early operation-green log is
  superseded by the final MMU suite for BBM evidence.
- Kernel authority test passes exact MM/IDs/revision/generation and records that
  a larger physical extent is queried separately from the exact logical row.
  Out-of-owner input refuses before retaining; wrong row and rollback refuse.
  This fixture uses the real kernel inventory and a recording fixed-generation
  owner provider, not a full carrier-ownership or hardware witness.
- Backend guard/accounting 11, shared-bookkeeping witness, EL1 114, engine 75,
  affected all-target Clippy, formatting and hardware softfloat EL1 image build
  pass. The engine suite exposed a pre-existing source-shape assertion that did
  not follow EngineStage1Services; committed-parent source confirmed that move
  predates this change. The corrected assertion follows ASID-scoped maintenance
  through the service as well as direct calls; the original failure is retained.

No signed guest execution, end-to-end alias caller witness, activation or
checkpoint promotion is claimed. Full caller composition remains a requirement
of the first signed descriptor-ownership delivery; current tests are lower-layer
evidence only. Main stays unchanged and x86 stays deferred.
