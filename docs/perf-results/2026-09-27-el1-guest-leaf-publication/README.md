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
versus the `<0.125` contract, so no performance improvement is claimed. The
next bounded task is transactional creation of the missing hierarchy under the
same guest editor, with whole-range preflight, RW/UXN/nG preservation, rollback
and explicit capacity refusal. Run the 256-page signed witness immediately;
only after it passes run the 1,024- and 4,096-page scales. Checkpoint 2, full CI
and full EL1 migration completion remain open.
