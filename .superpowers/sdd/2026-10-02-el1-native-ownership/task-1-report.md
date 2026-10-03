# Task 1 implementation report

Initial checkpoint (4f7a6d89a; superseded by the fix1 receipt below):
UserTransfer implementation and focused VM-free evidence completed;
all worker checks below passed before the implementation commit. Whole-N1 acceptance and
independent director review are not claimed. Worktree `wt-n1`, branch `work/n1`,
base `580c4a299`. No guests, Docker, merge, push, stash or bypassed hooks.

The production owner borrows SharedReservations/AddressSpaces and the retained
metadata bank. The private N0 model is removed. Closed CopyIn/CopyOut requests
own host bytes and offset, and the sealed admitted handle binds carrier/MM/root
incarnation. Physical custody is existing stage-2 record + actual mapping Arc;
the guest SpaceEditor stays on its service stack across bounded copy/cancel and
completion. Exact target lazy grants, private-file COW adoption/refill and the
I2 executable physical effect use existing production authorities.

Files: `carrick-el1` portal/entry/fault/cow/reservation owner; `carrick-el1-abi`
transfer/grant/executable records, COW claim authentication and residency window
lifecycle; `carrick-aarch64` owned transfer, borrowed service runner and narrow
private import admission; `carrick-mmu-core` admission and executable-aware COW
classification; `carrick-vmm-hvf` physical pin/copy, pending publication/custody
and covering fixtures; contract and plan receipts. The plan's superseding
implementation section maps exact production functions.

## Covering evidence

- Core units: `cargo test -p carrick-el1 -p carrick-el1-abi -p carrick-mmu-core -p carrick-aarch64 --lib --quiet`: 637 passed (93 AArch64, 214 EL1, 116 ABI, 214 MMU), zero failed.
- Two-live-MM matrix: both roots have 16/512 unrelated mappings at each
  16/64/256-page size, retained dynamic bank, real byte copies, full default
  executor occupancy, stopped target with OPEN gate; original descriptor/tree
  visit bounds retained. No host semantic callback is in the transfer path.
- Actual stage-2 pins defer retirement, stale identities refuse new retention,
  source Arc lifetime survives through memcpy, independent carrier identities
  reject same local MM/VM-generation crossfeed.
- Source byte semantics: Owned, CopyOnly, HostBackingPrivate, HostBackingShared;
  private imported writes resolve through actual guest COW and leave source
  bytes/file unchanged; shared file changes remain visible.
- Typed-retired partial replacement: real production reservation unmap/remap
  generation + guest Prepare and separate actual pending allocator/pin copy;
  fresh 4 KiB page zero, neighboring page in the SAME old 16 KiB compound
  unchanged before/after copy, old live physical IPA not reused.
- Exact pending-grant unmap race models kernel receipt ordering with the fake
  inventory authority and production publication/retirement helpers. It checks
  successor alias, live mapping/frame, stage-2 generation and actual `keep`
  bytes, including kernel-retired/backend-not-yet-retired ordering.
- Private imported anonymous=false root with empty COW pool returns owned
  exact-target CowSupply without anonymous mailbox use or retained editor.
  Physical refill uses existing allocator once and preserves MM/frame identity.
- Executable COW red/green: without publication callback, Resolved assertion
  failed. Now exact claimed grant publication occurs before CowRepoint, one
  crossing for executable private COW and zero for data-only COW. Host RX ARM64
  function returns 7 then 9 after UserTransfer write. I2-clean assertions occur
  BEFORE each RX transition, so test-only mprotect cannot conceal absent I2.
- ABI sealing has two compile-fail doctests. Runner fake vCPU proves intermediate
  copy/cancel resumes same PC/SP before caller registers are restored.

Red-first details retained: private import admission leaf was untagged
`0x60000090000fc3`; typed retired replacement was `Refused(Occupied)`;
kernel-only UserWrite was `Ok(Suspended)` instead of Fault; executable COW was
not Resolved. The existing COW residency witness also first exposed acceptance
of the old token after repoint. No expected failures or ignored tests added.

## Limits and rulings

The director authorized exact-target physical grants, pending alias publication
with exact retirement rollback, imported-private guest COW tagging, typed
retired replacement with fresh backing, and bounded I2 physical publication
while the real guest editor remains held. No host permission snapshot,
ForeignMmInvocation exclusion policy or second cache mechanism was added.

VM-free host RX execution is not guest execution. Signed guest page-table/TLBI
and complete artifact acceptance remain director gates. Public bulk Capacity,
Fork rebinding and GuestMemory venue 3 remain deferred as directed; existing
production-admission reds remain in the contract. `just accept` does not exist
in this worktree's justfile; no replacement guest recipe was run. Parent owns
final six gates, clean-tree inventories and independent whole-diff review.

## Final worker receipts

- `cargo test -p carrick-el1 -p carrick-el1-abi -p carrick-mmu-core -p carrick-aarch64 --lib --quiet`: exit 0, 637 passed.
- `cargo test -p carrick-vmm-hvf --lib user_transfer -- --test-threads=1`: exit 0, 5 passed.
- `cargo test -p carrick-vmm-hvf --lib transfer_ -- --test-threads=1`: exit 0, 4 passed.
- `cargo test -p carrick-vmm-hvf --lib guest_cow -- --test-threads=1`: exit 0, 11 passed.
- `cargo test -p carrick-el1-abi --doc --quiet`: exit 0, 2 compile-fail doctests passed.
- `cargo clippy -p carrick-aarch64 -p carrick-el1 -p carrick-el1-abi -p carrick-vmm-hvf --all-targets -- -D warnings`: exit 0.
- `cargo fmt --all` applied; `git diff --check` clean.

The initially attempted RWX host permission view returned -1; this was not
interpreted as a cache defect or a skipped witness. The final W^X RX/RW view
executes the actual retained ARM64 bytes successfully, with I2 completion
asserted independently before changing host permissions. No guest VM ran.


## Review fix1 receipt

All four Important review findings have covering fixes. Final commit follows
this receipt; parent owns independent review, six foreground gates and clean
line-position capture. No Cargo command will remain running at handoff.

- Recursive registry rollback: `PendingTransferGrant` carries the held guard
  through every fallible preparation step. The descriptor refusal red hung in
  the old recursive lock (exact test process killed at5s); current refusal and
  concurrent-unmap/successor fixture passes.
- Executable publication: every completed UserWrite re-dirties exact bytes,
  including non-executable aliases. Existing I2 lock spans dirty claim through
  invalidation, at most16KiB per lock, without content drain. Reds showed I2
  count1 vs2, nonexec peer0 vs1, and premature peer completion. All green.
- Original matrix: actual writeA/writeB/readA/readB at all six size/population
  points, both live roots, real pin1→0 per chunk, full slots/parked OPEN target,
  RO/NONE/retire A policy with errno14 and unchanged B. Restored writes exposed
  extra execute descriptor walks; one leaf translation now returns executable
  permission too, preserving original ≤8 descriptor loads/page and logarithmic
  reservation visits. Core EL1 reservation policy test remains present.
- External CopyOnly: source pin survives source directory/owner destruction;
  stale source generation refuses before target root publication. SeededAnon
  preparation uses existing allocator/inventory/custody. PendingImport owns
  host-setup descriptor undo through normal admission; refusal restores exact
  original descriptors BEFORE physical release. The additional red left new
  IPA665719930880 installed after physical rollback; green restores original
  IPA1073741824, then a new same-address import succeeds and reads `away`.
  This fixture models kernel permit issuance explicitly; separate kernel tests
  cover the actual SPACES_LOCK guard and normal dispatcher ordering.

Director-licensed admission authority is now concrete: kernel PreAdmissionGuard
holds existing SPACES_LOCK, outer BoundAddressSpaceAdmission obtains exact MM
mutation first, samples mutable anchors/limits under that authority, and owns
published cleanup before root admission. Raw AddressSpacePublication escapes
only after lock release. Actual old publish-before-mutation red admitted an
intervening editor and failed `old publish-before-mutation order admitted
concurrent edit`; current dispatcher test excludes that same editor.

Exact focused commands after fixes:

- `cargo test -p carrick-kernel --lib publication_to_root_admission_keeps_exact_mutation_authority -- --test-threads=1`: 1 passed.
- `cargo test -p carrick-kernel --lib pre_admission_owner_blocks -- --test-threads=1`: 1 passed.
- `cargo clippy -p carrick-kernel -p carrick-vmm-hvf -p carrick-aarch64 -p carrick-el1 -p carrick-hal --all-targets -- -D warnings`: exit0.
- `cargo test -p carrick-vmm-hvf --lib user_transfer -- --test-threads=1`: 8 passed.
- `cargo test -p carrick-vmm-hvf --lib transfer_ -- --test-threads=1`: 7 passed.
- `cargo test -p carrick-vmm-hvf --lib executable_ -- --test-threads=1`: 6 passed; one preexisting signed-harness-only entitlement negative control ignored.
- Core four-crate units repeated after final changes:637 passed (93/214/116/214); ABI sealing doctests2 passed.
- `python3 scripts/migrate/check-runtime-aborts.py --check`: all four shards valid, runtime282/HVF251/vCPU165/other59.
- `python3 scripts/migrate/check-runtime-global-state.py --check`: exit0.

Exact implementation/witness file:line map and reviewed inventory rationale
are in the plan's final N1 review fix receipt. No new cataloged host process or
identity operation is introduced by kernel admission locking; authoritative
compiler capture and line-position reconciliation require the clean final tree
and remain parent gates. This is VM-free composition, not signed guest syscall
or whole-N1 acceptance. Fork, bulk Capacity, GuestMemory venue3 remain OPEN.

## Review fix2 receipt

The scoped rereview accepted findings 1/3/4 but retained finding 2: page-granule
dirty state was claimed while only caller bytes were invalidated. Existing
CodeContent publication now expands to complete dirty pages, clamps to backing
bounds, and splits into at most 16 KiB per claim/invalidation lock hold. The
carrier forwards the authority's exact ranges to existing I2. Raw bit claiming
is private. No new cache mechanism, owner, inventory classification or policy.

Behavioral reds from `cargo test -p carrick-vmm-hvf --lib executable_publication_ -- --test-threads=1`:

- disjoint same-page cache lines at 0/0x200: invalidated `[(0,4)]`, expected `[(0,4096)]`;
- unaligned 16 KiB: invalidated `[(1,16384)]`, expected `[(0,16384),(16384,4096)]`.

The new boundary test also proves final partial backing-page clamping and
out-of-bounds refusal. Exact function/witness anchors are in the plan's fix2
receipt. Final scoped results follow; parent retains full gates and independent
review. No guests or Docker run.

- `cargo test -p carrick-vmm-hvf --lib executable_ -- --test-threads=1`: 8 passed, one preexisting signed-only negative control ignored.
- `cargo test -p carrick-vmm-hvf --lib user_transfer -- --test-threads=1`: 8 passed.
- `cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings`: exit 0.
- `cargo fmt --all --check` and `git diff --check`: pass.

## Final whole-branch review fix wave

Both findings in final-branch-review.md are implemented. Product changes are
limited to atomic fresh undo acquisition in the existing manager/editor and a
non-clone ImportDescriptorUndo retaining the exact stage-1 authority/resolver
through preparation, sync, commit and rollback. The claim precedes source
snapshot and physical allocation; rejection never joins an existing journal.
The contract now binds the actual physical HVF matrix test.

Behavioral reds (`cargo test -p carrick-vmm-hvf --lib transfer_import_refuses -- --test-threads=1`):

- `second pending import joined the first journal`;
- `import joined an existing loader journal`.

Both now pass. Competing-import tests preserve first descriptors, actual `away`
bytes, pin count one, exact inventory and allocator identity counter; then first
refusal and first commit both work. Loader-journal rejection preserves its
modified descriptor and rollback capability with unchanged physical counters.

Focused green commands:

- `cargo test -p carrick-vmm-hvf --lib transfer_ -- --test-threads=1`: 9 passed.
- `cargo test -p carrick-vmm-hvf --lib trap::user_transfer::tests::native_owner_matrix_moves_bytes_with_balanced_physical_pins -- --exact --list`: exactly 1 test discovered.
- Same exact test with `--exact --test-threads=1`: 1 passed.
- `cargo clippy -p carrick-vmm-hvf -p carrick-aarch64 -p carrick-mmu-core --all-targets -- -D warnings`: exit 0.
- `cargo run -p carrick-conformance-contract --bin check-contracts -- --root .`: 92 contracts, 15 claims, 164 surfaces checked.

Plan final receipt maps the exact new ownership/witness boundaries and moved/
retired fatal rationale. Parent retains final foreground gates, clean inventory
positions and one scoped review; no broad suite was duplicated in this wave.
- `python3 scripts/migrate/check-runtime-aborts.py --check --only hvf`: 250 reviewed carrier-fault sites valid; one retired missing-resolver site, one moved rollback site.
- `cargo fmt --all --check` and `git diff --check`: pass.
