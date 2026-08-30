# Foreign-MM Structural Retention Acceptance Evidence

Date: 2026-08-30

This document contains only fresh evidence for the acceptance repair on the
committed custody foundation. It supersedes the previous contents in full.

## Artifact identity

- Rebased foundation commit: `901945f82`
- Pre-rebase foundation provenance: `c8a2281dfd14520df87c8e9f0a3973c88157d36e`
- Foundation `trap.rs` blob: `27bc201f1ff835c3540044bebf27e5e315f4d14e`
- Acceptance-repair `trap.rs` blob: `4ccc8436c478b9bb6c2107d460606ab3b5eecd2a`
- Acceptance-repair `trap.rs` SHA-256:
  `5486ab63e648e92676fde3bb7e373519625a53d2fae399f73836e960b96a12cb`
- Worktree: `/Volumes/CaseSensitive/carrick/.worktrees/agy-rx-retention-foundation-v3`
- Branch: `codex/rx-custody-salvage`
- State: committed landing candidate pending final controller review.

The rebased signed-test wrapper from local `main` remains executable:

- Git mode/blob: `100755 a83629cbe0c7bba6bbeb17841af0fd7cd602852e`
- Filesystem mode: `755`
- SHA-256: `2a968e92c26fbc2a464ce4a20242237c4dde3122e58936d34e59c6afca84bab7`

## Acceptance boundary

`production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle`
is now ignored for ordinary host runs because it requires a signed HVF test
executable. It no longer enables the stage-2 test stub or calls the test-only
plan helper.

The test creates an empty `CarrierVmCustody`, creates and commits a real
`VirtualMachineInstance<GicDisabled>` through the production admission/create
transaction, uses allocator-backed production global-frame IPAs, constructs
`ProcessSpec::new(vm, plan)`, and calls
`HvfVmState::prepare_task_only_process_spec`. It accepts only
`HvpatchCarrierTaskState::Process`, never `LeaseTest`.

One non-dropping root VM handle prevents an applevisor wrapper from issuing a
second raw destroy while prepared state is cleaned up. Final teardown uses
`destroy_vm_with_custody` and exact terminal-record finalization. Fork
projection and retained-backing lookup use the transport's exact custody rather
than the legacy test-only directory.

## Rollback preimages

The row-2 stage-mapping failure begins with a live sentinel mapping and a
nonempty authoritative inventory. Its fingerprint includes `initialized`, all
extent identity fields, `frames.shared`, `frames.references`,
`frames.extent_references`, `frames.stage2_references`, and
`frames.authority_retained_stage2`. After the injected failure, the test proves
exact fingerprint equality, absence of both candidates, and continued presence
of the sentinel as the sole mapping.

The directory-publication failpoint seeds nonempty alias and replay state,
captures both exact preimages, and proves exact equality after rollback. An
RAII guard restores the pre-test alias/replay state even on early exit.

## Historical RED overlay

Artifact:
`docs/perf-results/2026-08-30-foreign-mm-structural-retention-red-overlay.patch`

- Exact pre-fix base: `700dcae52972a1312aab85c947821396c9f7c471`
- Base `trap.rs` blob: `e27e9bc7af9e8c9a8bef9eab140f57080097bc60`
- Overlay `trap.rs` blob: `3a73918b1824d6c1c9da906fe99eb04f065728c1`
- Patch SHA-256:
  `87f0d1fcd0061ced2ee4e0c45498c05b9670709cd3b398f1432b537180ecbad2`

The test-only overlay constructs the pre-fix `GlobalFrameHostOwner`, arms the
lease's backing-liveness audit, and drops the owner. The historical field/drop
architecture releases the host mapping before the stage-2 lease observes it,
so the behavioral assertion fails.

Materialize the committed artifact, then apply and verify it in an isolated
checkout of the exact base:

```sh
git show codex/rx-custody-salvage:docs/perf-results/2026-08-30-foreign-mm-structural-retention-red-overlay.patch > /private/tmp/rx-retention-red-overlay.patch
RX_RED_DIR="$(mktemp -d /private/tmp/rx-retention-red-overlay-base.XXXXXX)"
git worktree add --detach "$RX_RED_DIR" 700dcae52972a1312aab85c947821396c9f7c471
git -C "$RX_RED_DIR" apply --check --whitespace=error /private/tmp/rx-retention-red-overlay.patch
git -C "$RX_RED_DIR" apply --whitespace=error /private/tmp/rx-retention-red-overlay.patch
git -C "$RX_RED_DIR" hash-object crates/carrick-vmm-hvf/src/trap.rs
cd "$RX_RED_DIR"
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib trap::foreign_mm_tests::red_overlay_global_owner_retains_backing_until_stage2_retirement -- --exact --nocapture
```

Fresh applicability receipt: reverse application succeeded, forward
`git apply --check` succeeded, forward application succeeded, and the resulting
blob was exactly `3a73918b1824d6c1c9da906fe99eb04f065728c1`.

Fresh RED receipt, exit code `101`:

```text
running 1 test
test trap::foreign_mm_tests::red_overlay_global_owner_retains_backing_until_stage2_retirement ... FAILED
panicked at crates/carrick-vmm-hvf/src/trap.rs:258:9:
stage-2 retirement must observe the exact host backing still live
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 288 filtered out
```

## Fresh GREEN receipts

Signed production boundary and negative control:

```sh
RUSTC_WRAPPER= CARRICK_RUN_ID=rx-retention-signed just test-hvf production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle --ignored --exact --nocapture
```

Exit code `0`. The wrapper resolved the bare exact filter to the unique
module-qualified test. The signed positive passed `1/1`; the copied unentitled
executable's `unsigned_executable_maps_hv_denied_to_entitlement` negative
control passed `1/1`. Final wrapper summary:

```text
test-signed: OK (carrick-vmm-hvf: 8 signed executable(s) passed, negative control passed)
```

No guest instruction was executed; this acceptance exercises the real signed
HVF VM, stage-2, conversion, retention, retirement, and destroy boundaries.

Focused rollback:

```sh
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib foreign_mm_failure_injection_at_composition_boundaries -- --nocapture
```

Exit code `0`: `1 passed; 0 failed`.

Custody:

```sh
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib custody -- --nocapture
```

Exit code `0`: `38 passed; 0 failed`.

Foreign-MM host suite:

```sh
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib --features foreign-cow-test-support foreign_mm_tests -- --nocapture
```

Exit code `0`: `26 passed; 0 failed; 1 ignored`. The ignored row is the signed
acceptance run separately above.

Frame inventory:

```sh
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib --features foreign-cow-test-support frame_inventory -- --nocapture
```

Exit code `0`: `92 passed; 0 failed`.

Runtime production-carrier facade:

```sh
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib production_carrier -- --nocapture
```

Exit code `0`: `5 passed; 0 failed`; its process-isolated nested check also
passed `1/1`.

Compile and lint:

```sh
RUSTC_WRAPPER= cargo check -p carrick-vmm-hvf --lib
RUSTC_WRAPPER= cargo check -p carrick-vmm-hvf --lib --features foreign-cow-test-support
RUSTC_WRAPPER= cargo clippy -p carrick-vmm-hvf --lib --tests --features foreign-cow-test-support -- -D warnings
```

All three commands exited `0`; the final clippy run emitted no warnings.

## Scope attestation

No Linux kernel source was read, searched, inspected, or consulted. No
abandoned or rejected patch or workstream was read, searched, inspected, or
consulted. The historical RED artifact was authored from a fresh detached
worktree at the named commit.
