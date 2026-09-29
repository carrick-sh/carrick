//! Source-shape verification for frame publication lock discipline.

#![cfg(test)]

use std::path::Path;

fn guest_cow_fixture() -> (
    carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    crate::hvf_aarch64_engine::GuestCowBackingState,
) {
    use carrick_mmu_core::aarch64::SubstrateGpa;
    use carrick_mmu_core::aarch64::descriptor_txn::*;
    let nz = |n| std::num::NonZeroU64::new(n).unwrap();
    let backing = |n| BackingIdentity {
        frame_id: nz(n),
        mapping_id: nz(n + 1),
        owner_generation: nz(n + 2),
        inventory_revision: nz(n + 3),
    };
    let current = crate::hvf_aarch64_engine::GuestCowBackingState {
        mm_key: nz(7),
        root: SubstrateGpa(0x8000),
        va: carrick_guest_mem::GuestVa(0x4000),
        old_ipa: SubstrateGpa(0x10000),
        new_ipa: SubstrateGpa(0x20000),
        old_backing: backing(10),
        new_backing: backing(20),
    };
    (
        DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: current.mm_key,
                generation: nz(1),
            },
            root: current.root,
            op: DescriptorOp::CowRepoint {
                va: current.va.raw(),
                old_ipa: current.old_ipa,
                new_ipa: current.new_ipa,
                backing: current.new_backing,
            },
            tables: TableGrants::NONE,
        },
        current,
    )
}

fn verified_cow_receipt(
    txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
) -> carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt {
    use carrick_mmu_core::aarch64::descriptor_txn::*;
    txn.verify_receipt(&DescriptorReceipt {
        id: txn.id,
        digest: txn.digest(),
        outcome: DescriptorOutcome::Applied(DescriptorApplied {
            pages: 1,
            resident: PageSpan::EMPTY,
            tables_linked: 0,
            live_stores: 1,
            flush_required: true,
        }),
    })
    .unwrap()
}

#[test]
fn guest_cow_receipt_gate_rejects_stale_mm_root_generation_and_both_owners() {
    use crate::hvf_aarch64_engine::{GuestCowBackingError, GuestCowBackingTransaction};
    let (txn, expected) = guest_cow_fixture();
    let verified = verified_cow_receipt(&txn);
    let nz = |n| std::num::NonZeroU64::new(n).unwrap();
    for changed in [
        crate::hvf_aarch64_engine::GuestCowBackingState {
            mm_key: nz(8),
            ..expected
        },
        crate::hvf_aarch64_engine::GuestCowBackingState {
            root: carrick_mmu_core::aarch64::SubstrateGpa(0x9000),
            ..expected
        },
        crate::hvf_aarch64_engine::GuestCowBackingState {
            old_backing: carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                owner_generation: nz(99),
                ..expected.old_backing
            },
            ..expected
        },
        crate::hvf_aarch64_engine::GuestCowBackingState {
            new_backing: carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                owner_generation: nz(99),
                ..expected.new_backing
            },
            ..expected
        },
        crate::hvf_aarch64_engine::GuestCowBackingState {
            new_backing: carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                inventory_revision: nz(99),
                ..expected.new_backing
            },
            ..expected
        },
    ] {
        let mut pending = GuestCowBackingTransaction::new(txn, expected).unwrap();
        let mut mm_repoints = [0, 0];
        let mut retirements = 0;
        assert_eq!(
            pending.commit(&verified, changed, || {
                mm_repoints[0] += 1;
                retirements += 1;
            }),
            Err(GuestCowBackingError::StaleBacking)
        );
        assert_eq!((mm_repoints, retirements), ([0, 0], 0));
        pending
            .commit(&verified, expected, || {
                mm_repoints[0] += 1;
                retirements += 1;
            })
            .unwrap();
        assert_eq!((mm_repoints, retirements), ([1, 0], 1));
        assert_eq!(
            pending.commit(&verified, expected, || retirements += 1),
            Err(GuestCowBackingError::AlreadyCommitted)
        );
        assert_eq!(retirements, 1);
    }
    let mut other = txn;
    other.id.generation = nz(2);
    let mut pending = GuestCowBackingTransaction::new(txn, expected).unwrap();
    assert_eq!(
        pending.commit(&verified_cow_receipt(&other), expected, || panic!(
            "stale receipt committed"
        )),
        Err(GuestCowBackingError::WrongReceipt)
    );
    other = txn;
    other.id.mm_key = nz(8);
    assert_eq!(
        pending.commit(&verified_cow_receipt(&other), expected, || panic!(
            "other MM committed"
        )),
        Err(GuestCowBackingError::WrongReceipt)
    );
}

#[test]
fn guest_cow_requires_an_applied_receipt_and_host_lane_is_unchanged() {
    use carrick_mmu_core::aarch64::{LiveDescriptorOwner, descriptor_txn::*};
    let (txn, _) = guest_cow_fixture();
    for outcome in [
        DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking),
        DescriptorOutcome::RolledBack(DescriptorRefusal::Contended),
    ] {
        assert!(
            txn.verify_receipt(&DescriptorReceipt {
                id: txn.id,
                digest: txn.digest(),
                outcome
            })
            .is_err()
        );
    }
    let authority = carrick_aarch64::Stage1Authority::new();
    assert!(super::require_host_cow_lane(&authority).is_ok());
    authority.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
    assert!(super::require_host_cow_lane(&authority).is_err());
}

#[test]
fn host_cow_accounting_is_mm_scoped_and_survives_retirement() {
    let parent = crate::hvf_aarch64_engine::HostCowStats::default();
    let sibling = parent.clone();
    let child = crate::hvf_aarch64_engine::HostCowStats::default();
    parent.record_host_cow_resolution();
    sibling.record_host_cow_resolution();
    assert_eq!(parent.host_cow_resolutions(), 2);
    assert_eq!(child.host_cow_resolutions(), 0);
    drop(parent);
    assert_eq!(sibling.host_cow_resolutions(), 2);
}

#[test]
fn guest_lane_refuses_host_cow_before_copy_or_publication() {
    for (source, entry, first_effect) in [
        (
            include_str!("../cow_engine.rs"),
            "fn perform_frame_cow(",
            "authority.quiesce()",
        ),
        (
            include_str!("../cow_engine.rs"),
            "fn materialize_retired_reuse(",
            "let retained_ipa",
        ),
        (
            include_str!("../foreign_mm.rs"),
            "fn perform_foreign_cow_transaction(",
            "let executable_span",
        ),
        (
            include_str!("../sparse_materialization.rs"),
            "fn publish_replacing(",
            "let semantic_len",
        ),
    ] {
        let body = source.split_once(entry).unwrap().1;
        let guard = body
            .find("require_host_cow_lane(")
            .expect("guest lane must refuse before host work");
        assert!(guard < body.find(first_effect).unwrap(), "{entry}");
    }
}

#[test]
fn host_cow_counter_counts_only_completed_local_and_foreign_transactions() {
    for (source, entry, completion) in [
        (
            include_str!("../cow_engine.rs"),
            "fn perform_frame_cow(",
            "self.cow_armed.lock().disarm(span)",
        ),
        (
            include_str!("../foreign_mm.rs"),
            "fn perform_foreign_cow_transaction(",
            "lease_guard.retained = committed.clone()",
        ),
    ] {
        let body = source.split_once(entry).unwrap().1;
        let body = body.split("\n    pub(crate) fn ").next().unwrap();
        let count = body
            .find("record_host_cow_resolution()")
            .expect("completed COW needs its own counter");
        assert!(count > body.find(completion).unwrap());
        assert_eq!(body.matches("record_host_cow_resolution()").count(), 1);
    }
}

#[test]
fn alias_unmap_takes_frame_registry_guard_only_for_inventory_publication() {
    let source = include_str!("../cow_engine.rs");
    let unmap = source
        .split("pub(crate) fn unregister_process_alias(")
        .nth(1)
        .expect("alias unmap entry point")
        .split("pub(crate) fn prepare_process_alias_retirement(")
        .next()
        .expect("alias unmap end");
    let publication = unmap
        .find("if prepared.inventory.is_some()")
        .expect("inventory publication branch must precede guard acquisition");
    let guard = unmap
        .find("FrameRegistryGuard::acquire(")
        .expect("inventory publication needs a frame registry guard");
    assert!(publication < guard);
}

#[test]
fn frame_publication_sites_contain_no_carrier_topology_lock() {
    let cow_engine_src = include_str!("../cow_engine.rs");
    let foreign_mm_src = include_str!("../foreign_mm.rs");

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vcpu_loop_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/mod.rs"))
            .expect("read vcpu_loop/mod.rs");

    // 1. materialize_sparse_mmap_extent_inner
    let materialize_sparse = cow_engine_src
        .split("pub(crate) fn materialize_sparse_mmap_extent_inner(")
        .nth(1)
        .expect("materialize_sparse_mmap_extent_inner exists");
    let materialize_sparse_body = materialize_sparse
        .split("pub(crate) fn supersede_cow_receipts(")
        .next()
        .expect("materialize_sparse_mmap_extent_inner body end");
    assert!(
        !materialize_sparse_body.contains("acquire_topology_lock("),
        "materialize_sparse_mmap_extent_inner must not acquire the carrier topology lock"
    );

    // 2. materialize_retired_reuse
    let materialize_retired = cow_engine_src
        .split("pub(crate) fn materialize_retired_reuse(")
        .nth(1)
        .expect("materialize_retired_reuse exists");
    let materialize_retired_body = materialize_retired
        .split("pub(crate) fn publish_shared_repoint(")
        .next()
        .expect("materialize_retired_reuse body end");
    assert!(
        !materialize_retired_body.contains("acquire_topology_lock("),
        "materialize_retired_reuse must not acquire the carrier topology lock"
    );

    // 3. perform_frame_cow
    let perform_cow = cow_engine_src
        .split("pub(crate) fn perform_frame_cow(")
        .nth(1)
        .expect("perform_frame_cow exists");
    let perform_cow_body = perform_cow
        .split("pub(crate) fn refresh_fork_process_state_in(")
        .next()
        .expect("perform_frame_cow body end");
    assert!(
        !perform_cow_body.contains("acquire_topology_lock("),
        "perform_frame_cow must not acquire the carrier topology lock"
    );

    // 4. perform_foreign_cow_transaction
    let foreign_cow = foreign_mm_src
        .split("pub(crate) fn perform_foreign_cow_transaction(")
        .nth(1)
        .expect("perform_foreign_cow_transaction exists");
    let foreign_cow_body = foreign_cow
        .split("impl carrick_hal::ForeignMmReadLease")
        .next()
        .expect("perform_foreign_cow_transaction body end");
    assert!(
        !foreign_cow_body.contains("acquire_topology_lock("),
        "perform_foreign_cow_transaction must not acquire the carrier topology lock"
    );

    // 5. install_alias in vcpu_loop/mod.rs
    let install_alias = vcpu_loop_src
        .split("let install_alias =")
        .nth(1)
        .expect("install_alias closure exists");
    let install_alias_body = install_alias
        .split("break 'service installed;")
        .next()
        .expect("install_alias body end");
    assert!(
        !install_alias_body.contains("acquire_topology_lock("),
        "install_alias must not acquire the carrier topology lock"
    );
}

#[test]
fn frame_inventory_publication_and_retirement_sites_hold_registry_guard() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vcpu_loop_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/mod.rs"))
            .expect("read vcpu_loop/mod.rs");
    let quiesce_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/quiesce.rs"))
            .expect("read quiesce.rs");
    let exec_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/exec.rs"))
            .expect("read exec.rs");
    let binding_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/binding.rs"))
            .expect("read binding.rs");

    let assert_guard_precedes = |block: &str, target_call: &str, context: &str| {
        let guard_pos = block
            .find("FrameRegistryGuard::acquire(")
            .or_else(|| block.find("FrameRegistryGuard::new("))
            .unwrap_or_else(|| panic!("{context}: block must bind FrameRegistryGuard"));
        let call_pos = block
            .find(target_call)
            .unwrap_or_else(|| panic!("{context}: block must contain call to {target_call}"));
        assert!(
            guard_pos < call_pos,
            "{context}: FrameRegistryGuard must precede {target_call}"
        );
    };

    // 1. apply_alias_frame_inventory in vcpu_loop/mod.rs (install_alias)
    let install_alias_block = vcpu_loop_src
        .split("let install_alias =")
        .nth(1)
        .expect("install_alias exists")
        .split("break 'service installed;")
        .next()
        .expect("install_alias end");
    assert_guard_precedes(
        install_alias_block,
        "apply_alias_frame_inventory(&kernel_context, commit)",
        "vcpu_loop/mod.rs install_alias",
    );

    // 2. exec retirement apply & replacement apply in vcpu_loop/exec.rs
    let exec_apply_block = exec_src
        .split("drop(_hvpatch_topology);")
        .nth(1)
        .expect("exec apply block exists")
        .split("#[cfg(test)]")
        .next()
        .expect("exec apply block end");
    assert_guard_precedes(
        exec_apply_block,
        ".apply(old_mm_id, retired_commit)",
        "exec.rs old_mm retirement apply",
    );
    assert_guard_precedes(
        exec_apply_block,
        "engine.apply_exec_inventory(replacement_mm_id.raw(),",
        "exec.rs apply_exec_inventory",
    );

    // 3. detached address space retirement apply in vcpu_loop/binding.rs
    let binding_apply_block = binding_src
        .split("fn apply_detached_address_space_retirement(")
        .nth(2)
        .expect("apply_detached_address_space_retirement exists")
        .split("fn apply_detached_address_space_retirement_with_receipt(")
        .next()
        .expect("apply_detached_address_space_retirement end");
    assert_guard_precedes(
        binding_apply_block,
        ".apply(mm, commit)",
        "binding.rs apply_detached_address_space_retirement",
    );

    let binding_apply_receipt_block = binding_src
        .split("fn apply_detached_address_space_retirement_with_receipt(")
        .nth(2)
        .expect("apply_detached_address_space_retirement_with_receipt exists")
        .split("pub(crate) struct HvpatchLoopJob<E>")
        .next()
        .expect("apply_detached_address_space_retirement_with_receipt end");
    assert_guard_precedes(
        binding_apply_receipt_block,
        ".apply_retirement_with_receipt(mm, commit)",
        "binding.rs apply_detached_address_space_retirement_with_receipt",
    );

    // 4. fork apply_inventory in vcpu_loop/quiesce.rs
    let quiesce_apply_block = quiesce_src
        .split("ops.apply_inventory(&task_backend, child_context.kernel(), child_mm_id)")
        .next()
        .and_then(|prefix| prefix.rsplit("if !shares_mm {").next())
        .expect("quiesce apply_inventory block exists");
    assert!(
        quiesce_apply_block.contains("FrameRegistryGuard::acquire(")
            || quiesce_apply_block.contains("FrameRegistryGuard::new("),
        "quiesce.rs apply_inventory block must bind FrameRegistryGuard"
    );

    // 5. fork reservation in vcpu_loop/quiesce.rs
    let quiesce_reserve_block = quiesce_src
        .split("let mut inventory_reserve =")
        .nth(1)
        .expect("inventory_reserve exists")
        .split("let inventory_preparation =")
        .next()
        .expect("inventory_reserve end");
    assert_guard_precedes(
        quiesce_reserve_block,
        ".reserve_frame_inventory(frame_candidates, mapping_candidates, capacity)",
        "quiesce.rs inventory_reserve",
    );

    // 6. exec reservation in vcpu_loop/exec.rs
    let exec_reserve_block = exec_src
        .split("let replacement_capacity = match carrick_hal::FrameEventCapacity::for_event_count(")
        .nth(1)
        .expect("exec reservation exists")
        .split("Some(abandon)")
        .next()
        .expect("exec reservation end");
    assert_guard_precedes(
        exec_reserve_block,
        "engine.begin_exec_inventory(retired, replacement)",
        "exec.rs begin_exec_inventory",
    );

    // 7. exit terminal reservation in vcpu_loop/binding.rs
    let exit_reserve_block = binding_src
        .split("if owns_final_mm {")
        .nth(1)
        .expect("exit terminal reservation exists")
        .split("let prepared_core =")
        .next()
        .expect("exit terminal reservation end");
    assert_guard_precedes(
        exit_reserve_block,
        "engine\n                .begin_retirement_inventory(reservation)",
        "binding.rs begin_retirement_inventory",
    );
}

#[test]
fn fork_exec_exit_and_unmap_sites_contain_no_carrier_topology_lock() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let quiesce_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/quiesce.rs"))
            .expect("read quiesce.rs");
    let exec_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/exec.rs"))
            .expect("read exec.rs");
    let binding_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/binding.rs"))
            .expect("read binding.rs");
    let executor_settlement_src = std::fs::read_to_string(
        manifest_dir.join("../carrick-runtime/src/vcpu_loop/executor/settlement.rs"),
    )
    .expect("read executor/settlement.rs");
    let executor_src =
        std::fs::read_to_string(manifest_dir.join("../carrick-runtime/src/vcpu_loop/executor.rs"))
            .expect("read executor.rs");
    let cow_engine_src = include_str!("../cow_engine.rs");

    fn strip_tests(src: &str) -> &str {
        for pattern in [
            "\n#[cfg(test)]\npub(crate) mod tests",
            "\n#[cfg(test)]\nmod pt_pause_tests",
            "\n#[cfg(test)]\nmod tests",
            "\n#[cfg(test)]\npub(crate) fn fail_running_and_retire_for_test",
        ] {
            if let Some((prod, _)) = src.split_once(pattern) {
                return prod;
            }
        }
        src
    }

    fn contains_topology_lock(src: &str) -> bool {
        strip_tests(src).lines().any(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                return false;
            }
            trimmed.contains("acquire_topology_lock(")
                || trimmed.contains("try_acquire_topology_lock(")
        })
    }

    let mut failures = Vec::new();
    if contains_topology_lock(&quiesce_src) {
        failures.push("quiesce.rs production code contains carrier topology lock");
    }
    if contains_topology_lock(&exec_src) {
        failures.push("exec.rs production code contains carrier topology lock");
    }
    if contains_topology_lock(&binding_src) {
        failures.push("binding.rs production code contains carrier topology lock");
    }
    if contains_topology_lock(&executor_settlement_src) {
        failures.push("executor/settlement.rs production code contains carrier topology lock");
    }
    if strip_tests(&executor_src).lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with("//")
            && !trimmed.starts_with("/*")
            && !trimmed.starts_with('*')
            && trimmed.contains("acquire_process_retire_topology_lock_servicing")
    }) || strip_tests(&executor_settlement_src).lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with("//")
            && !trimmed.starts_with("/*")
            && !trimmed.starts_with('*')
            && trimmed.contains("acquire_process_retire_topology_lock_servicing")
    }) {
        failures.push(
            "executor production code contains acquire_process_retire_topology_lock_servicing",
        );
    }
    if contains_topology_lock(cow_engine_src) {
        failures.push("cow_engine.rs production code contains carrier topology lock");
    }
    assert!(
        failures.is_empty(),
        "production fork, exec, exit, unmap sites must not contain carrier topology lock:\n{}",
        failures.join("\n")
    );
}

/// The frame-registry leaf is a non-reentrant mutex. `commit_process_alias_retirement`
/// runs INSIDE `materialize_sparse_mmap_extent_inner`'s registry hold (a private-file
/// `mmap` publishes its replacement and retires the displaced rows under one leaf
/// section), so the commit must take the caller's guard as proof and never lock the
/// leaf itself. On 2026-09-12 it did lock it: every `mmap` of a private file-backed
/// mapping over live rows (Python loading an extension module) self-deadlocked the
/// executor and wedged the guest.
#[test]
fn alias_retirement_commit_takes_the_callers_registry_guard_and_never_locks_the_leaf() {
    let cow_engine_src = include_str!("../cow_engine.rs");
    let (_, after_sig) = cow_engine_src
        .split_once("pub(crate) fn commit_process_alias_retirement(")
        .expect("commit_process_alias_retirement exists");
    let (signature, body) = after_sig
        .split_once(") -> Result<(), TrapError> {")
        .expect("commit_process_alias_retirement signature ends with its Result");
    assert!(
        signature.contains("registry: &crate::fork_quiesce::FrameRegistryGuard<'_>"),
        "commit_process_alias_retirement must take the caller's FrameRegistryGuard as proof of the leaf hold"
    );
    let body = body
        .split_once("\n    pub(crate) fn ")
        .map_or(body, |(head, _)| head);
    assert!(
        !body.contains("frame_registry_lock()"),
        "commit_process_alias_retirement must never take the frame-registry leaf itself: its callers hold it"
    );
    for caller in [
        "materialize_sparse_mmap_extent_inner",
        "unregister_process_alias",
    ] {
        let (_, after) = cow_engine_src
            .split_once(&format!("fn {caller}("))
            .unwrap_or_else(|| panic!("{caller} exists"));
        let section = after
            .split_once("\n    pub(crate) fn ")
            .map_or(after, |(head, _)| head);
        assert!(
            section.contains("commit_process_alias_retirement(") && section.contains("&registry)"),
            "{caller} must pass its own registry guard into the retirement commit"
        );
    }
}

/// The go-net_http deadlock (2026-09-12, core `target/perf/perf2x-sep12/
/// nhwedge/nhw-2`): executors held `alias_registry()` inside
/// `mapping_for_range_in` while the match closure authenticated the row's
/// frame owner through `global_frame_host_owner_matches_in`, which takes
/// `global_frame_host_owners`; a detached address-space retirement held that
/// owners map (plus the frame inventory) and waited on the IPA allocator —
/// a cycle. Lock order: the alias registry is a LEAF for lookups. A query
/// under it may only run pure geometry/scope predicates; frame-owner
/// authentication (`global_frame_host_owner_matches_in`,
/// `global_frame_region_owner_matches_in`, any `custody` access) runs on the
/// returned candidates after the lock is released.
#[test]
fn alias_registry_queries_never_authenticate_frame_owners_under_the_lock() {
    let cow_engine_src = include_str!("../cow_engine.rs");
    let mut offenders = Vec::new();
    let mut search = 0;
    while let Some(found) = cow_engine_src[search..].find("alias_registry()") {
        let start = search + found;
        let rest = &cow_engine_src[start..];
        let Some(lock_at) = rest.find(".lock()") else {
            break;
        };
        if lock_at > 64 {
            search = start + 16;
            continue;
        }
        let statement_end = rest.find(';').unwrap_or(rest.len());
        let statement = &rest[..statement_end];
        let line = cow_engine_src[..start].matches('\n').count() + 1;
        for needle in [
            "global_frame_host_owner_matches_in",
            "global_frame_region_owner_matches_in",
            "alias_is_live",
            "region_is_live",
            "custody",
        ] {
            if statement.contains(needle) {
                offenders.push(format!(
                    "line {line}: `{needle}` inside an alias_registry().lock() statement"
                ));
            }
        }
        search = start + 16;
    }
    assert!(
        offenders.is_empty(),
        "frame-owner authentication must run outside the alias registry lock:\n{}",
        offenders.join("\n")
    );
}
