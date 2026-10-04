//! Source-shape verification for frame publication lock discipline.

#![cfg(test)]

use std::path::Path;

#[test]
fn host_cow_accounting_is_mm_scoped_and_survives_retirement() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let parent = crate::hvf_aarch64_engine::HostCowStats::default();
    let sibling = parent.clone();
    let child = crate::hvf_aarch64_engine::HostCowStats::default();
    parent.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    sibling.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    assert_eq!(parent.host_cow_resolutions(), 2);
    assert_eq!(child.host_cow_resolutions(), 0);
    drop(parent);
    assert_eq!(sibling.host_cow_resolutions(), 2);
}

#[test]
fn carrier_host_cow_ledger_aggregates_admitted_mms_and_survives_retirement() {
    use crate::hvf_aarch64_engine::{HostCowLedger, HostCowStats};
    let carrier = HostCowLedger::default();
    let other_carrier = HostCowLedger::default();
    let before = carrier.snapshot();
    let parent = carrier.admit_mm();
    let child = carrier.admit_mm();
    let foreign = other_carrier.admit_mm();
    let detached = HostCowStats::default();
    parent.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    child.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    child.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    foreign.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    detached.record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    drop((parent, child));
    let delta = carrier.snapshot().checked_delta(&before).unwrap();
    assert_eq!(delta.host_cow_resolutions, 3, "only this carrier's MMs");
    assert_eq!(delta.admitted_mms, 2);
    assert_eq!(other_carrier.snapshot().host_cow_resolutions, 1);
    assert_eq!(detached.host_cow_resolutions(), 1);
}

#[test]
fn host_cow_snapshot_delta_rejects_incomplete_or_cross_carrier_readings() {
    use crate::hvf_aarch64_engine::{HostCowLedger, HostCowSnapshot};
    let a = HostCowLedger::default();
    let b = HostCowLedger::default();
    let absent = HostCowSnapshot::default();
    assert!(
        !absent.complete,
        "absent carrier must read incomplete, not 0"
    );
    assert!(a.snapshot().checked_delta(&absent).is_none());
    assert!(absent.checked_delta(&a.snapshot()).is_none());
    assert!(a.snapshot().checked_delta(&b.snapshot()).is_none());
    a.admit_mm()
        .record_host_cow_resolution(crate::hvf_aarch64_engine::HostCowPath::StageFault);
    let later = a.snapshot();
    assert!(
        HostCowLedger::default()
            .snapshot()
            .checked_delta(&later)
            .is_none(),
        "a counter that went backwards is not a measurement"
    );
}

#[test]
fn guest_lane_refuses_host_cow_before_copy_or_publication() {
    // `materialize_retired_reuse` publishes through EL1 on the guest lane;
    // `foreign_mm::tests::guest_retained_reuse_*` pin that contract.
    // Converted writers publish through EL1 and must refuse a missing
    // driving vCPU before any allocation or inventory staging.
    let source = include_str!("../cow_engine.rs");
    let body = source
        .split_once("fn materialize_retired_reuse(")
        .unwrap()
        .1;
    let guard = body
        .find("guest_publication_available()")
        .expect("guest retained reuse must require its driving vCPU");
    assert!(guard < body.find("let retained_ipa").unwrap());
    assert!(
        !body
            .split("\n    }\n")
            .next()
            .unwrap()
            .contains("require_host_cow_lane("),
        "retained reuse is converted; it must not refuse the guest lane"
    );
    // The foreign writers are converted too: a guest-owned target publishes
    // through the caller vCPU the runtime lent, authenticated against the
    // exact target before any allocation, reservation or transition.
    let foreign = include_str!("../foreign_mm.rs");
    for (entry, guard, first_effect) in [
        (
            "fn perform_foreign_guest_cow(",
            "ForeignEl1Publisher::authenticate(",
            ".reserve(",
        ),
        (
            "fn materialize_foreign_pristine_write(",
            "ForeignStage1Services::for_target(",
            ".begin_materialization(",
        ),
        (
            "fn materialize_foreign_private_file_write(",
            "ForeignStage1Services::for_target(",
            ".begin_private_file_materialization(",
        ),
    ] {
        let body = foreign.split_once(entry).unwrap().1;
        let body = body.split("\n}\n").next().unwrap();
        let guard = body.find(guard).expect(entry);
        assert!(guard < body.find(first_effect).unwrap(), "{entry}");
    }
    let sparse = include_str!("../sparse_materialization.rs");
    let body = sparse.split_once("fn publish_replacing(").unwrap().1;
    let body = body.split("\n}\n").next().unwrap();
    assert!(
        body.find("guest_publication_available()").unwrap()
            < body.find("let semantic_len").unwrap()
    );
    assert!(
        !body.contains("require_host_cow_lane("),
        "foreign sparse publication is converted; it must not refuse the guest lane"
    );
    let cow = foreign
        .split_once("fn perform_foreign_cow_transaction(")
        .unwrap()
        .1;
    let cow = cow.split("\n}\n").next().unwrap();
    assert!(!cow.contains("require_host_cow_lane("));
    assert!(
        cow.find("return perform_foreign_guest_cow(").unwrap()
            < cow.find("OwnedHostMapping::map_shared_anon").unwrap(),
        "the guest lane leaves before the host lane allocates or copies"
    );
}

#[test]
fn host_cow_counter_counts_only_completed_local_and_foreign_transactions() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            .find("record_host_cow_resolution(")
            .expect("completed COW needs its own counter");
        assert!(count > body.find(completion).unwrap());
        assert_eq!(body.matches("record_host_cow_resolution(").count(), 1);
    }
}

#[test]
fn alias_unmap_takes_frame_registry_guard_only_for_inventory_publication() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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

#[test]
fn guest_cow_caller_requires_driving_vcpu_before_touching_backing() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    use super::*;
    let custody = std::sync::Arc::new(CarrierVmCustody::new_live_fixture());
    let mut task = HvfTaskState::neutral();
    task.page_tables_authority()
        .select_live_descriptor_owner(carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest);
    let mut flushed = false;
    let error = task.perform_frame_cow(
        &custody,
        0x4000,
        carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible,
        FrameCowTrigger {
            class: carrick_observability::probes::HvpatchFrameCowTriggerClass::Stage1PermissionFault,
            syndrome: 0,
            far: 0x4000,
            ttbr0: 0,
        },
        &mut || { flushed = true; Ok(()) },
    ).unwrap_err();
    assert!(error.to_string().contains("requires its driving vCPU"));
    assert!(!flushed);
    assert!(task.frame_inventory.ledger.lock().extents.is_empty());
}

#[test]
fn guest_cow_kernel_grant_refusal_releases_backend_inventory_and_owner() {
    use super::*;
    let _guard =
        crate::trap::frame_inventory_backend_tests::global_frame_allocator_test_lock().lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let custody = std::sync::Arc::new(CarrierVmCustody::new_live_fixture());
    let mut lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let (gpa, length) = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        length as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let host_addr = host.as_ptr() as usize;
    assert_eq!(
        unsafe { inventory_hv_vm_map(host.as_ptr().cast(), gpa, length as usize, 7) },
        0
    );
    lease.mark_mapped();
    let generation = register_global_frame_host_owner_in(&custody, lease, host, 7).unwrap();
    let nz = |n| std::num::NonZeroU64::new(n).unwrap();
    let reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([72; 32]),
        carrick_hal::FrameInventoryBatch::prepare(
            carrick_hal::KernelTransactionId::from_kernel_allocation(nz(1)),
            carrick_hal::FrameEventCapacity::for_event_count(2).unwrap(),
        )
        .unwrap(),
        vec![carrick_hal::FrameId::from_kernel_allocation(nz(1))],
        vec![carrick_hal::MappingId::from_kernel_allocation(nz(1))],
    );
    let inventory = std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let authority =
        std::sync::Arc::new(super::super::task_only_carrier_directory_tests::TestCowAuthority);
    let result = GuestPreparedBacking::prepare(
        custody.clone(),
        authority,
        inventory.clone(),
        reservation,
        nz(7),
        InventoryMappingStage {
            gpa,
            length,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: true,
            },
            backing: HvfVmState::private_backing_identity(),
            inherited_frame: None,
            stage2_lease: Some((gpa, length)),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr,
                generation,
            },
        },
    );
    assert!(matches!(result, Err(ref error) if error.to_string().contains("COW grant inventory")));
    let inventory = inventory.lock();
    assert!(inventory.extents.is_empty());
    let frames = inventory.frames.lock();
    assert!(frames.references.is_empty());
    assert!(frames.extent_references.is_empty());
    assert!(frames.stage2_references.is_empty());
    assert_eq!(
        global_frame_host_owner_identity_in(&custody, gpa, length),
        None
    );
    assert!(!ScopedStage2MapTestStub::is_mapped(gpa, length as usize));
}

fn replacement(base: u64, generation: u64) -> super::PendingEl1GrantReplacement {
    use super::*;
    let ready = carrick_hal::El1FrameGrantReady {
        physical_ipa: 0x80_0000_0000 + base,
        frame_id: 5,
        mapping_id: 6,
        owner_generation: generation,
        inventory_revision: 8,
    };
    PendingEl1GrantReplacement {
        grant: carrick_hal::threaded::El1FrameGrantRollback {
            mm_key: 41,
            semantic_base: base,
            len: 0x4000,
            ready,
        },
        predecessor_leases: std::collections::BTreeSet::from([(0x90_0000_0000, 0x4000)]),
        alias: AliasBacking {
            start: base,
            ipa: ready.physical_ipa,
            host_addr: 0x1000,
            size: 0x4000,
            physical_ipa: ready.physical_ipa,
            physical_host_addr: 0x1000,
            physical_size: 0x4000,
            perms: 7,
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: alias_ownership_scope(
                GuestMappingSharing::Private,
                None,
                ContainerRootToken::ROOT,
            ),
            inventory_backing: HvfVmState::private_backing_identity(),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: generation,
        },
    }
}

/// A guest-lane replacement is named to its completion or rollback by its
/// exact incarnation, and one span never holds two pending replacements.
#[test]
fn pending_el1_grant_replacements_match_only_the_exact_grant() {
    use super::*;
    let mut ledger = PendingEl1GrantReplacements::default();
    let first = replacement(0x10_0000, 3);
    assert!(ledger.insert(first.clone()));
    assert!(ledger.overlaps(0x10_3000, 0x1000));
    assert!(!ledger.overlaps(0x10_4000, 0x1000));
    assert!(!ledger.overlaps(0x0f_c000, 0x4000));
    assert!(
        !ledger.insert(replacement(0x10_2000, 9)),
        "an overlapping replacement is refused"
    );
    // Same span, another owner incarnation: not this grant.
    assert_eq!(ledger.take(&replacement(0x10_0000, 4).grant), None);
    assert!(ledger.insert(replacement(0x20_0000, 3)));
    assert_eq!(ledger.take(&first.grant), Some(first.clone()));
    assert_eq!(ledger.take(&first.grant), None, "taken exactly once");
    assert!(!ledger.overlaps(0x10_0000, 0x4000));
    assert!(ledger.take(&replacement(0x20_0000, 3).grant).is_some());
}

fn fn_body<'a>(source: &'a str, entry: &str) -> &'a str {
    source
        .split_once(entry)
        .unwrap_or_else(|| panic!("{entry}"))
        .1
        .split("\n    pub(crate) fn ")
        .next()
        .unwrap()
        .split("\n    fn ")
        .next()
        .unwrap()
}

fn in_order(body: &str, needles: &[&str]) {
    let mut at = 0;
    for needle in needles {
        let found = body[at..]
            .find(needle)
            .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
        at += found + needle.len();
    }
}

/// The guest lane publishes a replacement grant instead of declining it,
/// but retires nothing before EL1's receipt: the grant's alias is held back
/// in the MM's ledger (never registered beside its predecessor), and only
/// the host lane folds the retirement into the grant's commit.
#[test]
fn guest_lane_replacement_grant_defers_retirement_and_registration() {
    let source = include_str!("../cow_engine.rs");
    let prepare = fn_body(source, "fn prepare_el1_frame_grant(");
    assert!(
        !prepare.contains("require_host_cow_lane("),
        "the guest lane no longer refuses a replacement"
    );
    in_order(
        prepare,
        &[
            "Some(planned) if guest_lane => (None, Some(planned.planned_leases))",
            "Some(planned) => (Some(planned), None)",
            "publish_frame_grant(",
            "if let Some(retirement) = retirement.take()",
            "commit_preapplied_process_alias_retirement(",
            "None => register_shared_alias(published.alias)",
            "self.el1_grant_replacements.lock().insert(pending)",
            "transition.commit()",
        ],
    );
    assert_eq!(
        prepare.matches("register_shared_alias(").count(),
        1,
        "a replacement's alias is registered only at completion"
    );
}

/// Completion retires the predecessor only after re-preparing it against
/// the live inventory and proving the planned leases, then registers the
/// grant, under one frame-registry hold the retirement never takes itself.
/// Rollback of a pending replacement retires only the grant's own
/// unregistered publication: never the span's registered predecessor.
#[test]
fn replacement_completion_and_rollback_touch_the_right_owner() {
    let source = include_str!("../cow_engine.rs");
    let complete = fn_body(source, "fn complete_el1_frame_grant(");
    in_order(
        complete,
        &[
            "el1_grant_replacements.lock().take(&grant)",
            "prepare_process_alias_retirement(",
            "retirement.planned_leases != pending.predecessor_leases",
            "FrameRegistryGuard::acquire(",
            "commit_process_alias_retirement(",
            "&registry)",
            "register_shared_alias(pending.alias)",
            "drop(registry)",
        ],
    );
    let rollback = fn_body(source, "fn roll_back_el1_frame_grant(");
    let (pending, fresh) = rollback
        .split_once("let aliases = alias_registry()")
        .expect("fresh-grant rollback follows the pending branch");
    in_order(
        pending,
        &[
            "el1_grant_replacements.lock().take(&grant)",
            "retire_unregistered_el1_frame_grant(",
            "restore_pristine(",
            "return Ok(true)",
        ],
    );
    for predecessor_writer in [
        "unregister_process_alias(",
        "commit_process_alias_retirement(",
    ] {
        assert!(
            !pending.contains(predecessor_writer),
            "{predecessor_writer}"
        );
    }
    assert!(fresh.contains("is_exactly_el1_frame_grant("));
    let retire = fn_body(source, "fn retire_unregistered_el1_frame_grant(");
    in_order(
        retire,
        &[
            "reserve_process_alias_retirement(",
            "commit_process_alias_retirement_inner(",
            "AliasRetirementRows::NeverRegistered",
        ],
    );
    assert!(!retire.contains("FrameRegistryGuard::acquire("));
    let inner = fn_body(source, "fn try_commit_process_alias_retirement(");
    in_order(
        inner,
        &[
            "let registered = rows == AliasRetirementRows::Registered;",
            "if registered {",
            "supersede_cow_receipts(",
            "if registered {",
            "commit_planned_unregister_in(",
        ],
    );
}

/// A refused grant's rollback retires only the exact alias its preparation
/// registered: same span, semantic IPA and owner incarnation. A successor
/// owner at the same IPA, a split fragment, or a second overlapping alias
/// is not the grant's backing and must never be retired in its name.
#[test]
fn el1_frame_grant_rollback_matches_only_the_grants_own_alias() {
    use super::*;
    let grant = carrick_hal::threaded::El1FrameGrantRollback {
        mm_key: 9,
        semantic_base: 0x4000_0000,
        len: 0x4000,
        ready: carrick_hal::El1FrameGrantReady {
            physical_ipa: 0x9b_4000_0000,
            frame_id: 1,
            mapping_id: 2,
            owner_generation: 17,
            inventory_revision: 4,
        },
    };
    let alias = AliasBacking {
        start: grant.semantic_base,
        ipa: grant.ready.physical_ipa,
        host_addr: 0x1_0000_0000,
        size: grant.len as usize,
        physical_ipa: grant.ready.physical_ipa,
        physical_host_addr: 0x1_0000_0000,
        physical_size: grant.len as usize,
        perms: 7,
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            None,
            ContainerRootToken::ROOT,
        ),
        inventory_backing: HvfVmState::private_backing_identity(),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 17,
    };
    assert!(is_exactly_el1_frame_grant(&[(1, alias)], grant));
    assert!(!is_exactly_el1_frame_grant(&[], grant), "already retired");
    let successor = AliasBacking {
        owner_generation: 18,
        ..alias
    };
    assert!(!is_exactly_el1_frame_grant(&[(1, successor)], grant));
    let fragment = AliasBacking {
        size: 0x1000,
        ..alias
    };
    assert!(!is_exactly_el1_frame_grant(&[(1, fragment)], grant));
    let moved = AliasBacking {
        ipa: alias.ipa + 0x4000,
        ..alias
    };
    assert!(!is_exactly_el1_frame_grant(&[(1, moved)], grant));
    assert!(!is_exactly_el1_frame_grant(
        &[(1, alias), (2, fragment)],
        grant
    ));
}

/// Both refusal sites hand the grant to the one backend rollback; the
/// backend's rollback is the only inverse of `prepare_el1_frame_grant`.
#[test]
fn el1_frame_grant_rollback_retires_through_the_unmap_path_then_restores_pristine() {
    let source = include_str!("../cow_engine.rs");
    let body = source
        .rsplit_once("pub(crate) fn roll_back_el1_frame_grant(")
        .unwrap()
        .1
        .split("\n    pub(crate) fn ")
        .next()
        .unwrap();
    // A pending guest-lane replacement is rolled back first, through its
    // own branch (`replacement_completion_and_rollback_touch_the_right_owner`).
    let body = body
        .split_once("let aliases = alias_registry()")
        .expect("fresh-grant rollback")
        .1;
    let guard = body
        .find("is_exactly_el1_frame_grant(")
        .expect("exact identity guard");
    let retire = body
        .find("self.unregister_process_alias(")
        .expect("unmap retirement");
    let pristine = body.find(".restore_pristine(").expect("pristine restore");
    assert!(guard < retire && retire < pristine);
}

#[test]
fn host_cow_resolutions_are_classified_by_the_path_that_completed_them() {
    use crate::hvf_aarch64_engine::{HostCowLedger, HostCowPath};
    use carrick_observability::probes::HvpatchFrameCowTriggerClass as Class;
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let carrier = HostCowLedger::default();
    let before = carrier.snapshot();
    let mm = carrier.admit_mm();
    for class in [
        Class::Stage1PermissionFault,
        Class::SyscallGuestWrite,
        Class::SyscallGuestWrite,
        Class::BackingMaintenance,
        Class::PrivilegedInternal,
    ] {
        mm.record_host_cow_resolution(HostCowPath::of_trigger(class));
    }
    mm.record_host_cow_resolution(HostCowPath::ForeignPublication);
    let delta = carrier.snapshot().checked_delta(&before).unwrap();
    assert_eq!(delta.host_cow_by_path, [1, 2, 1, 1, 1]);
    assert_eq!(
        delta.host_cow_by_path.iter().sum::<u64>(),
        delta.host_cow_resolutions,
        "every resolution has exactly one path"
    );
}

#[test]
fn host_cow_is_split_by_mm_concentration_and_by_lane() {
    use crate::hvf_aarch64_engine::{HostCowLedger, HostCowPath};
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let carrier = HostCowLedger::default();
    let before = carrier.snapshot();
    let parent = carrier.admit_mm();
    let child = carrier.admit_mm();
    for _ in 0..3 {
        parent.record_host_cow_resolution(HostCowPath::StageFault);
    }
    child.record_host_cow_resolution(HostCowPath::StageFault);
    child.record_guest_lane_host_cow(HostCowPath::SyscallCopyOut);
    parent.record_guest_lane_host_cow(HostCowPath::StageFault);
    let delta = carrier.snapshot().checked_delta(&before).unwrap();
    assert_eq!(delta.host_cow_resolutions, 4);
    assert_eq!(delta.host_cow_max_per_mm, 3, "one MM owns most of them");
    assert_eq!(
        delta.guest_lane_host_cow_by_path,
        [1, 1, 0, 0, 0],
        "guest-lane host COWs are apart from host_cow_resolutions"
    );
}

/// Signed witness `el1_delegated_root_map_fixed_over_cow_pages`, round 1: a
/// 4 KiB-aligned region at host-compound offset 0x1000 whose first eight
/// pages were `MAP_FIXED`-replaced after a fork. The compound at +0x7000
/// (region pages 7..10) then holds page 7 on the replacement frame and
/// pages 8..10 on the old, still fork-armed frame, and the unmap kept the
/// compound's arm for its surviving pages. A write to page 8 must copy and
/// repoint pages 8..10 only. Repointing page 7 as well aimed it at a copy
/// of the OLD frame's page 7, so the guest read bytes from before the
/// replacement (`got=pattern(round=0,page=7)`) and the parent's own write
/// to page 7 vanished.
#[test]
fn frame_cow_repoints_only_pages_that_name_the_faulting_frame() {
    use super::*;
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    const PAGE: u64 = 0x1000;
    let base = 0x6000_0000_5000_u64;
    let old_frame = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;
    let replacement = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x80_0000;
    let mut tables = carrick_mmu_core::aarch64::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
    );
    // The original 64-page region: semantic IPA at compound offset 0x1000.
    tables
        .map_aliased(
            base,
            old_frame + PAGE,
            64 * PAGE,
            carrick_mmu_core::aarch64::UserLeafAccess {
                writable: false,
                executable: true,
            },
            None,
        )
        .expect("map the original region");
    // The MAP_FIXED replacement of pages 0..8 on its own frame.
    tables
        .map_aliased(
            base,
            replacement + PAGE,
            8 * PAGE,
            carrick_mmu_core::aarch64::UserLeafAccess {
                writable: false,
                executable: true,
            },
            None,
        )
        .expect("map the replacement");
    let task = HvfTaskState::neutral();
    task.page_tables_authority().set_manager(tables);
    // The arm the unmap left behind still covers the replaced pages.
    task.cow_armed
        .lock()
        .arm(&[carrick_aarch64::vmm::ForkCowRange {
            va: base,
            len: (64 * PAGE) as usize,
            executable: false,
            kernel_only: false,
            granule: carrick_aarch64::vmm::CowGranule::Compound,
        }]);

    let page = |index: u64| base + index * PAGE;
    let repoint = |fault: u64| {
        let candidate = task.cow_armed.lock().span_for(fault).expect("armed");
        task.live_cow_span(candidate, fault)
    };
    assert_eq!(
        repoint(page(8)),
        CowArmedSpan {
            va: page(8),
            len: (3 * PAGE) as usize,
            executable: false,
            kernel_only: false,
        },
        "a COW of the old frame must not repoint page 7, which names the replacement"
    );
    assert_eq!(
        repoint(page(7)),
        CowArmedSpan {
            va: page(7),
            len: PAGE as usize,
            executable: false,
            kernel_only: false,
        },
        "a COW of the replacement must not repoint pages 8..10 of the old frame"
    );
    // A compound wholly on one frame is still repointed whole.
    assert_eq!(
        repoint(page(12)),
        CowArmedSpan {
            va: page(11),
            len: (4 * PAGE) as usize,
            executable: false,
            kernel_only: false,
        },
    );
}

#[test]
fn host_lane_samples_are_counted_by_cause_and_site() {
    use crate::hvf_aarch64_engine::HostCowLedger;
    use carrick_aarch64::stage1_authority::{GuestLaneSite, HostLaneCause};
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let carrier = HostCowLedger::default();
    let before = carrier.snapshot();
    let mm = carrier.admit_mm();
    mm.record_host_lane_cause(GuestLaneSite::ForkPlan, HostLaneCause::PendingNoBacking);
    mm.record_host_lane_cause(GuestLaneSite::HostCow, HostLaneCause::PendingNoBacking);
    mm.record_host_lane_cause(GuestLaneSite::HostCow, HostLaneCause::PendingNoBacking);
    mm.record_host_lane_cause(GuestLaneSite::InitialBind, HostLaneCause::NeverSelected);
    let delta = carrier.snapshot().checked_delta(&before).unwrap();
    assert_eq!(
        delta.host_lane_samples[HostLaneCause::PendingNoBacking as usize],
        [0, 1, 2]
    );
    assert_eq!(
        delta.host_lane_samples[HostLaneCause::NeverSelected as usize],
        [1, 0, 0]
    );
    assert_eq!(
        delta.host_lane_samples.iter().flatten().sum::<u64>(),
        4,
        "every sample has one cause and one site"
    );
}
