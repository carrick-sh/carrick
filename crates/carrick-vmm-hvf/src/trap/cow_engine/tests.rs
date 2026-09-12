//! Source-shape verification for frame publication lock discipline.

#![cfg(test)]

use std::path::Path;

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
        .split("let install_alias = |permit:")
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
            .find("FrameRegistryGuard::new(")
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
        .split("let install_alias = |permit:")
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
        quiesce_apply_block.contains("FrameRegistryGuard::new("),
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
