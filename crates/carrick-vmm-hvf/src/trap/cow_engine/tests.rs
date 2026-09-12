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
        .split("pub(crate) fn mapping_for_range(")
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
        .split("pub(crate) fn handle_data_abort(")
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
