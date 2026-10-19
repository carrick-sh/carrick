//! Red witness for the ring stack audit (#369): the fixture personality's
//! deliberately oversized frame, built only with the CPL0 image's
//! `frame-budget-red-fixture` feature, must fail the same audit every ring
//! image build runs. The image builds themselves prove the real images pass.
#![allow(clippy::expect_used)]

use std::path::Path;

use carrick_xtask::frame_budget::{FrameBudgetArgs, run};

#[test]
fn the_ring_stack_audit_rejects_the_fixture_personalitys_oversized_frame() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/carrick-xtask");
    let mut out = Vec::new();
    let args = FrameBudgetArgs {
        elf: Vec::new(),
        red_fixture: true,
    };
    let result = run(root, &args, &mut out);
    let log = String::from_utf8_lossy(&out);
    assert!(result.is_ok(), "{result:?}\n{log}");
    assert!(log.contains("red fixture rejected"), "{log}");
    assert!(log.contains("exceeds the per-function ceiling"), "{log}");
    assert!(log.contains("ring stack budget exceeded"), "{log}");
}
