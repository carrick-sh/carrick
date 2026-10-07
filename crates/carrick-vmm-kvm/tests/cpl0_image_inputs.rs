//! The embedded production CPL0 image rebuilds whenever any source it compiles
//! changes. `build.rs` derives its `rerun-if-changed` inputs through
//! `cpl0_inputs.rs`; this test proves the derivation reaches every file the
//! image's sources pull in by `#[path]`/`include*!` (carrick-x86's cpl0_*.rs
//! sit outside the image's dependency closure) and the build configuration
//! that sets `code-model=kernel`. VM-free: reads sources and Cargo metadata.
#![allow(clippy::expect_used)]

#[path = "../cpl0_inputs.rs"]
mod cpl0_inputs;

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn derive() -> cpl0_inputs::Cpl0Inputs {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    cpl0_inputs::derive(&workspace(), &cargo).expect("derive CPL0 image inputs")
}

#[test]
fn every_literal_include_of_the_image_is_a_watched_input() {
    let inputs = derive();
    assert!(
        inputs.unresolved.is_empty(),
        "include literals that resolve to no file escape the watch list: {:?}",
        inputs.unresolved
    );
    let watched = inputs.watch_list(&workspace());
    for (from, target) in &inputs.includes {
        assert!(
            inputs.covers(target) && watched.iter().any(|w| target.starts_with(w)),
            "{} includes {}, which build.rs does not watch",
            from.display(),
            target.display()
        );
    }
}

#[test]
fn carrick_x86_cpl0_sources_and_build_config_are_inputs() {
    let inputs = derive();
    let root = workspace();
    for file in [
        "crates/carrick-x86/src/cpl0_entry.rs",
        "crates/carrick-x86/src/cpl0_scheduler.rs",
        "crates/carrick-x86/src/cpl0_lifecycle.rs",
    ] {
        let path = root.join(file).canonicalize().expect("cpl0 source exists");
        assert!(
            inputs.external_files.contains(&path),
            "{file} is compiled into the image but is not a derived input"
        );
    }
    let watched = inputs.watch_list(&root);
    for file in cpl0_inputs::WORKSPACE_INPUTS {
        assert!(
            watched.contains(&root.join(file)),
            "{file} configures the image build but is not watched"
        );
    }
    assert!(
        cpl0_inputs::WORKSPACE_INPUTS.contains(&".cargo/config.toml"),
        "code-model=kernel lives in .cargo/config.toml"
    );
    for package in ["carrick-x86-cpl0", "carrick-el1", "carrick-core"] {
        let dir = root
            .join("crates")
            .join(package)
            .canonicalize()
            .expect("crate dir");
        assert!(
            inputs.package_dirs.contains(&dir),
            "{package} is in the image's dependency closure but not watched"
        );
    }
}
