//! The embedded production CPL0 image rebuilds whenever any source it compiles
//! changes. `build.rs` derives its `rerun-if-changed` inputs through
//! `cpl0_inputs.rs`; this test proves the derivation reaches every file the
//! image's sources pull in by `#[path]`/`include*!` (carrick-x86's cpl0_*.rs
//! sit outside the image's dependency closure) and the build configuration
//! that sets `code-model=kernel`. VM-free: reads sources and manifests.
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
    cpl0_inputs::derive(&workspace()).expect("derive CPL0 image inputs")
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
    // The original target-filtered closure plus the conservative host-only
    // carrick-el1 -> carrick-fatal edge.
    let packages = [
        "carrick-core",
        "carrick-core-abi",
        "carrick-el1",
        "carrick-el1-abi",
        "carrick-fatal",
        "carrick-fd-core",
        "carrick-guest-arch",
        "carrick-inotify-core",
        "carrick-mmu-core",
        "carrick-personality-linux",
        "carrick-pipe-core",
        "carrick-sched-core",
        "carrick-signal-core",
        "carrick-syscall-abi",
        "carrick-x86-cpl0",
    ];
    assert_eq!(inputs.package_dirs.len(), packages.len());
    for package in packages {
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

#[test]
fn local_manifest_closure_needs_no_registry_or_lockfile() {
    let temp = tempfile::tempdir().expect("fixture root");
    let root = temp.path();
    std::fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace.dependencies]
alias = { package = "shared", path = "crates/shared" }
"#,
    )
    .expect("workspace manifest");
    for (name, manifest) in [
        (
            "carrick-x86-cpl0",
            r#"
[dependencies]
alias.workspace = true
remote = "999.0"
optional = { path = "../optional", optional = true }
[target.'cfg(target_os = "none")'.build-dependencies]
builder = { path = "../builder" }
[dev-dependencies]
missing = { path = "../missing" }
"#,
        ),
        (
            "shared",
            "[dependencies]\ncycle = { path = '../carrick-x86-cpl0' }",
        ),
        ("optional", "[package]\nname = 'optional'"),
        ("builder", "[package]\nname = 'builder'"),
    ] {
        let dir = root.join("crates").join(name);
        std::fs::create_dir_all(&dir).expect("fixture crate");
        std::fs::write(dir.join("Cargo.toml"), manifest).expect("fixture manifest");
    }
    let inputs = cpl0_inputs::derive(root).expect("file-only closure");
    let expected = ["carrick-x86-cpl0", "shared", "optional", "builder"]
        .into_iter()
        .map(|name| {
            root.join("crates")
                .join(name)
                .canonicalize()
                .expect("crate path")
        })
        .collect();
    assert_eq!(inputs.package_dirs, expected);
}
